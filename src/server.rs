//! Notary server: handles plain-TCP (backend MPC-TLS) and WebSocket connections.
//!
//! # Endpoints
//!
//! - **TCP** (`--port`): MPC-TLS verifier for Rust backend provers. The section
//!   9.1 attestation is written back down the socket the prover
//!   opened. Nothing here dispatches on the server name: the record carries
//!   it, and the contract that reads the record pins it.
//! - **GET  /info**: returns `{version, publicKey}` — compatible with tlsn-js.
//! - **GET  /healthcheck**: `{"status":"ok"}`, or 503 `{"status":"draining"}`
//!   once the process has been told to stop.
//! - **GET /notarize-proxy** (WS upgrade): ProxyMode session followed by one
//!   length-prefixed attestation in its own WebSocket message.
//! - **GET /internal/notarize-proxy** (WS upgrade, `--internal-proxy-route`
//!   only): the same session for our own in-cluster services, with no
//!   per-client limit and its own session pool. It exists for the load
//!   balancer to block; a request that arrived through one -- it carries
//!   `X-Forwarded-For` or `CF-Connecting-IP` -- is refused with 403.
//!
//! The HTTP routes are served on one listener (`--ws-port`), and the route
//! is the whole classification: every per-client limit applies on
//! `/notarize-proxy` and none on `/internal/notarize-proxy`. Nothing a
//! request carries moves it from one tier to the other; the only thing a
//! header can do on the internal route is get the request refused.
//!
//! # Trust model
//!
//! The notary is one half of a 2-of-2 trust scheme. Having taken part as the
//! MPC-TLS or ProxyMode verifier, it signs what it observed, and one thing
//! only: the section 9.1 attested data. Both transports produce the same
//! record, because the transport says nothing about the TLS session it
//! describes.
//!
//! Its signature alone registers nothing. A contract on the Consumer Chain
//! authenticates it -- the Notary Service, spec section 9.1 --
//! and NOT the proving circuit: an attestation is authenticated on chain, and
//! the circuit proves only what cannot be read from authenticated evidence.

use std::{
    net::SocketAddr,
    pin::pin,
    sync::{
        atomic::{
            AtomicBool,
            Ordering,
        },
        Arc,
    },
    time::Duration,
};

use axum::{
    extract::ConnectInfo,
    middleware::AddExtension,
    Router,
};
use hyper::server::conn::http1;
use hyper_util::{
    rt::{
        TokioIo,
        TokioTimer,
    },
    service::TowerToHyperService,
};
use libid_signer::{
    ManagedSigner,
    SignerSource,
};
use tlsn::webpki::CertificateDer;
use tokio::{
    net::TcpListener,
    sync::{
        watch,
        Semaphore,
    },
};
use tokio_util::task::TaskTracker;
use tower::Service;
use tracing::{
    debug,
    error,
    info,
    warn,
};

use crate::{
    config::{
        ClientIpHeader,
        NotaryServerConfig,
    },
    error::{
        Error,
        Result,
    },
    limits::available_cores,
    store::{
        LimitStore,
        Store,
        WindowLimits,
    },
};

mod accounting;
mod attestation;
mod mpc;
mod routes;
mod ws;

use routes::router;

/// How far along the server is in stopping. The listeners watch this.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Accepting everything.
    Running,
    /// Told to stop: the MPC listener is closed, the HTTP listener answers
    /// only to say so (503), and the sessions already running finish.
    Draining,
    /// Every session is done or out of time; the HTTP listener closes.
    Stopped,
}

/// Handle for controlling the running notary server.
pub struct NotaryServerHandle {
    local_addr: Option<SocketAddr>,
    ws_local_addr: Option<SocketAddr>,
    phase: watch::Sender<Phase>,
    draining: Arc<AtomicBool>,
    /// One token per connection, from admission to the handler's return, so
    /// a drain knows when it is done.
    in_flight: TaskTracker,
    /// How long a drain waits for the sessions in flight: the setup
    /// deadline plus the connection deadline, because a connection counts
    /// from its handler's first moment and is bounded by both in turn.
    drain_deadline: Duration,
}

impl NotaryServerHandle {
    /// Returns the address the internal MPC-TLS listener is bound to, if
    /// enabled.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    /// Returns the address the public HTTP/WebSocket server is bound to, if
    /// enabled.
    pub fn ws_local_addr(&self) -> Option<SocketAddr> {
        self.ws_local_addr
    }

    /// Stops every listener now, without waiting for the sessions in
    /// flight: what a second stop signal asks for while a drain is running.
    pub fn shutdown(&self) {
        self.draining.store(true, Ordering::SeqCst);
        let _ = self.phase.send(Phase::Stopped);
    }

    /// Stop taking work, finish what is running, then stop the listeners.
    ///
    /// The health check answers 503 from the first moment, so the load
    /// balancer stops routing here while the sessions already running
    /// finish; the MPC listener closes at once and its queue empties with an
    /// error. The HTTP listener keeps answering -- 503 to every upgrade --
    /// until the last session ends or the setup and connection deadlines
    /// together elapse, because a closed port looks like a crash to the
    /// balancer and a 503 looks like what it is. Then it closes too, and
    /// this returns.
    pub async fn drain(&self) {
        self.draining.store(true, Ordering::SeqCst);
        let _ = self.phase.send(Phase::Draining);
        self.in_flight.close();
        let open = self.in_flight.len();
        info!(
            sessions = open,
            deadline_secs = self.drain_deadline.as_secs(),
            "draining: no new sessions; waiting for the ones in flight"
        );
        match tokio::time::timeout(self.drain_deadline, self.in_flight.wait()).await {
            Ok(()) => info!("drained: every session finished"),
            Err(_) => warn!(
                sessions = self.in_flight.len(),
                "drain deadline reached with sessions still running; stopping anyway"
            ),
        }
        let _ = self.phase.send(Phase::Stopped);
    }
}

/// Which ProxyMode route a request arrived on. This, and nothing else about
/// the request, decides whether the per-client limits apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tier {
    /// `/notarize-proxy`: browsers behind the load balancer; every limit
    /// applies.
    Public,
    /// `/internal/notarize-proxy`, with `--internal-proxy-route`: our own
    /// services; no per-client limit, no client address header keyed on,
    /// and its own session pool.
    Internal,
}

impl Tier {
    /// The path a ProxyMode session on this tier is opened on.
    fn route(self) -> &'static str {
        match self {
            Self::Public => "/notarize-proxy",
            Self::Internal => "/internal/notarize-proxy",
        }
    }
}

/// The headers a load balancer adds to name the client that connected to
/// it. The public route keys its limits on one of them; the internal route
/// refuses a request carrying either, because our own services reach it
/// inside the cluster and never through the balancer.
const PROXIED_BY: [&str; 2] = ["x-forwarded-for", "cf-connecting-ip"];

#[derive(Clone)]
struct NotaryState {
    /// Notary signing identity (local hex key or AWS KMS).
    signer: Arc<ManagedSigner>,
    /// Public ProxyMode slots: an upgrade that finds none is refused with
    /// 503.
    proxy_sessions: Arc<Semaphore>,
    /// Internal ProxyMode slots: their own pool, so public load never
    /// queues our own services behind it.
    internal_proxy_sessions: Arc<Semaphore>,
    /// ProxyMode slots each public client may hold at once; `0` disables
    /// the cap.
    max_sessions_per_ip: usize,
    /// Where the public route's per-client counts live. Never consulted for
    /// the internal route.
    limits: Store,
    /// Sessions one public client may start per window.
    per_ip_upgrades: WindowLimits,
    /// Bytes one public client may relay per window.
    per_ip_bytes: WindowLimits,
    /// Which header names the client on the public route. Never keyed on
    /// for the internal route.
    client_ip_header: ClientIpHeader,
    /// Bytes one ProxyMode session may relay, both directions combined.
    proxy_max_bytes: usize,
    proxy_root_store: Arc<tlsn::webpki::RootCertStore>,
    /// `None` connects to the TLS-authenticated server name on port 443;
    /// The upstream override `run_with` was given; `None` dials
    /// `<server name>:443`.
    proxy_server_addr: Option<SocketAddr>,
    /// MPC-TLS slots: a prover that finds none waits for one. Closed on
    /// shutdown, so the queue drains with an error instead of hanging.
    mpc_sessions: Arc<Semaphore>,
    /// Overall deadline for one session on either transport, from the moment
    /// it starts: the session itself plus the attestation exchange, and for
    /// MPC-TLS the wait for a slot. Defense in depth: whatever future bug
    /// makes a session pend, no connection can pin a handler task (and its
    /// MPC buffers) forever. Reaching a session is `setup_deadline`'s job.
    connection_deadline: Duration,
    /// How long a connection may sit before it starts its session. Until it
    /// does it holds no slot, so an idle socket costs a socket and nothing
    /// else.
    setup_deadline: Duration,
    public_key_hex: String,
    /// Set once the process has been told to stop: the health check says
    /// so, and no upgrade is accepted.
    draining: Arc<AtomicBool>,
    /// The connections a drain waits for.
    /// One token per connection, from admission to the handler's return, so
    /// a drain knows when it is done.
    in_flight: TaskTracker,
}

#[cfg(test)]
impl NotaryState {
    /// A state around `signer` with every limit at its default; a test
    /// overrides the one field it exercises.
    fn for_tests(signer: ManagedSigner) -> Self {
        Self {
            public_key_hex: hex::encode(signer.compressed_public_key()),
            signer: Arc::new(signer),
            proxy_sessions: Arc::new(Semaphore::new(crate::limits::DEFAULT_MAX_SESSIONS)),
            internal_proxy_sessions: Arc::new(Semaphore::new(
                crate::limits::DEFAULT_MAX_SESSIONS,
            )),
            max_sessions_per_ip: 4,
            limits: Store::memory(),
            per_ip_upgrades: "10/1m,60/30m,100/1h".parse::<WindowLimits>().unwrap(),
            per_ip_bytes: "100MB/1m,600MB/30m,1GB/1h".parse::<WindowLimits>().unwrap(),
            client_ip_header: ClientIpHeader::XForwardedFor,
            proxy_max_bytes: 10_000_000,
            proxy_root_store: Arc::new(libid_tlsn::root_store()),
            proxy_server_addr: None,
            mpc_sessions: Arc::new(Semaphore::new(4)),
            connection_deadline: Duration::from_secs(300),
            setup_deadline: Duration::from_secs(15),
            draining: Arc::new(AtomicBool::new(false)),
            in_flight: TaskTracker::new(),
        }
    }
}

// ─── Server startup ──────────────────────────────────────────────────────────

/// How often expired leases and dead windows are swept from the store.
const SWEEP_EVERY: Duration = Duration::from_secs(60);

/// Where every ProxyMode session dials instead of `<server name>:443`, and
/// the root its certificate may chain to besides the public ones. Not a
/// configuration: the release binary passes none, and only the binary the
/// e2e suite builds (`--features e2e`) can supply one.
#[derive(Clone, Debug)]
pub struct Upstream {
    pub addr: SocketAddr,
    pub ca: Option<CertificateDer>,
}

/// Start the notary server: the MPC-TLS listener and the HTTP/WebSocket
/// server, each only if configured.
pub async fn run(config: NotaryServerConfig) -> Result<NotaryServerHandle> {
    run_with(config, None).await
}

/// [`run`], with every ProxyMode session dialling `upstream` instead of the
/// server it authenticates.
pub async fn run_with(
    config: NotaryServerConfig,
    upstream: Option<Upstream>,
) -> Result<NotaryServerHandle> {
    if config.internal_proxy_route && config.ws_port == 0 {
        return Err(Error::NotaryServer {
            detail: "--internal-proxy-route mounts on the public port, which \
                     --ws-port 0 disables"
                .into(),
        });
    }
    let per_ip_upgrades = config.per_ip_upgrades.clone();
    let per_ip_bytes = config.per_ip_bytes.clone();
    let limits_store = config
        .limits_store()
        .map_err(|detail| Error::NotaryServer { detail })?;
    let mut proxy_root_store = libid_tlsn::root_store();
    let proxy_upstream = upstream.map(|upstream| {
        warn!(
            addr = %upstream.addr,
            extra_root = upstream.ca.is_some(),
            "every ProxyMode session dials the upstream override"
        );
        proxy_root_store.roots.extend(upstream.ca);
        upstream.addr
    });

    // A store that cannot be reached is a startup error, not a limit that
    // refuses every client once the process is up.
    let limits =
        Store::connect(&limits_store)
            .await
            .map_err(|e| Error::NotaryServer {
                detail: e.to_string(),
            })?;

    // SIGNING_KEY accepts `kms:<key-id-or-alias>` or a hex key.
    let signer = SignerSource::from_spec(&config.signing_key)?
        .build_managed(None)
        .await?;
    info!(
        notary = %signer.address(),
        via = %signer.describe(),
        "notary signer ready"
    );
    let public_key_hex = hex::encode(signer.compressed_public_key());

    // Every limit in force, in one line, so an operator never has to read
    // another crate to learn one of them. The MPC-TLS data limits are
    // libid-tlsn's: the verifier rejects a session configured above them
    // before any MPC work is done, and they are not tunable from here.
    let cores = available_cores();
    let mpc_max_sessions = config.mpc_max_sessions.resolve(cores);
    info!(
        proxy_max_sessions = config.max_sessions,
        internal_max_sessions = config.internal_max_sessions,
        proxy_max_bytes = config.proxy_max_bytes,
        mpc_max_sessions,
        mpc_max_sessions_setting = %config.mpc_max_sessions,
        cores = cores.map(std::num::NonZeroUsize::get),
        mpc_max_sent_data = libid_tlsn::MAX_SENT_DATA,
        mpc_max_recv_data = libid_tlsn::MAX_RECV_DATA,
        connection_deadline_secs = config.connection_deadline_secs,
        setup_deadline_secs = config.setup_deadline_secs,
        max_sessions_per_ip = config.max_sessions_per_ip,
        per_ip_upgrades = %per_ip_upgrades,
        per_ip_bytes = %per_ip_bytes,
        client_ip_header = %config.client_ip_header,
        limits_store = %limits.describe(),
        "resource limits in force"
    );
    let state = NotaryState {
        signer: Arc::new(signer),
        proxy_sessions: Arc::new(Semaphore::new(config.max_sessions)),
        internal_proxy_sessions: Arc::new(Semaphore::new(config.internal_max_sessions)),
        max_sessions_per_ip: config.max_sessions_per_ip,
        limits,
        per_ip_upgrades,
        per_ip_bytes,
        client_ip_header: config.client_ip_header,
        proxy_max_bytes: config.proxy_max_bytes,
        proxy_root_store: Arc::new(proxy_root_store),
        proxy_server_addr: proxy_upstream,
        mpc_sessions: Arc::new(Semaphore::new(mpc_max_sessions)),
        connection_deadline: config.connection_deadline(),
        setup_deadline: config.setup_deadline(),
        public_key_hex,
        draining: Arc::new(AtomicBool::new(false)),
        in_flight: TaskTracker::new(),
    };

    // Broadcast the phase to the listeners and the sweeper.
    let (phase_tx, phase_rx) = watch::channel(Phase::Running);

    // ── Internal MPC-TLS listener (Rust provers in the cluster) ───────
    // Off unless configured: it has no per-client limits.
    let tcp_listener = match config.port {
        Some(port) => Some(TcpListener::bind(format!("{}:{port}", config.host)).await?),
        None => None,
    };
    let local_addr = tcp_listener.as_ref().and_then(|l| l.local_addr().ok());
    match local_addr {
        Some(addr) => info!("Notary MPC-TLS listening on {addr} (internal)"),
        None => info!("Notary MPC-TLS port off (--port not set)"),
    }

    // ── Public HTTP/WebSocket server (browser / tlsn-js) ──────────────
    let ws_listener = if config.ws_port == 0 {
        None
    } else {
        let ws_addr = format!("{}:{}", config.host, config.ws_port);
        Some(TcpListener::bind(&ws_addr).await?)
    };
    let ws_local_addr = ws_listener.as_ref().and_then(|l| l.local_addr().ok());
    match ws_local_addr {
        Some(addr) => info!("Notary WebSocket listening on {addr} (public)"),
        None => info!("Notary public WebSocket port off (--ws-port 0)"),
    }
    // The internal route rides the public port; the balancer has to block
    // it, and this line is what an operator checks against that config.
    if config.internal_proxy_route {
        info!(
            internal_proxy_route = true,
            route = Tier::Internal.route(),
            "internal ProxyMode route mounted on the public port; no per-client \
             limits, the load balancer must answer 403 for /internal/*"
        );
    } else {
        info!(
            internal_proxy_route = false,
            "internal ProxyMode route off (--internal-proxy-route not set)"
        );
    }

    if let Some(tcp_listener) = tcp_listener {
        let tcp_state = state.clone();
        let mut tcp_phase = phase_rx.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = tcp_listener.accept() => {
                        match result {
                            Ok((stream, peer)) => {
                                info!("TCP connection from {}", peer);
                                let s = tcp_state.clone();
                                let in_flight = s.in_flight.token();
                                tokio::spawn(async move {
                                    if let Err(e) = s.handle_tcp_prover(stream).await {
                                        error!("TCP handler error for {}: {}", peer, e);
                                    }
                                    drop(in_flight);
                                });
                            }
                            Err(e) => error!("TCP accept failed: {}", e),
                        }
                    }
                    // Any change is at least Draining: stop accepting.
                    _ = tcp_phase.changed() => {
                        info!("Notary TCP shutting down");
                        // Provers still waiting for a slot fail now with a clear
                        // error; the ones holding a slot keep it to the end.
                        tcp_state.mpc_sessions.close();
                        break;
                    }
                }
            }
        });
    }

    if let Some(listener) = ws_listener {
        spawn_http_server(
            listener,
            router(state.clone(), config.internal_proxy_route),
            phase_rx.clone(),
            state.setup_deadline,
        );
    }

    // Expired leases and dead windows go on their own; the sweep only keeps
    // the store from growing. Every replica runs one, which is safe.
    let sweep_store = state.limits.clone();
    let mut sweep_phase = phase_rx;
    tokio::spawn(async move {
        loop {
            tokio::select! {
                () = tokio::time::sleep(SWEEP_EVERY) => {
                    match sweep_store.sweep().await {
                        Ok(rows) => debug!(rows, "limits store swept"),
                        Err(error) => warn!(%error, "limits store sweep failed"),
                    }
                }
                _ = sweep_phase.changed() => break,
            }
        }
    });

    Ok(NotaryServerHandle {
        local_addr,
        ws_local_addr,
        phase: phase_tx,
        draining: Arc::clone(&state.draining),
        in_flight: state.in_flight.clone(),
        // A token lives from admission to the handler's return: the setup
        // deadline bounds the first stretch, the connection deadline the second.
        drain_deadline: state.setup_deadline + state.connection_deadline,
    })
}

/// How long the accept loop waits after an accept fails for a reason that
/// is the host's, such as running out of file descriptors, before it tries
/// again.
const ACCEPT_RETRY: Duration = Duration::from_secs(1);

/// Serve `app` on `listener` until the phase reaches `Stopped`. Draining
/// keeps the listener open on purpose: the health check has to be reachable
/// to say 503.
///
/// HTTP/1.1 only: the balancer speaks nothing else to a target and the
/// WebSocket upgrade is HTTP/1.1. A connection that has not sent its
/// request headers within `header_deadline` is closed; until it has, it
/// holds no token, no slot and no client, so this is its only bound.
fn spawn_http_server(
    listener: TcpListener,
    app: Router,
    mut phase: watch::Receiver<Phase>,
    header_deadline: Duration,
) {
    tokio::spawn(async move {
        // Connect info so a session's log lines can name the peer.
        let mut make_service = app.into_make_service_with_connect_info::<SocketAddr>();
        let connections = TaskTracker::new();
        loop {
            let (stream, peer) = tokio::select! {
                accepted = listener.accept() => match accepted {
                    Ok(accepted) => accepted,
                    Err(error) if is_peer_error(&error) => continue,
                    Err(error) => {
                        error!(%error, "HTTP accept failed");
                        tokio::time::sleep(ACCEPT_RETRY).await;
                        continue;
                    }
                },
                changed = phase.changed() => {
                    if changed.is_err() || *phase.borrow_and_update() == Phase::Stopped {
                        break;
                    }
                    continue;
                }
            };
            let service = make_service
                .call(peer)
                .await
                .unwrap_or_else(|never| match never {});
            connections.spawn(serve_connection(
                stream,
                peer,
                service,
                phase.clone(),
                header_deadline,
            ));
        }
        drop(listener);
        connections.close();
        connections.wait().await;
    });
}

/// One HTTP/1.1 connection, served until the peer is done with it or the
/// phase reaches `Stopped`, when it is told to finish the request in
/// progress and close. A WebSocket upgrade hands the stream to its session
/// and ends the connection here.
async fn serve_connection(
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    service: AddExtension<Router, ConnectInfo<SocketAddr>>,
    mut phase: watch::Receiver<Phase>,
    header_deadline: Duration,
) {
    let mut connection = pin!(http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(header_deadline)
        .serve_connection(TokioIo::new(stream), TowerToHyperService::new(service))
        .with_upgrades());
    let served = loop {
        tokio::select! {
            served = connection.as_mut() => break served,
            changed = phase.changed() => {
                if changed.is_err() || *phase.borrow_and_update() == Phase::Stopped {
                    connection.as_mut().graceful_shutdown();
                    break connection.await;
                }
            }
        }
    };
    if let Err(error) = served {
        debug!(%peer, %error, "HTTP connection ended");
    }
}

/// Whether an accept failed because of the peer, which hung up before it
/// was accepted, rather than the host. A peer's failure is nothing to
/// wait out.
fn is_peer_error(error: &std::io::Error) -> bool {
    use std::io::ErrorKind::{
        ConnectionAborted,
        ConnectionRefused,
        ConnectionReset,
    };
    matches!(
        error.kind(),
        ConnectionRefused | ConnectionAborted | ConnectionReset
    )
}

#[cfg(test)]
mod tests {
    use libid_signer::{
        ManagedSigner,
        SignerSource,
    };

    /// Each session test drives a real MPC-TLS or ProxyMode setup, which is
    /// CPU-heavy in a debug build. Run at once on a 4-vCPU CI runner they
    /// starve each other past their timeouts; one at a time they fit easily.
    pub(super) static ONE_SESSION_AT_A_TIME: tokio::sync::Mutex<()> =
        tokio::sync::Mutex::const_new(());

    /// anvil #0 — public test key.
    const TEST_KEY: &str =
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    pub(super) async fn test_signer() -> ManagedSigner {
        SignerSource::from_spec(TEST_KEY)
            .unwrap()
            .build_managed(None)
            .await
            .unwrap()
    }
}
