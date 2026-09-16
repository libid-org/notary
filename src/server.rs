//! Notary server: handles plain-TCP (backend MPC-TLS) and WebSocket connections.
//!
//! # Endpoints
//!
//! - **TCP** (`--port`): MPC-TLS verifier for Rust backend provers. The section
//!   9.1 ceremony attestation is written back down the socket the prover
//!   opened. Nothing here dispatches on the server name: the record carries
//!   it, and the contract that reads the record pins it.
//! - **GET  /info**: returns `{version, publicKey}` — compatible with tlsn-js.
//! - **GET  /healthcheck**: `{"status":"ok"}`, or 503 `{"status":"draining"}`
//!   once the process has been told to stop.
//! - **GET /notarize-proxy** (WS upgrade): ProxyMode session followed by one
//!   length-prefixed ceremony attestation in its own WebSocket message.
//!
//! The HTTP routes are served on two listeners, the public one (`--ws-port`)
//! and the internal one (`--internal-ws-port`). The listening port is the
//! whole classification: every per-client limit applies on the public port
//! and none on the internal one, and nothing a connection carries -- header,
//! peer address, anything -- moves it from one tier to the other.
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
//! authenticates it -- the Notary Service of ceremony-common section 9.1 --
//! and NOT the proving circuit: an attestation is authenticated on chain, and
//! the circuit proves only what cannot be read from authenticated evidence.

use std::{
    net::SocketAddr,
    sync::{
        atomic::{
            AtomicBool,
            AtomicUsize,
            Ordering,
        },
        Arc,
    },
    time::{
        Duration,
        Instant,
        SystemTime,
    },
};

use axum::{
    extract::{
        ws::{
            CloseFrame,
            Message,
            WebSocket,
            WebSocketUpgrade,
        },
        ConnectInfo,
        State,
    },
    http::{
        header::RETRY_AFTER,
        StatusCode,
    },
    response::{
        IntoResponse,
        Json,
        Response,
    },
    routing::get,
    Router,
};
use futures_util::{
    SinkExt,
    StreamExt,
};
use libid_ceremony::AttestedData;
use libid_signer::{
    ManagedSigner,
    SignerSource,
};
use libid_tlsn::attest::{
    FromObserved,
    ObservedSession,
};
use libid_transcript::{
    write_msg,
    AttestationWire,
};
use serde::Serialize;
use tlsn::{
    config::verifier::VerifierConfig,
    connection::ServerName,
    transcript::{
        PartialTranscript,
        TranscriptCommitment,
    },
    verifier::{
        VerifierCommitStart,
        VerifierOutput,
    },
    Session,
};
use tokio::{
    io::{
        AsyncReadExt,
        AsyncWriteExt,
    },
    net::TcpListener,
    sync::{
        watch,
        Notify,
        Semaphore,
        TryAcquireError,
    },
};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tower_http::cors::{
    Any,
    CorsLayer,
};
use tracing::{
    debug,
    error,
    info,
    warn,
};

use crate::{
    client_ip::{
        self,
        ClientKey,
    },
    config::{
        ClientIpHeader,
        NotaryServerConfig,
    },
    error::{
        Error,
        Result,
    },
    limits::{
        available_cores,
        CappedIo,
        DataCap,
        PeekedIo,
    },
    store::{
        self,
        Dimension,
        LeaseId,
        LimitStore,
        WindowLimits,
    },
};

/// How far along the server is in stopping. The listeners watch this.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Accepting everything.
    Running,
    /// Told to stop: the MPC listener is closed, the HTTP listeners answer
    /// only to say so (503), and the sessions already running finish.
    Draining,
    /// Every session is done or out of time; the HTTP listeners close.
    Stopped,
}

/// Handle for controlling the running notary server.
pub struct NotaryServerHandle {
    local_addr: Option<SocketAddr>,
    ws_local_addr: Option<SocketAddr>,
    internal_ws_local_addr: Option<SocketAddr>,
    phase: watch::Sender<Phase>,
    draining: Arc<AtomicBool>,
    in_flight: Arc<InFlight>,
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

    /// Returns the address the internal HTTP/WebSocket server is bound to,
    /// if enabled.
    pub fn internal_ws_local_addr(&self) -> Option<SocketAddr> {
        self.internal_ws_local_addr
    }

    /// Stops every listener now, without waiting for the sessions in
    /// flight. For tests; a deployment calls [`NotaryServerHandle::drain`].
    pub fn shutdown(self) {
        self.draining.store(true, Ordering::SeqCst);
        let _ = self.phase.send(Phase::Stopped);
    }

    /// Stop taking work, finish what is running, then stop the listeners.
    ///
    /// The health check answers 503 from the first moment, so the load
    /// balancer stops routing here while the sessions already running
    /// finish; the MPC listener closes at once and its queue empties with an
    /// error. The HTTP listeners keep answering -- 503 to every upgrade --
    /// until the last session ends or the setup and connection deadlines
    /// together elapse, because a closed port looks like a crash to the
    /// balancer and a 503 looks like what it is. Then they close too, and
    /// this returns.
    pub async fn drain(self) {
        self.draining.store(true, Ordering::SeqCst);
        let _ = self.phase.send(Phase::Draining);
        let open = self.in_flight.count();
        info!(
            sessions = open,
            deadline_secs = self.drain_deadline.as_secs(),
            "draining: no new sessions; waiting for the ones in flight"
        );
        match tokio::time::timeout(self.drain_deadline, self.in_flight.idle()).await {
            Ok(()) => info!("drained: every session finished"),
            Err(_) => warn!(
                sessions = self.in_flight.count(),
                "drain deadline reached with sessions still running; stopping anyway"
            ),
        }
        let _ = self.phase.send(Phase::Stopped);
    }
}

/// The sessions running right now, on every listener, so a drain knows when
/// it is done. A connection counts from the moment its handler starts to the
/// moment it returns: the setup deadline bounds the first stretch and the
/// connection deadline the second, so their sum bounds the drain.
#[derive(Debug, Default)]
struct InFlight {
    count: AtomicUsize,
    idle: Notify,
}

impl InFlight {
    /// Count one more connection until the guard drops.
    fn enter(self: &Arc<Self>) -> InFlightGuard {
        self.count.fetch_add(1, Ordering::SeqCst);
        InFlightGuard(Arc::clone(self))
    }

    fn count(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }

    /// Resolves once nothing is in flight. Registers for the wake-up before
    /// reading the count, so a guard dropped in between is not missed.
    async fn idle(&self) {
        loop {
            let notified = self.idle.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.count() == 0 {
                return;
            }
            notified.await;
        }
    }
}

struct InFlightGuard(Arc<InFlight>);

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        if self.0.count.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.0.idle.notify_waiters();
        }
    }
}

/// Which listener a request arrived on. This, and nothing about the request,
/// decides whether the per-client limits apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tier {
    /// `--ws-port`: browsers behind the load balancer; every limit applies.
    Public,
    /// `--internal-ws-port`: our own services; no per-client limit, no
    /// client address header read, and its own session pool.
    Internal,
}

/// The state one HTTP listener serves its routes from.
#[derive(Clone)]
struct ListenerState {
    tier: Tier,
    notary: NotaryState,
}

/// Owns a spawned task and aborts it on drop unless the handle was taken back
/// out with [`AbortOnDrop::into_inner`].
///
/// Dropping a bare [`tokio::task::JoinHandle`] DETACHES the task rather than
/// cancelling it, so every `?` early return below would leave the spawned
/// driver (or WS pump) running unsupervised — each aborted connection then
/// retains the task and its buffers. With this guard, cancellation is the
/// default on every exit path, including panics and the caller dropping the
/// future; the success path opts out by taking the handle back to join it.
/// (Same shape as the guard inside `libid-tlsn`'s session functions.)
struct AbortOnDrop<T>(Option<tokio::task::JoinHandle<T>>);

impl<T> AbortOnDrop<T> {
    fn new(handle: tokio::task::JoinHandle<T>) -> Self {
        Self(Some(handle))
    }

    /// The wrapped handle, for polling the task without disarming the guard.
    fn handle_mut(&mut self) -> &mut tokio::task::JoinHandle<T> {
        self.0.as_mut().expect("handle present until into_inner")
    }

    /// Disarm the guard and hand the handle back for joining.
    fn into_inner(mut self) -> tokio::task::JoinHandle<T> {
        self.0.take().expect("handle present until into_inner")
    }
}

/// Error for a session driver that finished while session setup was still in
/// flight. The driver only completes once the underlying transport is closed
/// or dead, so a protocol request submitted to it may never resolve: without
/// this, a browser that connected and went away would leave its session
/// pending -- and its slot taken -- until the connection deadline. (Same
/// race, and the same fix, as `libid_tlsn::verifier` on the TCP path.)
fn driver_finished_early<T, E: std::fmt::Display>(
    result: std::result::Result<std::result::Result<T, E>, tokio::task::JoinError>,
) -> Error {
    let detail = match result {
        Ok(Ok(_)) => "driver task finished before the session completed".into(),
        Ok(Err(e)) => format!("driver task: {e}"),
        Err(e) => format!("driver task join: {e}"),
    };
    Error::NotaryServer { detail }
}

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
        }
    }
}

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
    /// Where the public port's per-client counts live. Never consulted for
    /// the internal port.
    limits: Arc<dyn LimitStore>,
    /// Sessions one public client may start per window.
    per_ip_upgrades: WindowLimits,
    /// Bytes one public client may relay per window.
    per_ip_bytes: WindowLimits,
    /// Which header names the client on the public port. Never read on the
    /// internal port.
    client_ip_header: ClientIpHeader,
    /// Bytes one ProxyMode session may relay, both directions combined.
    proxy_max_bytes: usize,
    proxy_root_store: Arc<tlsn::webpki::RootCertStore>,
    /// `None` connects to the TLS-authenticated server name on port 443;
    /// `--proxy-upstream`, a test hook, dials this instead.
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
    in_flight: Arc<InFlight>,
}

#[cfg(test)]
impl NotaryState {
    /// A state around `signer` with every limit at its default; a test
    /// overrides the one field it exercises.
    fn for_tests(signer: ManagedSigner) -> Self {
        Self {
            public_key_hex: hex::encode(signer.compressed_public_key()),
            signer: Arc::new(signer),
            proxy_sessions: Arc::new(Semaphore::new(1024)),
            internal_proxy_sessions: Arc::new(Semaphore::new(1024)),
            max_sessions_per_ip: 4,
            limits: Arc::new(store::MemoryStore::new()),
            per_ip_upgrades: WindowLimits::parse("10/1m,60/30m,100/1h").unwrap(),
            per_ip_bytes: WindowLimits::parse("100MB/1m,600MB/30m,1GB/1h").unwrap(),
            client_ip_header: ClientIpHeader::XForwardedFor,
            proxy_max_bytes: 10_000_000,
            proxy_root_store: Arc::new(libid_tlsn::root_store()),
            proxy_server_addr: None,
            mpc_sessions: Arc::new(Semaphore::new(4)),
            connection_deadline: Duration::from_secs(300),
            setup_deadline: Duration::from_secs(15),
            draining: Arc::new(AtomicBool::new(false)),
            in_flight: Arc::new(InFlight::default()),
        }
    }
}

#[derive(Serialize)]
struct InfoResponse {
    version: String,
    #[serde(rename = "publicKey")]
    public_key: String,
}

// ─── Server startup ──────────────────────────────────────────────────────────

/// How often expired leases and dead windows are swept from the store.
const SWEEP_EVERY: Duration = Duration::from_secs(60);

/// Start the notary server: the MPC-TLS listener and the public and internal
/// HTTP/WebSocket servers, each only if configured.
pub async fn run(config: NotaryServerConfig) -> Result<NotaryServerHandle> {
    let per_ip_upgrades = config
        .per_ip_upgrades()
        .map_err(|detail| Error::NotaryServer { detail })?;
    let per_ip_bytes = config
        .per_ip_bytes()
        .map_err(|detail| Error::NotaryServer { detail })?;
    let limits_store = config
        .limits_store()
        .map_err(|detail| Error::NotaryServer { detail })?;
    let mut proxy_root_store = libid_tlsn::root_store();
    let proxy_upstream = config
        .proxy_upstream()
        .map_err(|detail| Error::NotaryServer { detail })?
        .map(|upstream| {
            warn!(
                addr = %upstream.addr,
                extra_root = upstream.ca.is_some(),
                "TEST HOOK: every ProxyMode session dials --proxy-upstream"
            );
            proxy_root_store.roots.extend(upstream.ca);
            upstream.addr
        });

    // A store that cannot be reached is a startup error, not a limit that
    // refuses every client once the process is up.
    let limits =
        store::connect(&limits_store)
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
        in_flight: Arc::new(InFlight::default()),
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

    // ── Internal HTTP/WebSocket server (our own services) ─────────────
    let internal_ws_listener = match config.internal_ws_port {
        Some(port) => Some(TcpListener::bind(format!("{}:{port}", config.host)).await?),
        None => None,
    };
    let internal_ws_local_addr = internal_ws_listener
        .as_ref()
        .and_then(|l| l.local_addr().ok());
    match internal_ws_local_addr {
        Some(addr) => info!("Notary WebSocket listening on {addr} (internal)"),
        None => info!("Notary internal WebSocket port off (--internal-ws-port not set)"),
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
                                let in_flight = s.in_flight.enter();
                                tokio::spawn(async move {
                                    let _in_flight = in_flight;
                                    if let Err(e) = handle_tcp_prover(stream, &s).await {
                                        error!("TCP handler error for {}: {}", peer, e);
                                    }
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
        spawn_http_server(listener, Tier::Public, state.clone(), phase_rx.clone());
    }
    if let Some(listener) = internal_ws_listener {
        spawn_http_server(listener, Tier::Internal, state.clone(), phase_rx.clone());
    }

    // Expired leases and dead windows go on their own; the sweep only keeps
    // the store from growing. Every replica runs one, which is safe.
    let sweep_store = Arc::clone(&state.limits);
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
        internal_ws_local_addr,
        phase: phase_tx,
        draining: Arc::clone(&state.draining),
        in_flight: Arc::clone(&state.in_flight),
        drain_deadline: state.setup_deadline + state.connection_deadline,
    })
}

/// The HTTP routes, served as `tier`. Both listeners are built here; only
/// the tier differs.
fn router(tier: Tier, notary: NotaryState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_headers(Any)
        .allow_methods(Any);
    Router::new()
        .route("/info", get(info_handler))
        .route("/healthcheck", get(healthcheck_handler))
        .route("/notarize-proxy", get(notarize_proxy_ws_handler))
        .layer(cors)
        .with_state(ListenerState { tier, notary })
}

/// Serve `router(tier, state)` on `listener` until the phase reaches
/// `Stopped`. Draining keeps the listener open on purpose: the health check
/// has to be reachable to say 503.
fn spawn_http_server(
    listener: TcpListener,
    tier: Tier,
    state: NotaryState,
    mut phase: watch::Receiver<Phase>,
) {
    let app = router(tier, state);
    tokio::spawn(async move {
        // Connect info so a session's log lines can name the peer.
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            while *phase.borrow_and_update() != Phase::Stopped {
                if phase.changed().await.is_err() {
                    break;
                }
            }
        })
        .await
        .unwrap_or_else(|e| error!("{tier:?} HTTP server error: {}", e));
    });
}

// ─── REST handlers ───────────────────────────────────────────────────────────

async fn info_handler(State(listener): State<ListenerState>) -> Json<InfoResponse> {
    Json(InfoResponse {
        version: format!("v{}", env!("CARGO_PKG_VERSION")),
        public_key: listener.notary.public_key_hex.clone(),
    })
}

/// `{"status":"ok"}`, or 503 `{"status":"draining"}` once the process has
/// been told to stop, so the balancer takes this replica out before its
/// listeners close.
async fn healthcheck_handler(State(listener): State<ListenerState>) -> Response {
    if listener.notary.draining.load(Ordering::SeqCst) {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "status": "draining" })),
        )
            .into_response()
    } else {
        Json(serde_json::json!({ "status": "ok" })).into_response()
    }
}

// ─── Ceremony attestation ───────────────────────────────────────────────────

// The wire record itself is `libid_transcript::AttestationWire`. It is defined
// there, beside the `write_msg`/`read_msg` that frame it, because a prover has
// to read exactly what this writes -- and a copy here would be a second
// definition of one message, agreeing only for as long as nobody renames a
// field. What the notary puts in it is still decided here, and it is nothing
// it derived by applying a profile rule: no handle, no account identifier, no
// client identifier, no chain address (REQ-COMMON-61). Every one is derivable
// from the revealed ranges, and a second signed representation can disagree
// with the bytes it was taken from. That is why this endpoint no longer takes
// `handle`, `user_id` or `session_addr` -- the Platform Verifier reads them
// itself, and the notary deciding them would be the profile-specific
// judgement REQ-COMMON-33 forbids it.

/// Build the section 9.1 attested data for one completed session and sign it.
///
/// Both transports end here and receive the same record on their reclaimed
/// channel, because transport says nothing about the TLS session it describes.
async fn sign_ceremony_attestation(
    signer: &ManagedSigner,
    partial: &PartialTranscript,
    authority: &str,
    commitments: &[TranscriptCommitment],
    created_at: u64,
) -> Result<AttestationWire> {
    let attested = AttestedData::from_observed(ObservedSession {
        transcript: partial,
        authority,
        commitments,
        created_at,
    })
    .map_err(|e| Error::NotaryServer {
        detail: format!("attested data: {e}"),
    })?;
    let encoded = attested.encode().map_err(|e| Error::NotaryServer {
        detail: format!("encode attested data: {e}"),
    })?;

    // The notary signs `keccak256(attestedData)` and no other preimage
    // (REQ-COMMON-47).
    let notary_signature = signer
        .sign_claim(&libid_crypto::keccak256(&encoded))
        .await?;
    Ok(AttestationWire {
        attested_data: encoded,
        notary_signature,
    })
}

fn attestation_frame(attestation: &AttestationWire) -> Result<Vec<u8>> {
    const MAX_FRAME_BYTES: usize = 10 * 1024 * 1024;

    let json = serde_json::to_vec(attestation)?;
    if json.len() > MAX_FRAME_BYTES {
        return Err(Error::NotaryServer {
            detail: format!("attestation frame is too large: {} bytes", json.len()),
        });
    }
    let len = u32::try_from(json.len())
        .map_err(|_| Error::NotaryServer {
            detail: format!("attestation frame is too large: {} bytes", json.len()),
        })?
        .to_be_bytes();
    let mut frame = Vec::with_capacity(len.len() + json.len());
    frame.extend_from_slice(&len);
    frame.extend_from_slice(&json);
    Ok(frame)
}

// ─── ProxyMode WebSocket handler ─────────────────────────────────────────────
//
// The browser (prover) connects here as a WebSocket. The notary runs the
// ProxyMode verifier: it forwards raw TLS bytes between the browser and the
// target server, authenticates the transcript against the record layer's own
// tags, then receives the prover's reveal request and captures what the
// session disclosed.

/// Seconds a refused client is told to wait before its next upgrade.
const RETRY_AFTER_SECS: &str = "60";

async fn notarize_proxy_ws_handler(
    ws: WebSocketUpgrade,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    State(listener): State<ListenerState>,
) -> Response {
    let state = listener.notary;

    // In flight from here, before the draining check: admission is two
    // store round trips, and an upgrade inside them when the drain starts
    // must be waited for, not raced. Every refusal below drops the guard.
    let in_flight = state.in_flight.enter();

    // Nothing new once the process is stopping; the sessions already
    // running finish, and the balancer has been told by the health check.
    if state.draining.load(Ordering::SeqCst) {
        info!(%peer, "ProxyMode: upgrade refused, notary is draining");
        return (StatusCode::SERVICE_UNAVAILABLE, "notary is draining").into_response();
    }

    // The port is the whole classification. The internal listener asks
    // nothing about the client and consults no store: our own services are
    // the protocol, not users of it.
    let client = match listener.tier {
        Tier::Internal => {
            if state.internal_proxy_sessions.available_permits() == 0 {
                info!(%peer, "ProxyMode (internal): all session slots busy; upgrade refused with 503");
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
            None
        }
        Tier::Public => match admit_public_upgrade(peer, &headers, &state).await {
            Ok(client) => Some(client),
            Err(refusal) => return refusal,
        },
    };

    ws.on_upgrade(move |socket| async move {
        let _in_flight = in_flight;
        handle_ws_proxy_notarize(socket, peer, client, state).await;
    })
}

/// The public port's checks before an upgrade, cheapest first, and the
/// client the session counts against if it passes them all. A refusal is the
/// response to send instead.
async fn admit_public_upgrade(
    peer: SocketAddr,
    headers: &axum::http::HeaderMap,
    state: &NotaryState,
) -> std::result::Result<ClientKey, Response> {
    // Who this session counts against. A refusal here is a refusal, never a
    // fallback to the socket peer: behind a load balancer that peer is the
    // balancer, so falling back would quietly turn the per-client cap into a
    // cap on the whole service.
    let client = match client_ip::resolve(headers, state.client_ip_header) {
        Ok(client) => client,
        Err(reason) => {
            info!(%peer, %reason, "ProxyMode: upgrade refused, client unidentified");
            return Err((StatusCode::BAD_REQUEST, reason.to_string()).into_response());
        }
    };

    // Refuse rather than queue: a browser retries a refused upgrade cheaply,
    // and nothing has been spent on this session yet.
    //
    // No slot is reserved here. The check is advisory -- it turns a saturated
    // notary away at the cheapest point, before the upgrade -- and the slot
    // itself is taken when the browser sends its first relayed bytes. A socket
    // that upgrades and then stays silent would otherwise hold a slot for the
    // whole connection deadline: a denial of service costing one 150-byte
    // request per slot.
    if state.proxy_sessions.available_permits() == 0 {
        info!(%peer, "ProxyMode: all session slots busy; upgrade refused with 503");
        return Err(StatusCode::SERVICE_UNAVAILABLE.into_response());
    }

    // The windows, in the shared store. An upgrade is counted here, before
    // anything is spent on it; the bytes window only has to have room, since
    // the bytes are charged when the session ends. A store that cannot
    // answer is a refusal: a limit that fails open under a store outage is a
    // limit an attacker can switch off. An empty window is no limit, and
    // asks the store nothing.
    let store_down = |error: store::StoreError| {
        warn!(%peer, %client, %error, "ProxyMode: upgrade refused, limits store unavailable");
        (StatusCode::SERVICE_UNAVAILABLE, "limits store unavailable").into_response()
    };
    let too_many = |what: &str| {
        info!(%peer, %client, "ProxyMode: upgrade refused with 429, {what} window full");
        (
            StatusCode::TOO_MANY_REQUESTS,
            [(RETRY_AFTER, RETRY_AFTER_SECS)],
            format!("too many {what} from this client; retry later"),
        )
            .into_response()
    };
    if !state.per_ip_upgrades.is_empty() {
        match state
            .limits
            .count(&client, Dimension::Upgrades, 1, &state.per_ip_upgrades)
            .await
        {
            Ok(true) => {}
            Ok(false) => return Err(too_many("sessions started")),
            Err(error) => return Err(store_down(error)),
        }
    }
    if !state.per_ip_bytes.is_empty() {
        match state
            .limits
            .would_fit(&client, Dimension::Bytes, 1, &state.per_ip_bytes)
            .await
        {
            Ok(true) => {}
            Ok(false) => return Err(too_many("bytes relayed")),
            Err(error) => return Err(store_down(error)),
        }
    }
    Ok(client)
}

/// How a ProxyMode WebSocket ends once the session is over: with the
/// attestation and a clean close, or with a close frame that says why there is
/// none. The pump owns the sink, so the session hands it the ending.
enum SessionEnd {
    /// The framed attestation, then a normal close.
    Attested(Vec<u8>),
    /// No attestation; the frame tells the browser what cut it off.
    Aborted(CloseFrame),
}

/// WebSocket close code 1008, "policy violation": the session broke a rule of
/// this endpoint, and the reason names which one.
const CLOSE_POLICY_VIOLATION: u16 = 1008;

/// WebSocket close code 1013, "try again later": the notary is at capacity.
/// It differs from the 503 on the upgrade only in when it happens -- the slots
/// filled between this browser's upgrade and its first bytes.
const CLOSE_TRY_AGAIN_LATER: u16 = 1013;

/// The browser's first relayed bytes, or `None` if it went away before sending
/// any.
///
/// Only a binary frame starts a session. Pings and text do not: a socket kept
/// warm by pings is still an idle socket, and the point of waiting here is
/// that idle sockets hold no session slot.
async fn first_relayed_bytes(
    ws_rx: &mut futures_util::stream::SplitStream<WebSocket>,
) -> Option<Vec<u8>> {
    while let Some(Ok(msg)) = ws_rx.next().await {
        match msg {
            Message::Binary(data) => return Some(data.to_vec()),
            Message::Close(_) => return None,
            _ => {}
        }
    }
    None
}

/// What one public session owes the store when it ends: the bytes it
/// relayed, charged to its client's windows, and its lease back.
///
/// Settled on the way out of the handler; if the handler never gets there --
/// a panic, or the task cancelled under it -- the drop settles from a task
/// of its own, so no lease outlives its session and no bytes go uncharged.
/// Neither can fail the session: a store that will not take the charge is
/// logged and the session has already ended.
struct Accounting {
    store: Arc<dyn LimitStore>,
    client: ClientKey,
    lease: Option<LeaseId>,
    relayed: Arc<DataCap>,
    windows: WindowLimits,
    settled: bool,
}

impl Accounting {
    async fn settle(mut self) {
        self.settled = true;
        settle(
            &*self.store,
            self.client,
            self.lease.take(),
            self.relayed.used(),
            &self.windows,
        )
        .await;
    }
}

impl Drop for Accounting {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        let store = Arc::clone(&self.store);
        let client = self.client;
        let lease = self.lease.take();
        let used = self.relayed.used();
        let windows = std::mem::take(&mut self.windows);
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                runtime.spawn(async move {
                    settle(&*store, client, lease, used, &windows).await;
                });
            }
            // The runtime itself is going away; the lease expires by itself.
            Err(_) => {
                warn!(%client, "ProxyMode: no runtime to settle a session's accounting")
            }
        }
    }
}

async fn settle(
    store: &dyn LimitStore,
    client: ClientKey,
    lease: Option<LeaseId>,
    used: usize,
    windows: &WindowLimits,
) {
    if used > 0 {
        if let Err(error) = store
            .charge(&client, Dimension::Bytes, used as u64, windows)
            .await
        {
            warn!(%client, used, %error, "ProxyMode: relayed bytes not charged");
        }
    }
    if let Some(lease) = lease {
        if let Err(error) = store.release(&lease).await {
            warn!(%client, %error, "ProxyMode: session lease not released; it expires by itself");
        }
    }
}

/// One ProxyMode session on an upgraded socket. `client` is `Some` on the
/// public port, where the session holds a lease and its bytes are charged,
/// and `None` on the internal port, where nothing is counted per client.
async fn handle_ws_proxy_notarize(
    socket: WebSocket,
    peer: SocketAddr,
    client: Option<ClientKey>,
    state: NotaryState,
) {
    let (mut ws_tx, mut ws_rx) = socket.split();

    // The session starts here, not at the upgrade: a slot is worth spending
    // once there is a session to spend it on.
    let first =
        match tokio::time::timeout(state.setup_deadline, first_relayed_bytes(&mut ws_rx))
            .await
        {
            Ok(Some(first)) => first,
            Ok(None) => {
                info!(%peer, "ProxyMode: browser closed before starting a session");
                return;
            }
            Err(_) => {
                info!(
                    %peer,
                    "ProxyMode: no session data within the {}s setup deadline; closing",
                    state.setup_deadline.as_secs()
                );
                let _ = ws_tx
                    .send(Message::Close(Some(CloseFrame {
                        code: CLOSE_POLICY_VIOLATION,
                        reason: "no session data within the setup deadline".into(),
                    })))
                    .await;
                return;
            }
        };

    // Every relayed byte counts against the session cap on both tiers -- it
    // is what bounds a transcript, not a rate -- and on the public tier the
    // total is charged to the client when the session ends.
    let relayed = DataCap::new(state.proxy_max_bytes);

    // This client's own lease first: one client at its cap must not spend a
    // slot from the shared pool to find that out. Held for the session
    // lifetime, like the pool permit below.
    let (pool, accounting) = match client {
        None => (&state.internal_proxy_sessions, None),
        Some(client) => {
            let lease = if state.max_sessions_per_ip == 0 {
                None
            } else {
                match state
                    .limits
                    .try_lease(
                        &client,
                        state.max_sessions_per_ip,
                        state.connection_deadline,
                    )
                    .await
                {
                    Ok(Some(lease)) => Some(lease),
                    Ok(None) => {
                        info!(
                            %peer, %client,
                            "ProxyMode: client already running {} sessions; refused with 1013",
                            state.max_sessions_per_ip
                        );
                        let _ = ws_tx
                            .send(Message::Close(Some(CloseFrame {
                                code: CLOSE_TRY_AGAIN_LATER,
                                reason: "too many sessions from this client; retry"
                                    .into(),
                            })))
                            .await;
                        return;
                    }
                    Err(error) => {
                        warn!(%peer, %client, %error, "ProxyMode: session refused, limits store unavailable");
                        let _ = ws_tx
                            .send(Message::Close(Some(CloseFrame {
                                code: CLOSE_TRY_AGAIN_LATER,
                                reason: "limits store unavailable".into(),
                            })))
                            .await;
                        return;
                    }
                }
            };
            let accounting = Accounting {
                store: Arc::clone(&state.limits),
                client,
                lease,
                relayed: Arc::clone(&relayed),
                windows: state.per_ip_bytes.clone(),
                settled: false,
            };
            (&state.proxy_sessions, Some(accounting))
        }
    };

    // Held for the session lifetime; dropping it returns the slot.
    let Ok(_permit) = Arc::clone(pool).try_acquire_owned() else {
        info!(%peer, "ProxyMode: all session slots busy; session refused with 1013");
        let _ = ws_tx
            .send(Message::Close(Some(CloseFrame {
                code: CLOSE_TRY_AGAIN_LATER,
                reason: "notary is at capacity; retry".into(),
            })))
            .await;
        if let Some(accounting) = accounting {
            accounting.settle().await;
        }
        return;
    };

    let (io_a, io_b) = tokio::io::duplex(1 << 17);
    let (mut pipe_reader, mut pipe_writer) = tokio::io::split(io_a);

    // Keep inbound and outbound ownership separate. Whichever direction ends
    // first must not cancel a write already accepted in the other direction.
    let (end_tx, end_rx) = tokio::sync::oneshot::channel::<SessionEnd>();
    let _inbound_task = AbortOnDrop::new(tokio::spawn(async move {
        // The frame that started the session, put back in front of the rest.
        if pipe_writer.write_all(&first).await.is_ok() {
            while let Some(Ok(msg)) = ws_rx.next().await {
                match msg {
                    Message::Binary(data)
                        if pipe_writer.write_all(&data).await.is_err() =>
                    {
                        break
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
        }
        // The browser is gone, by close frame or by dropped socket. Tell the
        // session so: it reads EOF, fails, and the connection's session slot
        // comes back now. Dropping the write half alone would not do that --
        // the read half in the outbound pump keeps the pipe open -- and the
        // session would sit on its slot until the connection deadline.
        let _ = pipe_writer.shutdown().await;
    }));
    let outbound_task = AbortOnDrop::new(tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            match pipe_reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if ws_tx
                        .send(Message::Binary(buf[..n].to_vec().into()))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
        }

        // This message boundary is the handoff: TLSNotary may read ahead
        // within one WebSocket message, but it cannot consume this later one
        // before its mux has finished.
        match end_rx.await {
            Ok(SessionEnd::Attested(frame)) => {
                let _ = ws_tx.send(Message::Binary(frame.into())).await;
                let _ = ws_tx.send(Message::Close(None)).await;
            }
            Ok(SessionEnd::Aborted(close)) => {
                let _ = ws_tx.send(Message::Close(Some(close))).await;
            }
            Err(_) => {
                let _ = ws_tx.send(Message::Close(None)).await;
            }
        }
    }));

    let protocol = async {
        let result = match run_proxy_verifier_session(io_b, &state, &relayed).await {
            Ok(attestation) => attestation_frame(&attestation).and_then(|frame| {
                end_tx.send(SessionEnd::Attested(frame)).map_err(|_| {
                    Error::NotaryServer {
                        detail: "browser disconnected before attestation handoff".into(),
                    }
                })
            }),
            Err(Error::ProxyDataCapExceeded {
                authority,
                used,
                limit,
            }) => {
                // The browser must learn it was the cap and not the network;
                // a bare drop would look like any other failure. Fits the
                // 123-byte reason budget with room to spare.
                let _ = end_tx.send(SessionEnd::Aborted(CloseFrame {
                    code: CLOSE_POLICY_VIOLATION,
                    reason: format!(
                        "PROXY_DATA_CAP_EXCEEDED: relayed {used} bytes, cap {limit}"
                    )
                    .into(),
                }));
                Err(Error::ProxyDataCapExceeded {
                    authority,
                    used,
                    limit,
                })
            }
            Err(error) => {
                drop(end_tx);
                Err(error)
            }
        };
        if let Err(error) = outbound_task.into_inner().await {
            error!("ProxyMode WebSocket outbound pump join error: {error}");
        }
        result
    };

    match tokio::time::timeout(state.connection_deadline, protocol).await {
        Ok(Ok(())) => {}
        Ok(Err(Error::ProxyDataCapExceeded {
            authority,
            used,
            limit,
        })) => error!(
            %peer,
            authority,
            used,
            limit,
            "ProxyMode session aborted: data cap exceeded; nothing attested"
        ),
        Ok(Err(e)) => error!(%peer, "ProxyMode verifier error: {}", e),
        Err(_) => error!(
            %peer,
            "ProxyMode session exceeded the {}s connection deadline; aborting",
            state.connection_deadline.as_secs()
        ),
    }

    if let Some(accounting) = accounting {
        accounting.settle().await;
    }
}

/// The verifier's half of one ProxyMode session on `socket`; every byte
/// relayed to the server counts against `relayed`.
async fn run_proxy_verifier_session<T>(
    socket: T,
    state: &NotaryState,
    relayed: &Arc<DataCap>,
) -> Result<AttestationWire>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();
    // Guarded spawn: every exit path below — each `?`, panics, the caller
    // dropping this future — aborts the driver instead of detaching it.
    let mut driver_task = AbortOnDrop::new(tokio::spawn(driver));

    // Set once the relay has run. Before that, the driver finishing means the
    // browser went away under the session; after, it means the peer closed
    // the mux, which is how a session ends.
    let established = AtomicBool::new(false);
    let established = &established;

    // An inner error means a rejection was sent and the driver must be joined
    // before returning; an outer error can abort the guarded driver.
    let setup = async {
        let verifier = handle
            .new_verifier(
                VerifierConfig::builder()
                    .root_store(state.proxy_root_store.as_ref().clone())
                    .build()
                    .map_err(|e| Error::NotaryServer {
                        detail: format!("verifier config: {e}"),
                    })?,
            )
            .map_err(|e| Error::NotaryServer {
                detail: format!("new verifier: {e}"),
            })?;

        let verifier = verifier.commit().await.map_err(|e| Error::NotaryServer {
            detail: format!("verifier commit: {e}"),
        })?;

        let proxy_verifier = match verifier {
            VerifierCommitStart::Proxy(v) => v,
            _ => {
                return Err(Error::NotaryServer {
                    detail: "expected ProxyTls protocol, got other".into(),
                });
            }
        };

        let server_name_str = proxy_verifier.config().server_name().as_str().to_string();
        info!("ProxyMode: connecting to {server_name_str}:443");

        let server_addr = state
            .proxy_server_addr
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| format!("{server_name_str}:443"));
        let server_tcp = match tokio::net::TcpStream::connect(server_addr).await {
            Ok(server_tcp) => server_tcp,
            Err(error) => {
                let detail = format!("TCP connect to {server_name_str}: {error}");
                proxy_verifier
                    .reject(Some("UPSTREAM_CONNECT_FAILED"))
                    .await
                    .map_err(|error| Error::NotaryServer {
                        detail: format!("send connection rejection: {error}"),
                    })?;
                handle.close();
                return Ok(Err(Error::NotaryServer { detail }));
            }
        };

        // The relay is the only unbounded thing in ProxyMode: tlsn buffers
        // every relayed byte for the tag check that follows, so the cap on the
        // server stream is the cap on this session's memory. Crossing it fails
        // the relay mid-stream; the transcript is never shortened, because a
        // shortened one would attest as complete.
        let cap = Arc::clone(relayed);
        let verifier = proxy_verifier
            .accept()
            .await
            .map_err(|e| Error::NotaryServer {
                detail: format!("verifier accept: {e}"),
            })?
            .run(CappedIo::new(server_tcp, Arc::clone(&cap)).compat())
            .await
            .map_err(|e| {
                if cap.exceeded() {
                    Error::ProxyDataCapExceeded {
                        authority: server_name_str.clone(),
                        used: cap.used(),
                        limit: cap.limit(),
                    }
                } else {
                    Error::NotaryServer {
                        detail: format!("run_proxy: {e}"),
                    }
                }
            })?;
        established.store(true, Ordering::Release);

        let verifier = verifier.verify().await.map_err(|e| Error::NotaryServer {
            detail: format!("verifier verify: {e}"),
        })?;

        if !verifier.request().server_identity() {
            verifier
                .reject(Some("server identity is required"))
                .await
                .ok();
            return Err(Error::NotaryServer {
                detail: "prover did not request server identity reveal".into(),
            });
        }

        let (
            VerifierOutput {
                server_name,
                transcript,
                transcript_commitments,
            },
            verifier,
        ) = verifier.accept().await.map_err(|e| Error::NotaryServer {
            detail: format!("verifier output accept: {e}"),
        })?;

        verifier.close().await.map_err(|e| Error::NotaryServer {
            detail: format!("verifier close: {e}"),
        })?;
        handle.close();

        Ok::<_, Error>(Ok((server_name, transcript, transcript_commitments)))
    };
    tokio::pin!(setup);

    // Race setup against the driver. The driver only finishes early when the
    // transport died under the session -- a browser that connected and went
    // away -- and a protocol request already submitted to it may then never
    // resolve, so fail instead of pending forever on a taken slot.
    let mut finished_driver = None;
    let setup_outcome = tokio::select! {
        biased;
        res = &mut setup => res?,
        driver_res = driver_task.handle_mut() => {
            if !established.load(Ordering::Acquire) {
                return Err(driver_finished_early(driver_res));
            }
            // The peer closed the mux as its last act while this side was
            // still finishing. Let setup complete and keep the driver's
            // result: a finished handle cannot be polled a second time.
            finished_driver = Some(driver_res);
            (&mut setup).await?
        }
    };
    let join_driver = |driver_task: AbortOnDrop<_>| async move {
        match finished_driver {
            Some(res) => res,
            None => driver_task.into_inner().await,
        }
    };
    let (server_name, transcript, transcript_commitments) = match setup_outcome {
        Ok(output) => output,
        Err(error) => {
            let _ = join_driver(driver_task).await;
            return Err(error);
        }
    };

    let io = join_driver(driver_task)
        .await
        .map_err(|e| Error::NotaryServer {
            detail: format!("driver join: {e}"),
        })?
        .map_err(|e| Error::NotaryServer {
            detail: format!("driver: {e}"),
        })?
        .into_inner();
    drop(io);

    // What the prover chose to reveal is not read here and not judged here.
    // Which ranges a profile expects belongs to the Platform Verifier
    // (REQ-COMMON-51), and this used to name them -- one endpoint's shape
    // written into the notary, which is the profile-specific decision
    // REQ-COMMON-33 forbids it from making.
    let server_name = server_name.ok_or_else(|| Error::NotaryServer {
        detail: "prover did not reveal server name".into(),
    })?;
    let ServerName::Dns(ref dns_name) = server_name;
    let domain = dns_name.as_str().to_string();

    // Which host answered is attested, not restricted. The record carries the
    // cert-verified server name as `authorityId`, and each Platform Verifier
    // compares that against the authority its own profile pins -- so an
    // attestation naming an attacker's server is refused on chain, by the
    // contract that knows which host the session was supposed to reach.
    //
    // Pinning one hostname here would add nothing to that and would cost
    // something real: GitHub alone needs two authorities (`github.com` for the
    // exchange, `api.github.com` for the identity session), so a single
    // platform identity cannot serve even one platform, let alone a notary
    // shared by X and GitHub. Limiting who may use a public notary is access
    // control, and belongs where access control lives.

    let partial_transcript = transcript;
    if let Some(ref pt) = partial_transcript {
        info!(
            "ProxyMode verified: {} sent, {} recv bytes for {domain}",
            pt.sent_unsafe().len(),
            pt.received_unsafe().len()
        );
    } else {
        info!("ProxyMode verified: no transcript revealed for {domain} (commits only)");
    }

    // ── Extract the single hash commit per session ──
    //
    // Keep the session's own output rather than flattening it. Which ranges a
    // profile expects, and what their bytes must contain, is the Platform
    // Verifier's business (REQ-COMMON-51); the notary answers only for what it
    // observed. The range-count rules that used to live here encoded one
    // endpoint's shape into the notary, which is exactly the profile-specific
    // decision REQ-COMMON-33 forbids it from making.
    let Some(partial) = partial_transcript else {
        return Err(Error::NotaryServer {
            detail: "session revealed no transcript".into(),
        });
    };

    let attestation = sign_ceremony_attestation(
        &state.signer,
        &partial,
        dns_name.as_str(),
        &transcript_commitments,
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    )
    .await?;
    info!("ProxyMode: ceremony attestation ready for {domain}");
    Ok(attestation)
}

// ─── Core notary logic (transport-agnostic) ─────────────────────────────────

/// TCP client (Rust backend prover) — uses the full custom wire protocol.
async fn handle_tcp_prover<T>(socket: T, state: &NotaryState) -> Result<()>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Sync + Unpin + 'static,
{
    // Wait for the prover to say something before spending a slot on it. A
    // slot taken on accept is a slot anyone who can open a TCP socket may
    // reserve -- no TLS, no protocol, not one byte -- and hold for the whole
    // connection deadline. Sixteen such sockets took every MPC slot on a
    // four-core pod, and the real provers behind them queued until their own
    // deadlines expired. The first byte costs the attacker nothing either, but
    // it puts them on a clock this side controls: the slot is now held by a
    // session in progress, which the connection deadline already bounds.
    let socket = await_session_start(socket, state.setup_deadline).await?;
    with_mpc_slot(state, handle_notary_session(socket, state)).await
}

/// `socket` with its first byte read and put back, once the prover sends one.
///
/// Reading is what proves a connection is a client rather than an open socket.
/// The byte read here belongs to the session that follows, so it is replayed
/// into it and the session sees the stream it would have seen.
async fn await_session_start<T>(mut socket: T, deadline: Duration) -> Result<PeekedIo<T>>
where
    T: tokio::io::AsyncRead + Unpin,
{
    let mut first = [0u8; 1];
    let read = tokio::time::timeout(deadline, socket.read(&mut first))
        .await
        .map_err(|_| Error::NotaryServer {
            detail: format!(
                "no prover data within the {}s setup deadline",
                deadline.as_secs()
            ),
        })?
        .map_err(|e| Error::NotaryServer {
            detail: format!("reading the first prover byte: {e}"),
        })?;
    if read == 0 {
        return Err(Error::NotaryServer {
            detail: "prover closed the connection before sending anything".into(),
        });
    }
    Ok(PeekedIo::new(first[..read].to_vec(), socket))
}

/// Run `session` holding one of the MPC-TLS slots, waiting for one first if
/// they are all taken.
///
/// Waiting, not refusing, is the point: MPC-TLS is the heavy path, and a
/// prover refused after paying for its setup would pay again, so the slots
/// only bound how many run at once. The queue is FIFO. The connection
/// deadline covers the whole session -- the wait for a slot and then the
/// session itself -- so no client, however broken, pins this handler task
/// past it, and a queued prover never waits forever either.
async fn with_mpc_slot<F, T>(state: &NotaryState, session: F) -> Result<T>
where
    F: std::future::Future<Output = Result<T>>,
{
    let deadline = state.connection_deadline;
    let shutting_down = || Error::NotaryServer {
        detail: "notary is shutting down; not starting a session".into(),
    };
    tokio::time::timeout(deadline, async {
        let slots = Arc::clone(&state.mpc_sessions);
        let _slot = match slots.clone().try_acquire_owned() {
            Ok(slot) => slot,
            Err(TryAcquireError::Closed) => return Err(shutting_down()),
            Err(TryAcquireError::NoPermits) => {
                info!("MPC-TLS: all session slots busy; prover queued");
                let queued = Instant::now();
                let slot = slots.acquire_owned().await.map_err(|_| shutting_down())?;
                info!(
                    waited_ms = queued.elapsed().as_millis(),
                    "MPC-TLS: prover left the queue and starts its session"
                );
                slot
            }
        };
        session.await
    })
    .await
    .map_err(|_| Error::NotaryServer {
        detail: format!("connection exceeded the {}s deadline", deadline.as_secs()),
    })?
}

async fn handle_notary_session<T>(socket: T, state: &NotaryState) -> Result<()>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Sync + Unpin + 'static,
{
    let result = libid_tlsn::verifier(socket).await?;
    handle_verified_session(result, state).await
}

async fn handle_verified_session<T>(
    result: libid_tlsn::VerifierResult<T>,
    state: &NotaryState,
) -> Result<()>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Sync + Unpin + 'static,
{
    let transcript = &result.partial_transcript;
    let sent = transcript.sent_unsafe();
    let recv = transcript.received_unsafe();
    info!(
        "Verification complete: {} sent, {} recv bytes",
        sent.len(),
        recv.len()
    );

    let ServerName::Dns(ref dns_name) = result.server_name;
    let domain = dns_name.as_str().to_string();
    info!("Domain from SNI: {}", domain);

    // The ceremony record is transport-agnostic and session-agnostic. It is
    // built from what the session revealed, the server the notary
    // authenticated, the commitments over the rest, and the notary's own clock
    // -- an MPC-TLS session produces all four exactly as a ProxyMode one does,
    // and the keeper's JWKS reading exactly as a platform session does. This
    // used to dispatch on the server name and answer `www.googleapis.com` with
    // a Merkle proof of its own shape; that was the notary deciding what a
    // session was for, which is the profile-specific decision REQ-COMMON-33
    // forbids it from making. The record names the host; the contract that
    // reads the record decides whether it wanted that host.
    let ceremony_attestation = sign_ceremony_attestation(
        &state.signer,
        &result.partial_transcript,
        &domain,
        &result.transcript_commitments,
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    )
    .await?;

    let mut io = result.recovered_io;
    write_msg(&mut io, &ceremony_attestation).await?;
    info!("Ceremony attestation sent to prover");

    Ok(())
}

#[cfg(test)]
mod tests {
    /// Each session test drives a real MPC-TLS or ProxyMode setup, which is
    /// CPU-heavy in a debug build. Run at once on a 4-vCPU CI runner they
    /// starve each other past their timeouts; one at a time they fit easily.
    static ONE_SESSION_AT_A_TIME: tokio::sync::Mutex<()> =
        tokio::sync::Mutex::const_new(());

    #[tokio::test]
    async fn attestation_is_one_length_prefixed_frame_then_eof() {
        use libid_transcript::read_msg;
        use tokio::io::AsyncReadExt;

        use super::{
            attestation_frame,
            AttestationWire,
        };

        let frame = attestation_frame(&AttestationWire {
            attested_data: vec![1, 2, 3],
            notary_signature: vec![4; 65],
        })
        .unwrap();
        let mut browser = frame.as_slice();

        let frame: serde_json::Value = read_msg(&mut browser).await.unwrap();
        assert_eq!(frame["attested_data"], serde_json::json!([1, 2, 3]));
        assert_eq!(frame["notary_signature"].as_array().unwrap().len(), 65);
        assert_eq!(browser.read(&mut [0]).await.unwrap(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mpc_protocol_returns_attestation_on_the_recovered_socket() {
        use std::time::Duration;

        use libid_signer::SignerSource;
        use libid_transcript::read_msg;
        use tlsn::{
            config::verifier::VerifierConfig,
            verifier::{
                VerifierCommitStart,
                VerifierOutput,
            },
            webpki::{
                CertificateDer,
                RootCertStore,
            },
            Session,
        };
        use tlsn_sdk_core::{
            HttpRequest,
            ProverConfig,
            Reveal,
            SdkProver,
        };
        use tlsn_server_fixture_certs::{
            CA_CERT_DER,
            SERVER_DOMAIN,
        };
        use tokio::io::AsyncReadExt;
        use tokio_util::compat::{
            FuturesAsyncReadCompatExt,
            TokioAsyncReadCompatExt,
        };

        use super::{
            handle_verified_session,
            AttestationWire,
            NotaryState,
        };

        const TEST_KEY: &str =
            "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

        let _session_slot = ONE_SESSION_AT_A_TIME.lock().await;
        let signer = SignerSource::from_spec(TEST_KEY)
            .unwrap()
            .build_managed(None)
            .await
            .unwrap();
        let expected_pubkey = signer.compressed_public_key().to_vec();
        let state = NotaryState::for_tests(signer);

        let (prover_io, notary_io) = tokio::io::duplex(2 << 23);
        let (target_io, fixture_io) = tokio::io::duplex(1 << 17);
        let fixture_task = tokio::spawn(async move {
            tlsn_server_fixture::bind(fixture_io.compat())
                .await
                .unwrap();
        });

        let notary_task = tokio::spawn(async move {
            let session = Session::new(notary_io.compat());
            let (driver, mut handle) = session.split();
            let driver_task = tokio::spawn(driver);
            let verifier = handle
                .new_verifier(
                    VerifierConfig::builder()
                        .root_store(RootCertStore {
                            roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
                        })
                        .build()
                        .unwrap(),
                )
                .unwrap();
            let verifier = verifier.commit().await.unwrap();
            let VerifierCommitStart::Mpc(verifier) = verifier else {
                panic!("expected MPC mode");
            };
            let verifier = verifier.accept().await.unwrap().run().await.unwrap();
            let tls_transcript = verifier.tls_transcript().clone();
            let (output, verifier) =
                verifier.verify().await.unwrap().accept().await.unwrap();
            verifier.close().await.unwrap();
            handle.close();

            let VerifierOutput {
                server_name,
                transcript,
                transcript_commitments,
                ..
            } = output;
            let recovered_io = driver_task.await.unwrap().unwrap().into_inner();
            handle_verified_session(
                libid_tlsn::VerifierResult {
                    partial_transcript: transcript.unwrap(),
                    server_name: server_name.unwrap(),
                    tls_transcript,
                    transcript_commitments,
                    recovered_io,
                },
                &state,
            )
            .await
            .unwrap();
        });

        let protocol = async {
            let mut prover = SdkProver::new(
                ProverConfig::builder(SERVER_DOMAIN)
                    .root_certs(vec![CA_CERT_DER.to_vec()])
                    .build()
                    .unwrap(),
            )
            .unwrap();
            prover.setup(prover_io.compat()).await.unwrap();
            let response = prover
                .send_request_mpc(
                    target_io.compat(),
                    HttpRequest::get(format!("https://{SERVER_DOMAIN}/bytes?size=16"))
                        .header("Host", SERVER_DOMAIN)
                        .header("Connection", "close"),
                )
                .await
                .unwrap();
            assert_eq!(response.status, 200);

            let transcript = prover.transcript().unwrap();
            prover
                .reveal(
                    Reveal::new()
                        .sent(0..transcript.sent.len())
                        .recv(0..transcript.recv.len())
                        .server_identity(true),
                    None,
                )
                .await
                .unwrap();

            let mut io = prover.finish().await.unwrap().compat();
            let attestation: AttestationWire = read_msg(&mut io).await.unwrap();
            assert_eq!(
                &attestation.attested_data[..32],
                &libid_crypto::keccak256(SERVER_DOMAIN.as_bytes())
            );
            let recovered = libid_crypto::recover_eth_claim(
                &attestation.notary_signature,
                &libid_crypto::keccak256(&attestation.attested_data),
            )
            .unwrap();
            assert_eq!(recovered.to_encoded_point(true).as_bytes(), expected_pubkey);
            assert_eq!(io.read(&mut [0]).await.unwrap(), 0);
        };

        tokio::time::timeout(Duration::from_secs(60), protocol)
            .await
            .expect("local MPC smoke timed out");
        notary_task.await.unwrap();
        fixture_task.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn proxy_protocol_returns_attestation_on_the_reclaimed_websocket() {
        use std::{
            net::SocketAddr,
            sync::Arc,
            time::Duration,
        };

        use futures_util::{
            SinkExt,
            StreamExt,
        };
        use libid_signer::SignerSource;
        use libid_transcript::read_msg;
        use tlsn_sdk_core::{
            HttpRequest,
            ProverConfig,
            ProverMode,
            Reveal,
            SdkProver,
        };
        use tlsn_server_fixture_certs::{
            CA_CERT_DER,
            SERVER_DOMAIN,
        };
        use tokio::{
            io::{
                AsyncReadExt,
                AsyncWriteExt,
            },
            net::TcpListener,
            sync::{
                mpsc,
                Semaphore,
            },
        };
        use tokio_tungstenite::{
            connect_async,
            tungstenite::Message as WsMessage,
        };
        use tokio_util::compat::{
            FuturesAsyncReadCompatExt,
            TokioAsyncReadCompatExt,
        };

        use super::{
            router,
            NotaryState,
            Tier,
        };

        const TEST_KEY: &str =
            "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

        let _session_slot = ONE_SESSION_AT_A_TIME.lock().await;
        let prover_config = ProverConfig::builder(SERVER_DOMAIN)
            .mode(ProverMode::Proxy)
            .root_certs(vec![CA_CERT_DER.to_vec()])
            .build()
            .unwrap();

        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        let target_task = tokio::spawn(async move {
            let (socket, _) = target_listener.accept().await.unwrap();
            tlsn_server_fixture::bind(socket.compat()).await.unwrap();
        });

        let signer = SignerSource::from_spec(TEST_KEY)
            .unwrap()
            .build_managed(None)
            .await
            .unwrap();
        let expected_pubkey = signer.compressed_public_key().to_vec();
        let mut state = NotaryState::for_tests(signer);
        state.internal_proxy_sessions = Arc::new(Semaphore::new(1));
        state.proxy_root_store = Arc::new(prover_config.root_store.clone());
        state.proxy_server_addr = Some(target_addr);
        // The protocol is the same on both tiers; the internal one asks
        // nothing about the client.
        let notary_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let notary_addr = notary_listener.local_addr().unwrap();
        let notary_task = tokio::spawn(async move {
            axum::serve(
                notary_listener,
                router(Tier::Internal, state)
                    .into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });

        let (websocket, _) = connect_async(format!("ws://{notary_addr}/notarize-proxy"))
            .await
            .unwrap();
        let (mut ws_tx, mut ws_rx) = websocket.split();
        let (browser_io, pump_io) = tokio::io::duplex(1 << 17);
        let (frame_tx, mut frame_rx) = mpsc::unbounded_channel();
        let pump_task = tokio::spawn(async move {
            let (mut pipe_reader, mut pipe_writer) = tokio::io::split(pump_io);
            let ws_to_pipe = async {
                while let Some(message) = ws_rx.next().await {
                    match message.unwrap() {
                        WsMessage::Binary(data) => {
                            frame_tx.send(data.to_vec()).unwrap();
                            pipe_writer.write_all(&data).await.unwrap();
                        }
                        WsMessage::Close(_) => {
                            pipe_writer.shutdown().await.unwrap();
                            break;
                        }
                        _ => {}
                    }
                }
            };
            let pipe_to_ws = async {
                let mut buf = vec![0u8; 65536];
                loop {
                    match pipe_reader.read(&mut buf).await.unwrap() {
                        0 => break,
                        n => ws_tx
                            .send(WsMessage::Binary(buf[..n].to_vec().into()))
                            .await
                            .unwrap(),
                    }
                }
            };
            tokio::select! {
                _ = ws_to_pipe => {}
                _ = pipe_to_ws => {}
            }
        });

        let protocol = async {
            let mut prover = SdkProver::new(prover_config.clone()).unwrap();
            prover.setup(browser_io.compat()).await.unwrap();
            let response = prover
                .send_request_proxy(
                    HttpRequest::get(format!("https://{SERVER_DOMAIN}/bytes?size=16"))
                        .header("Host", SERVER_DOMAIN)
                        .header("Connection", "close"),
                )
                .await
                .unwrap();
            assert_eq!(response.status, 200);

            let transcript = prover.transcript().unwrap();
            prover
                .reveal(
                    Reveal::new()
                        .sent(0..transcript.sent.len())
                        .recv(0..transcript.recv.len())
                        .server_identity(true),
                    None,
                )
                .await
                .unwrap();

            let mut io = prover.finish().await.unwrap().compat();
            let attestation: serde_json::Value = read_msg(&mut io).await.unwrap();
            let attested_data: Vec<u8> = attestation["attested_data"]
                .as_array()
                .unwrap()
                .iter()
                .map(|byte| byte.as_u64().unwrap() as u8)
                .collect();
            let signature: Vec<u8> = attestation["notary_signature"]
                .as_array()
                .unwrap()
                .iter()
                .map(|byte| byte.as_u64().unwrap() as u8)
                .collect();

            assert_eq!(
                &attested_data[..32],
                &libid_crypto::keccak256(SERVER_DOMAIN.as_bytes())
            );
            assert_eq!(signature.len(), 65);
            let recovered = libid_crypto::recover_eth_claim(
                &signature,
                &libid_crypto::keccak256(&attested_data),
            )
            .unwrap();
            assert_eq!(recovered.to_encoded_point(true).as_bytes(), expected_pubkey);
            assert_eq!(io.read(&mut [0]).await.unwrap(), 0);
        };

        tokio::time::timeout(Duration::from_secs(30), protocol)
            .await
            .expect("local ProxyMode smoke timed out");
        pump_task.await.unwrap();
        let mut frames = Vec::new();
        while let Ok(frame) = frame_rx.try_recv() {
            frames.push(frame);
        }
        let attestation_frame = frames.last().expect("missing attestation message");
        let declared_len =
            u32::from_be_bytes(attestation_frame[..4].try_into().unwrap()) as usize;
        assert_eq!(declared_len, attestation_frame.len() - 4);
        serde_json::from_slice::<super::AttestationWire>(&attestation_frame[4..])
            .expect("the final WebSocket message is not an attestation");
        target_task.await.unwrap();

        // The target listener is now gone. A second session exercises the
        // same TcpStream::connect error path as a DNS failure and must close
        // the browser transport promptly instead of waiting five minutes.
        let (websocket, _) = connect_async(format!("ws://{notary_addr}/notarize-proxy"))
            .await
            .unwrap();
        let (mut ws_tx, mut ws_rx) = websocket.split();
        let (browser_io, pump_io) = tokio::io::duplex(1 << 17);
        let failed_pump = tokio::spawn(async move {
            let (mut pipe_reader, mut pipe_writer) = tokio::io::split(pump_io);
            let ws_to_pipe = async {
                while let Some(message) = ws_rx.next().await {
                    match message.unwrap() {
                        WsMessage::Binary(data) => {
                            pipe_writer.write_all(&data).await.unwrap();
                        }
                        WsMessage::Close(_) => {
                            pipe_writer.shutdown().await.unwrap();
                            break;
                        }
                        _ => {}
                    }
                }
            };
            let pipe_to_ws = async {
                let mut buf = vec![0u8; 65536];
                loop {
                    match pipe_reader.read(&mut buf).await.unwrap() {
                        0 => break,
                        n => {
                            if ws_tx
                                .send(WsMessage::Binary(buf[..n].to_vec().into()))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                    }
                }
            };
            tokio::select! {
                _ = ws_to_pipe => {}
                _ = pipe_to_ws => {}
            }
        });
        let mut prover = SdkProver::new(prover_config).unwrap();
        let failed_session = async {
            prover
                .setup(browser_io.compat())
                .await
                .map_err(|error| error.to_string())?;
            prover
                .send_request_proxy(
                    HttpRequest::get(format!("https://{SERVER_DOMAIN}/bytes?size=16"))
                        .header("Host", SERVER_DOMAIN)
                        .header("Connection", "close"),
                )
                .await
                .map(|_| ())
                .map_err(|error| error.to_string())
        };
        let result = tokio::time::timeout(Duration::from_secs(3), failed_session)
            .await
            .expect("server connect failure was not propagated to the prover");
        assert!(
            result.unwrap_err().contains("UPSTREAM_CONNECT_FAILED"),
            "server connect failure lost its public diagnostic"
        );
        failed_pump.await.unwrap();
        notary_task.abort();
    }

    /// A client that connects and then goes silent forever must not pin the
    /// handler past the connection deadline — defense in depth over the
    /// fail-fast fixes, covering whatever future bug makes a session pend.
    /// Paused time: the runtime auto-advances the clock to the deadline the
    /// moment everything is blocked, so the test finishes in milliseconds.
    /// A connection that says nothing fails at the setup deadline, and holds
    /// no session slot while it waits.
    ///
    /// Both halves matter. Sixteen sockets that connect and stay silent took
    /// every MPC slot on a four-core pod when the slot was taken on accept,
    /// and held each for the 300s connection deadline; real provers queued
    /// behind them until their own deadlines expired. Opening a socket now
    /// costs the socket and nothing else.
    #[tokio::test(start_paused = true)]
    async fn silent_connection_hits_the_setup_deadline_and_takes_no_slot() {
        use std::time::Duration;

        use libid_signer::SignerSource;

        use super::{
            handle_tcp_prover,
            NotaryState,
        };

        // anvil #0 — public test key.
        let key_hex = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let signer = SignerSource::from_spec(key_hex)
            .unwrap()
            .build_managed(None)
            .await
            .unwrap();
        let state = NotaryState::for_tests(signer);
        let slots = state.mpc_sessions.available_permits();

        // The client half stays open and never writes a byte.
        let (_client, server) = tokio::io::duplex(1 << 16);

        let started = tokio::time::Instant::now();
        let connection = {
            let state = state.clone();
            tokio::spawn(async move { handle_tcp_prover(server, &state).await })
        };

        // A moment in: the connection is alive and still holds nothing.
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(!connection.is_finished(), "the connection failed too early");
        assert_eq!(
            state.mpc_sessions.available_permits(),
            slots,
            "a connection that has sent nothing took a session slot"
        );

        let err = connection
            .await
            .unwrap()
            .expect_err("a silent connection must fail, not pend");
        assert!(
            err.to_string().contains("setup deadline"),
            "expected the setup-deadline error, got: {err}"
        );
        assert!(
            started.elapsed() >= state.setup_deadline,
            "failed before the setup deadline — some step errored spuriously"
        );
        assert!(
            started.elapsed() < state.connection_deadline,
            "an idle socket must not be held for the whole connection deadline"
        );
    }

    /// The limits an operator sets, tripped for real: the ProxyMode data cap
    /// and the MPC-TLS session queue. (The ProxyMode 503 and the flag parsing
    /// are integration tests in `tests/resource_limits.rs`, through the
    /// public surface.)
    mod limits {
        use std::{
            net::SocketAddr,
            sync::{
                atomic::{
                    AtomicBool,
                    Ordering,
                },
                Arc,
            },
            time::Duration,
        };

        use futures_util::{
            SinkExt,
            StreamExt,
        };
        use libid_signer::{
            ManagedSigner,
            SignerSource,
        };
        use libid_transcript::read_msg;
        use tlsn::{
            config::verifier::VerifierConfig,
            verifier::{
                VerifierCommitStart,
                VerifierOutput,
            },
            webpki::{
                CertificateDer,
                RootCertStore,
            },
            Session,
        };
        use tlsn_sdk_core::{
            HttpRequest,
            ProverConfig,
            ProverMode,
            Reveal,
            SdkProver,
        };
        use tlsn_server_fixture_certs::{
            CA_CERT_DER,
            SERVER_DOMAIN,
        };
        use tokio::{
            io::{
                AsyncReadExt,
                AsyncWriteExt,
                DuplexStream,
            },
            net::TcpListener,
            sync::Semaphore,
        };
        use tokio_tungstenite::{
            connect_async,
            tungstenite::{
                client::IntoClientRequest,
                http::HeaderValue,
                protocol::frame::coding::CloseCode,
                Message as WsMessage,
            },
        };
        use tokio_util::compat::{
            FuturesAsyncReadCompatExt,
            TokioAsyncReadCompatExt,
        };

        use super::{
            super::{
                handle_tcp_prover,
                handle_verified_session,
                router,
                store::{
                    Dimension,
                    LeaseId,
                    StoreError,
                },
                with_mpc_slot,
                AttestationWire,
                ClientKey,
                LimitStore,
                NotaryState,
                Result,
                Tier,
                WindowLimits,
            },
            ONE_SESSION_AT_A_TIME,
        };

        /// anvil #0 — public test key.
        const TEST_KEY: &str =
            "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

        async fn test_signer() -> ManagedSigner {
            SignerSource::from_spec(TEST_KEY)
                .unwrap()
                .build_managed(None)
                .await
                .unwrap()
        }

        /// What the browser saw of one ProxyMode WebSocket: every binary
        /// message, and the close frame if the notary sent one.
        struct BrowserSide {
            binary: Vec<Vec<u8>>,
            close: Option<(u16, String)>,
        }

        /// The client a session on `tier` is opened as: named in
        /// `X-Forwarded-For` on the public tier, as the load balancer would;
        /// nothing on the internal tier, which reads no header.
        fn client_on(tier: Tier) -> Option<&'static str> {
            match tier {
                Tier::Public => Some("203.0.113.7"),
                Tier::Internal => None,
            }
        }

        /// The upgrade request for `notary_addr`, naming `client` in
        /// `X-Forwarded-For` when there is one.
        fn upgrade_from(
            notary_addr: SocketAddr,
            client: Option<&str>,
        ) -> tokio_tungstenite::tungstenite::http::Request<()> {
            let mut request = format!("ws://{notary_addr}/notarize-proxy")
                .into_client_request()
                .unwrap();
            if let Some(client) = client {
                request
                    .headers_mut()
                    .insert("x-forwarded-for", HeaderValue::from_str(client).unwrap());
            }
            request
        }

        /// Open a ProxyMode WebSocket as `client` and pump it to and from a
        /// duplex the prover drives, the way tlsn_wasm's transport does in
        /// the browser.
        async fn browser(
            notary_addr: SocketAddr,
            client: Option<&str>,
        ) -> (DuplexStream, tokio::task::JoinHandle<BrowserSide>) {
            let (websocket, _) = connect_async(upgrade_from(notary_addr, client))
                .await
                .unwrap();
            let (mut ws_tx, mut ws_rx) = websocket.split();
            let (browser_io, pump_io) = tokio::io::duplex(1 << 17);
            let pump = tokio::spawn(async move {
                let (mut pipe_reader, mut pipe_writer) = tokio::io::split(pump_io);
                let mut seen = BrowserSide {
                    binary: Vec::new(),
                    close: None,
                };
                let ws_to_pipe = async {
                    while let Some(message) = ws_rx.next().await {
                        match message.unwrap() {
                            WsMessage::Binary(data) => {
                                seen.binary.push(data.to_vec());
                                if pipe_writer.write_all(&data).await.is_err() {
                                    break;
                                }
                            }
                            WsMessage::Close(frame) => {
                                seen.close = frame.map(|frame| {
                                    (u16::from(frame.code), frame.reason.to_string())
                                });
                                let _ = pipe_writer.shutdown().await;
                                break;
                            }
                            _ => {}
                        }
                    }
                    seen
                };
                let pipe_to_ws = async {
                    let mut buf = vec![0u8; 65536];
                    loop {
                        match pipe_reader.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if ws_tx
                                    .send(WsMessage::Binary(buf[..n].to_vec().into()))
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                        }
                        // Keep reading the socket until the notary closes it.
                    }
                    std::future::pending::<BrowserSide>().await
                };
                tokio::select! {
                    seen = ws_to_pipe => seen,
                    seen = pipe_to_ws => seen,
                }
            });
            (browser_io, pump)
        }

        /// Serve `router(tier, state)` on an ephemeral port; the task is
        /// aborted by the test that spawned it.
        async fn serve(
            tier: Tier,
            state: NotaryState,
        ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let task = tokio::spawn(async move {
                axum::serve(
                    listener,
                    router(tier, state)
                        .into_make_service_with_connect_info::<SocketAddr>(),
                )
                .await
                .unwrap();
            });
            (addr, task)
        }

        /// A store whose every call parks until the test lets it go, so the
        /// notary can be looked at while admission is in progress. Once let
        /// go, everything fits.
        struct Gate {
            entered: tokio::sync::Notify,
            go: Semaphore,
        }

        impl Gate {
            fn new() -> Arc<Self> {
                Arc::new(Self {
                    entered: tokio::sync::Notify::new(),
                    go: Semaphore::new(0),
                })
            }

            async fn park(&self) {
                self.entered.notify_one();
                self.go.acquire().await.expect("never closed").forget();
            }
        }

        struct ParkedStore(Arc<Gate>);

        #[async_trait::async_trait]
        impl LimitStore for ParkedStore {
            async fn try_lease(
                &self,
                _: &ClientKey,
                _: usize,
                _: Duration,
            ) -> std::result::Result<Option<LeaseId>, StoreError> {
                self.0.park().await;
                Ok(Some(LeaseId::new()))
            }

            async fn release(&self, _: &LeaseId) -> std::result::Result<(), StoreError> {
                self.0.park().await;
                Ok(())
            }

            async fn count(
                &self,
                _: &ClientKey,
                _: Dimension,
                _: u64,
                _: &WindowLimits,
            ) -> std::result::Result<bool, StoreError> {
                self.0.park().await;
                Ok(true)
            }

            async fn would_fit(
                &self,
                _: &ClientKey,
                _: Dimension,
                _: u64,
                _: &WindowLimits,
            ) -> std::result::Result<bool, StoreError> {
                self.0.park().await;
                Ok(true)
            }

            async fn charge(
                &self,
                _: &ClientKey,
                _: Dimension,
                _: u64,
                _: &WindowLimits,
            ) -> std::result::Result<(), StoreError> {
                self.0.park().await;
                Ok(())
            }

            async fn sweep(&self) -> std::result::Result<u64, StoreError> {
                self.0.park().await;
                Ok(0)
            }

            fn describe(&self) -> String {
                "parked".into()
            }
        }

        /// An upgrade is in flight from before its admission -- two store
        /// round trips -- so a drain that starts meanwhile waits for it
        /// rather than stopping the listeners under it; and it is out of
        /// flight once its handler returns.
        #[tokio::test(flavor = "multi_thread")]
        async fn an_upgrade_counts_as_in_flight_while_admission_runs() {
            let gate = Gate::new();
            let mut state = NotaryState::for_tests(test_signer().await);
            state.limits = Arc::new(ParkedStore(Arc::clone(&gate)));
            let in_flight = Arc::clone(&state.in_flight);
            let (notary_addr, notary_task) = serve(Tier::Public, state).await;

            let upgrade = tokio::spawn(async move {
                connect_async(upgrade_from(notary_addr, client_on(Tier::Public)))
                    .await
                    .expect("the upgrade is admitted once the store answers")
            });
            tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
                .await
                .expect("admission never asked the store");
            assert_eq!(
                in_flight.count(),
                1,
                "an upgrade inside admission is in flight"
            );

            // Let admission through; the socket is dropped unstarted, and
            // the handler's return takes the connection out of flight.
            gate.go.add_permits(2);
            let (socket, _) = upgrade.await.unwrap();
            drop(socket);
            let idle = async {
                while in_flight.count() != 0 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            };
            tokio::time::timeout(Duration::from_secs(5), idle)
                .await
                .expect("the connection never left flight");

            notary_task.abort();
        }

        /// A relay that crosses the cap is aborted mid-stream: the browser's
        /// request fails, the WebSocket closes with code 1008 and a reason
        /// naming the cap, and no attestation frame is ever sent. The cap is
        /// per session on both tiers; the internal one needs no client.
        #[tokio::test(flavor = "multi_thread")]
        async fn proxy_session_over_the_data_cap_is_aborted_without_attestation() {
            let _session_slot = ONE_SESSION_AT_A_TIME.lock().await;
            let prover_config = ProverConfig::builder(SERVER_DOMAIN)
                .mode(ProverMode::Proxy)
                .root_certs(vec![CA_CERT_DER.to_vec()])
                .build()
                .unwrap();

            let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target_addr = target_listener.local_addr().unwrap();
            let target_task = tokio::spawn(async move {
                let (socket, _) = target_listener.accept().await.unwrap();
                // The fixture errors once the relay drops it; that is the
                // abort arriving, not a test failure.
                let _ = tlsn_server_fixture::bind(socket.compat()).await;
            });

            // The handshake alone is a few KB; a 64 KiB body is sure to cross
            // an 8 KiB cap, and sure to fit the success path's default.
            const CAP: usize = 8 * 1024;
            let mut state = NotaryState::for_tests(test_signer().await);
            state.proxy_max_bytes = CAP;
            state.proxy_root_store = Arc::new(prover_config.root_store.clone());
            state.proxy_server_addr = Some(target_addr);
            let (notary_addr, notary_task) = serve(Tier::Internal, state).await;

            let (browser_io, mut pump) = browser(notary_addr, None).await;
            let mut prover = SdkProver::new(prover_config).unwrap();
            let session = async {
                prover.setup(browser_io.compat()).await.unwrap();
                prover
                    .send_request_proxy(
                        HttpRequest::get(format!(
                            "https://{SERVER_DOMAIN}/bytes?size=65536"
                        ))
                        .header("Host", SERVER_DOMAIN)
                        .header("Connection", "close"),
                    )
                    .await
            };
            tokio::pin!(session);

            // The WebSocket is where the notary's verdict is observable. The
            // request itself may fail, or may pend: once the notary closes
            // the transport, this SDK prover's session driver dies and its
            // proxy stream never wakes, which is the client's business.
            // Either way it must not succeed.
            let seen = tokio::time::timeout(Duration::from_secs(30), async {
                tokio::select! {
                    outcome = &mut session => {
                        assert!(outcome.is_err(), "a request over the cap must not succeed");
                        pump.await.unwrap()
                    }
                    seen = &mut pump => seen.unwrap(),
                }
            })
            .await
            .expect("the notary neither failed the request nor closed the WebSocket");
            let (code, reason) = seen.close.expect("closed without a close frame");
            assert_eq!(code, u16::from(CloseCode::Policy), "reason: {reason}");
            assert!(
                reason.starts_with("PROXY_DATA_CAP_EXCEEDED: relayed "),
                "reason: {reason}"
            );
            assert!(
                reason.ends_with(&format!(", cap {CAP}")),
                "reason: {reason}"
            );
            for frame in &seen.binary {
                let attested = frame.len() >= 4
                    && u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize
                        == frame.len() - 4
                    && serde_json::from_slice::<AttestationWire>(&frame[4..]).is_ok();
                assert!(!attested, "an attestation was sent for a capped session");
            }

            notary_task.abort();
            target_task.await.unwrap();
        }

        /// A public WebSocket upgrade as an HTTP client sends it, so a
        /// refusal's status and body can be read whole: tungstenite keeps
        /// only what arrived in the same read as the headers.
        async fn upgrade_request(notary_addr: SocketAddr) -> reqwest::Response {
            reqwest::Client::new()
                .get(format!("http://{notary_addr}/notarize-proxy"))
                .header("x-forwarded-for", client_on(Tier::Public).unwrap())
                .header("connection", "upgrade")
                .header("upgrade", "websocket")
                .header("sec-websocket-version", "13")
                .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
                .send()
                .await
                .expect("the notary answers the upgrade")
        }

        /// One complete ProxyMode session against the fixture server,
        /// through `router(tier, state)`: the browser's request, its reveal,
        /// and the attestation frame read back. Returns the notary's
        /// address, what the browser saw, and the serving task, for what
        /// the test wants to check next. The caller holds
        /// `ONE_SESSION_AT_A_TIME`.
        async fn complete_session(
            tier: Tier,
            mut state: NotaryState,
        ) -> (SocketAddr, BrowserSide, tokio::task::JoinHandle<()>) {
            let prover_config = ProverConfig::builder(SERVER_DOMAIN)
                .mode(ProverMode::Proxy)
                .root_certs(vec![CA_CERT_DER.to_vec()])
                .build()
                .unwrap();

            let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target_addr = target_listener.local_addr().unwrap();
            let target_task = tokio::spawn(async move {
                let (socket, _) = target_listener.accept().await.unwrap();
                tlsn_server_fixture::bind(socket.compat()).await.unwrap();
            });

            state.proxy_root_store = Arc::new(prover_config.root_store.clone());
            state.proxy_server_addr = Some(target_addr);
            let (notary_addr, notary_task) = serve(tier, state).await;

            let (browser_io, pump) = browser(notary_addr, client_on(tier)).await;
            let mut prover = SdkProver::new(prover_config).unwrap();
            let session = async {
                prover.setup(browser_io.compat()).await.unwrap();
                let response = prover
                    .send_request_proxy(
                        HttpRequest::get(format!(
                            "https://{SERVER_DOMAIN}/bytes?size=16"
                        ))
                        .header("Host", SERVER_DOMAIN)
                        .header("Connection", "close"),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status, 200);
                let transcript = prover.transcript().unwrap();
                prover
                    .reveal(
                        Reveal::new()
                            .sent(0..transcript.sent.len())
                            .recv(0..transcript.recv.len())
                            .server_identity(true),
                        None,
                    )
                    .await
                    .unwrap();
                let mut io = prover.finish().await.unwrap().compat();
                let _: AttestationWire = read_msg(&mut io).await.unwrap();
            };
            tokio::time::timeout(Duration::from_secs(30), session)
                .await
                .expect("local ProxyMode session timed out");
            let seen = pump.await.unwrap();
            target_task.await.unwrap();
            (notary_addr, seen, notary_task)
        }

        /// `--per-ip-bytes` is charged with what a session really relayed:
        /// one full session -- a TLS handshake alone is more than a
        /// kilobyte -- fills a 1 KB window, and the client's next upgrade is
        /// refused with 429 naming the bytes window. The upgrades window is
        /// off, so nothing else can be what refuses.
        #[tokio::test(flavor = "multi_thread")]
        async fn the_bytes_window_is_charged_when_a_session_ends() {
            let _session_slot = ONE_SESSION_AT_A_TIME.lock().await;
            let mut state = NotaryState::for_tests(test_signer().await);
            state.per_ip_bytes = WindowLimits::parse("1KB/1h").unwrap();
            state.per_ip_upgrades = WindowLimits::default();
            let (notary_addr, seen, notary_task) =
                complete_session(Tier::Public, state).await;
            assert!(
                seen.close.is_none(),
                "the session did not end cleanly: {:?}",
                seen.close
            );

            // The charge lands as the handler returns, a moment after the
            // browser saw its close frame.
            let refused = async {
                loop {
                    let response = upgrade_request(notary_addr).await;
                    if response.status() != 101 {
                        return response;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            };
            let refused = tokio::time::timeout(Duration::from_secs(5), refused)
                .await
                .expect("the bytes window never refused an upgrade");
            assert_eq!(refused.status(), 429);
            assert!(refused.headers().contains_key("retry-after"));
            let body = refused.text().await.unwrap();
            assert!(body.contains("bytes"), "{body}");

            notary_task.abort();
        }

        /// A store that answers nothing but errors.
        struct DownStore;

        #[async_trait::async_trait]
        impl LimitStore for DownStore {
            async fn try_lease(
                &self,
                _: &ClientKey,
                _: usize,
                _: Duration,
            ) -> std::result::Result<Option<LeaseId>, StoreError> {
                Err(StoreError("down".into()))
            }

            async fn release(&self, _: &LeaseId) -> std::result::Result<(), StoreError> {
                Err(StoreError("down".into()))
            }

            async fn count(
                &self,
                _: &ClientKey,
                _: Dimension,
                _: u64,
                _: &WindowLimits,
            ) -> std::result::Result<bool, StoreError> {
                Err(StoreError("down".into()))
            }

            async fn would_fit(
                &self,
                _: &ClientKey,
                _: Dimension,
                _: u64,
                _: &WindowLimits,
            ) -> std::result::Result<bool, StoreError> {
                Err(StoreError("down".into()))
            }

            async fn charge(
                &self,
                _: &ClientKey,
                _: Dimension,
                _: u64,
                _: &WindowLimits,
            ) -> std::result::Result<(), StoreError> {
                Err(StoreError("down".into()))
            }

            async fn sweep(&self) -> std::result::Result<u64, StoreError> {
                Err(StoreError("down".into()))
            }

            fn describe(&self) -> String {
                "down".into()
            }
        }

        /// A store the internal port must never reach: every call panics,
        /// and a panic in the handler ends the session.
        struct PanickingStore;

        #[async_trait::async_trait]
        impl LimitStore for PanickingStore {
            async fn try_lease(
                &self,
                _: &ClientKey,
                _: usize,
                _: Duration,
            ) -> std::result::Result<Option<LeaseId>, StoreError> {
                panic!("the internal port asked the store for a lease")
            }

            async fn release(&self, _: &LeaseId) -> std::result::Result<(), StoreError> {
                panic!("the internal port released a lease")
            }

            async fn count(
                &self,
                _: &ClientKey,
                _: Dimension,
                _: u64,
                _: &WindowLimits,
            ) -> std::result::Result<bool, StoreError> {
                panic!("the internal port counted in the store")
            }

            async fn would_fit(
                &self,
                _: &ClientKey,
                _: Dimension,
                _: u64,
                _: &WindowLimits,
            ) -> std::result::Result<bool, StoreError> {
                panic!("the internal port asked the store for room")
            }

            async fn charge(
                &self,
                _: &ClientKey,
                _: Dimension,
                _: u64,
                _: &WindowLimits,
            ) -> std::result::Result<(), StoreError> {
                panic!("the internal port charged the store")
            }

            async fn sweep(&self) -> std::result::Result<u64, StoreError> {
                panic!("the internal port swept the store")
            }

            fn describe(&self) -> String {
                "panicking".into()
            }
        }

        /// A store that cannot answer is a refusal, never a pass: with a
        /// window in force the upgrade itself is refused with 503, naming
        /// the store -- whichever of the two windows is the one in force.
        #[tokio::test(flavor = "multi_thread")]
        async fn a_store_that_cannot_answer_refuses_the_upgrade() {
            for (upgrades, bytes) in [("1/1h", ""), ("", "1KB/1h")] {
                let mut state = NotaryState::for_tests(test_signer().await);
                state.limits = Arc::new(DownStore);
                state.per_ip_upgrades = WindowLimits::parse(upgrades).unwrap();
                state.per_ip_bytes = WindowLimits::parse(bytes).unwrap();
                let (notary_addr, notary_task) = serve(Tier::Public, state).await;

                let refused = upgrade_request(notary_addr).await;
                assert_eq!(refused.status(), 503, "windows {upgrades:?} {bytes:?}");
                assert_eq!(refused.text().await.unwrap(), "limits store unavailable");

                notary_task.abort();
            }
        }

        /// With no window in force the store is not asked at the upgrade,
        /// which goes through; the session's lease is the next thing asked
        /// of it, and that refusal closes the socket with 1013 on the first
        /// frame, naming the store.
        #[tokio::test(flavor = "multi_thread")]
        async fn a_store_that_cannot_answer_refuses_the_session_with_1013() {
            let mut state = NotaryState::for_tests(test_signer().await);
            state.limits = Arc::new(DownStore);
            state.per_ip_upgrades = WindowLimits::default();
            state.per_ip_bytes = WindowLimits::default();
            let (notary_addr, notary_task) = serve(Tier::Public, state).await;

            let (mut socket, _) =
                connect_async(upgrade_from(notary_addr, client_on(Tier::Public)))
                    .await
                    .expect("with no window in force the upgrade does not ask the store");
            socket
                .send(WsMessage::Binary(b"\x16\x03\x01".to_vec().into()))
                .await
                .unwrap();
            let close = async {
                loop {
                    match socket.next().await {
                        Some(Ok(WsMessage::Close(frame))) => return frame,
                        Some(Ok(_)) => {}
                        other => panic!("expected a close frame, got {other:?}"),
                    }
                }
            };
            let frame = tokio::time::timeout(Duration::from_secs(5), close)
                .await
                .expect("the notary never closed the session")
                .expect("closed without a close frame");
            assert_eq!(u16::from(frame.code), 1013, "reason: {}", frame.reason);
            assert_eq!(frame.reason, "limits store unavailable");

            notary_task.abort();
        }

        /// The internal port never touches the store: a full session
        /// completes, attestation and all, against a store that panics on
        /// every call.
        #[tokio::test(flavor = "multi_thread")]
        async fn the_internal_port_never_touches_the_store() {
            let _session_slot = ONE_SESSION_AT_A_TIME.lock().await;
            let mut state = NotaryState::for_tests(test_signer().await);
            state.limits = Arc::new(PanickingStore);
            let (_, seen, notary_task) = complete_session(Tier::Internal, state).await;
            assert!(
                seen.close.is_none(),
                "the session did not end cleanly: {:?}",
                seen.close
            );
            notary_task.abort();
        }

        /// The notary's half of an MPC-TLS session against the test fixture:
        /// what `libid_tlsn::verifier` does, with the fixture's CA trusted,
        /// ending in the real attestation path.
        async fn fixture_mpc_session(
            notary_io: DuplexStream,
            state: &NotaryState,
        ) -> Result<()> {
            let session = Session::new(notary_io.compat());
            let (driver, mut handle) = session.split();
            let driver_task = tokio::spawn(driver);
            let verifier = handle
                .new_verifier(
                    VerifierConfig::builder()
                        .root_store(RootCertStore {
                            roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
                        })
                        .build()
                        .unwrap(),
                )
                .unwrap();
            let VerifierCommitStart::Mpc(verifier) = verifier.commit().await.unwrap()
            else {
                panic!("expected MPC mode");
            };
            let verifier = verifier.accept().await.unwrap().run().await.unwrap();
            let tls_transcript = verifier.tls_transcript().clone();
            let (output, verifier) =
                verifier.verify().await.unwrap().accept().await.unwrap();
            verifier.close().await.unwrap();
            handle.close();
            let VerifierOutput {
                server_name,
                transcript,
                transcript_commitments,
                ..
            } = output;
            let recovered_io = driver_task.await.unwrap().unwrap().into_inner();
            handle_verified_session(
                libid_tlsn::VerifierResult {
                    partial_transcript: transcript.unwrap(),
                    server_name: server_name.unwrap(),
                    tls_transcript,
                    transcript_commitments,
                    recovered_io,
                },
                state,
            )
            .await
        }

        /// With one MPC-TLS slot taken, a second prover is not refused: it
        /// waits, and once the slot frees it runs a whole session and gets
        /// its attestation. The first "prover" is a silent TCP client on the
        /// real handler; the second is a real prover behind the same queue.
        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn mpc_prover_queues_behind_a_full_slot_and_then_succeeds() {
            let _session_slot = ONE_SESSION_AT_A_TIME.lock().await;
            let mut state = NotaryState::for_tests(test_signer().await);
            state.mpc_sessions = Arc::new(Semaphore::new(1));
            let expected_pubkey = state.signer.compressed_public_key().to_vec();

            // A holds the only slot: it sent the byte that starts a session,
            // then said nothing more. Connecting alone would take no slot.
            let (mut a_client, a_server) = tokio::io::duplex(1 << 16);
            let a_state = state.clone();
            let a_task =
                tokio::spawn(async move { handle_tcp_prover(a_server, &a_state).await });
            a_client.write_all(b"\x00").await.unwrap();
            let slot_taken = async {
                while state.mpc_sessions.available_permits() != 0 {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            };
            tokio::time::timeout(Duration::from_secs(5), slot_taken)
                .await
                .expect("the stalled client never took the slot");

            // B: a real prover, whose notary side goes through the queue.
            let (prover_io, notary_io) = tokio::io::duplex(2 << 23);
            let (target_io, fixture_io) = tokio::io::duplex(1 << 17);
            let fixture_task = tokio::spawn(async move {
                tlsn_server_fixture::bind(fixture_io.compat())
                    .await
                    .unwrap();
            });
            let b_started = Arc::new(AtomicBool::new(false));
            let b_state = state.clone();
            let b_task = tokio::spawn({
                let b_started = Arc::clone(&b_started);
                async move {
                    with_mpc_slot(&b_state, async {
                        b_started.store(true, Ordering::SeqCst);
                        fixture_mpc_session(notary_io, &b_state).await
                    })
                    .await
                }
            });

            let mut prover = SdkProver::new(
                ProverConfig::builder(SERVER_DOMAIN)
                    .root_certs(vec![CA_CERT_DER.to_vec()])
                    .build()
                    .unwrap(),
            )
            .unwrap();
            let mut setup = Box::pin(prover.setup(prover_io.compat()));

            // Queued: B's setup neither completes nor fails while A holds the
            // slot, and B's session has not started.
            assert!(
                tokio::time::timeout(Duration::from_secs(1), &mut setup)
                    .await
                    .is_err(),
                "B ran, or was refused, while A held the only slot"
            );
            assert!(!b_started.load(Ordering::SeqCst), "B started before A left");
            assert!(!b_task.is_finished(), "B was refused instead of queued");

            // A goes away: its verifier fails fast on the dead socket and the
            // slot is released. B, still on the same connection, proceeds.
            drop(a_client);
            let a_outcome = tokio::time::timeout(Duration::from_secs(5), a_task)
                .await
                .expect("the stalled client did not release the slot")
                .unwrap();
            assert!(a_outcome.is_err(), "a stalled client cannot have succeeded");

            tokio::time::timeout(Duration::from_secs(60), &mut setup)
                .await
                .expect("the queued prover never set up after the slot freed")
                .unwrap();
            drop(setup);
            assert!(b_started.load(Ordering::SeqCst));

            let protocol = async {
                let response = prover
                    .send_request_mpc(
                        target_io.compat(),
                        HttpRequest::get(format!(
                            "https://{SERVER_DOMAIN}/bytes?size=16"
                        ))
                        .header("Host", SERVER_DOMAIN)
                        .header("Connection", "close"),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status, 200);
                let transcript = prover.transcript().unwrap();
                prover
                    .reveal(
                        Reveal::new()
                            .sent(0..transcript.sent.len())
                            .recv(0..transcript.recv.len())
                            .server_identity(true),
                        None,
                    )
                    .await
                    .unwrap();
                let mut io = prover.finish().await.unwrap().compat();
                let attestation: AttestationWire = read_msg(&mut io).await.unwrap();
                let recovered = libid_crypto::recover_eth_claim(
                    &attestation.notary_signature,
                    &libid_crypto::keccak256(&attestation.attested_data),
                )
                .unwrap();
                assert_eq!(recovered.to_encoded_point(true).as_bytes(), expected_pubkey);
            };
            tokio::time::timeout(Duration::from_secs(60), protocol)
                .await
                .expect("the queued prover never finished after the slot freed");
            b_task.await.unwrap().expect("the queued session failed");
            fixture_task.await.unwrap();
        }

        /// A queued prover is still under the connection deadline: it fails
        /// with the deadline error, not later. Paused time, as in
        /// `silent_connection_hits_the_deadline`.
        #[tokio::test(start_paused = true)]
        async fn queued_prover_hits_the_deadline_while_waiting() {
            let mut state = NotaryState::for_tests(test_signer().await);
            state.mpc_sessions = Arc::new(Semaphore::new(1));
            let _running = Arc::clone(&state.mpc_sessions)
                .acquire_owned()
                .await
                .unwrap();

            let started = tokio::time::Instant::now();
            let err = with_mpc_slot(&state, async { Ok(()) })
                .await
                .expect_err("a queued prover must not wait past the deadline");
            assert!(err.to_string().contains("deadline"), "got: {err}");
            assert!(started.elapsed() >= state.connection_deadline);
        }

        /// Shutdown closes the queue: a prover waiting for a slot fails at
        /// once with a message that says so, instead of sitting there until
        /// the runtime is torn down under it.
        #[tokio::test]
        async fn queued_prover_fails_fast_when_the_queue_closes() {
            let mut state = NotaryState::for_tests(test_signer().await);
            state.mpc_sessions = Arc::new(Semaphore::new(1));
            let _running = Arc::clone(&state.mpc_sessions)
                .acquire_owned()
                .await
                .unwrap();

            let queued_state = state.clone();
            let queued = tokio::spawn(async move {
                with_mpc_slot(&queued_state, async { Ok(()) }).await
            });
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert!(!queued.is_finished(), "the prover was not queued");

            state.mpc_sessions.close();
            let err = tokio::time::timeout(Duration::from_secs(1), queued)
                .await
                .expect("the queued prover did not drain on shutdown")
                .unwrap()
                .expect_err("a drained prover has no session to succeed");
            assert!(err.to_string().contains("shutting down"), "got: {err}");
        }
    }
}
