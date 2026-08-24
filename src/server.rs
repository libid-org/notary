//! Notary server: handles plain-TCP (backend MPC-TLS) and WebSocket connections.
//!
//! # Endpoints
//!
//! - **TCP** (port `NOTARY_PORT`): MPC-TLS verifier for Rust backend provers.
//!   Dispatches on the TLS-cert-verified server name after verification:
//!   `www.googleapis.com` sessions are answered with a signed
//!   [`crate::jwks::JwksNotaryResponse`] (JWKS rotation duty); every other
//!   session with the platform [`NotaryResponse`].
//! - **GET  /info**: returns `{version, publicKey}` — compatible with tlsn-js.
//! - **POST /session**: creates a session, returns `{sessionId}` — tlsn-js API.
//! - **GET  /notarize?sessionId=…** (WS upgrade): MPC-TLS session for tlsn-js
//!   browser client.
//! - **GET  /notarize-proxy?sessionId=…** (WS upgrade): ProxyMode session for
//!   WASM browser client (the primary browser path).
//! - **GET  /attestation/:session_id**: signs the attested data of a completed
//!   session, MPC-TLS or ProxyMode alike -- the record is built from what the
//!   session revealed, and that does not depend on how the bytes reached the
//!   notary. Takes no parameters: there is nothing in the record a caller
//!   could choose.
//! - **GET  /proxy** (WS upgrade): raw TCP proxy used by the tlsn-js MPC path.
//!
//! # Trust model
//!
//! The notary is one half of a 2-of-2 trust scheme. It signs the
//! transcript root after participating as the MPC-TLS verifier or ProxyMode
//! verifier. Its signature alone does NOT register an identity on-chain — the
//! ZK circuit or smart contract verifies the signature against the notary pubkey.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::SystemTime,
};

use axum::{
    extract::{
        ws::{
            Message,
            WebSocket,
            WebSocketUpgrade,
        },
        Path,
        Query,
        State,
    },
    http::StatusCode,
    response::{
        IntoResponse,
        Json,
    },
    routing::{
        get,
        post,
    },
    Router,
};
use futures_util::{
    SinkExt,
    StreamExt,
};
use libid_attestations::compute_notary_digest;
use libid_crypto::{
    double_hash_leaf,
    keccak256,
};
use libid_signer::{
    ManagedSigner,
    SignerSource,
};
use libid_transcript::{
    find_request_line_range,
    read_msg,
    write_msg,
    EvmProof,
    NotaryResponse,
};
use rand::RngCore;
use serde::{
    Deserialize,
    Serialize,
};
use tlsn::{
    attestation::{
        request::Request,
        signing::{
            KeyAlgId,
            Signature as TlsnSignature,
            SignatureAlgId,
            SignatureError as TlsnSignatureError,
            Signer as TlsnSigner,
            VerifyingKey as TlsnVerifyingKey,
        },
        Attestation,
        AttestationConfig,
        CryptoProvider,
    },
    config::verifier::VerifierConfig,
    connection::{
        ConnectionInfo,
        ServerName,
        TranscriptLength,
    },
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
    sync::RwLock,
};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tower_http::cors::{
    Any,
    CorsLayer,
};
use tracing::{
    error,
    info,
    warn,
};

use crate::{
    config::NotaryServerConfig,
    error::{
        Error,
        Result,
    },
    jwks,
};

/// Handle for controlling the running notary server.
pub struct NotaryServerHandle {
    local_addr: SocketAddr,
    ws_local_addr: Option<SocketAddr>,
    shutdown: tokio::sync::watch::Sender<bool>,
}

impl NotaryServerHandle {
    /// Returns the address the TCP wire listener is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Returns the address the HTTP/WebSocket server is bound to, if enabled.
    pub fn ws_local_addr(&self) -> Option<SocketAddr> {
        self.ws_local_addr
    }

    /// Signals every background task (TCP accept loop, WS server, session
    /// sweep) to stop, so none leaks after shutdown.
    pub fn shutdown(self) {
        let _ = self.shutdown.send(true);
    }
}

// ─── Session state ───────────────────────────────────────────────────────────

/// What a completed session hands the attestation endpoint.
///
/// The session's own tlsn output, kept whole. The previous shape flattened it
/// into one bearer hash, one range and two revealed blobs, which cannot express
/// the attested data of ceremony-common section 9.1: the received direction
/// carried no offsets at all, only one commitment was admissible, and the
/// transcript lengths were nowhere. Keeping the tlsn types and mapping them at
/// signing time is what makes those expressible.
#[derive(Clone)]
pub struct SessionAttestation {
    /// The revealed transcript, with its authenticated ranges and lengths.
    pub partial: PartialTranscript,
    /// The DNS name the notary authenticated in the TLS handshake.
    pub authority: String,
    /// Every commitment the session produced.
    pub commitments: Vec<TranscriptCommitment>,
    /// The notary's OWN clock when the session completed (REQ-COMMON-57).
    pub created_at: u64,
}

struct SessionEntry {
    /// What the session revealed, captured at completion, from which the
    /// notary signs the section 9.1 record on demand at
    /// `GET /attestation/{session_id}`. Both transports fill it: the record
    /// describes what was observed, not how it arrived.
    raw_attest: Option<SessionAttestation>,
    /// Notified when `raw_attest` is populated so the attestation handler
    /// wakes up immediately instead of polling.
    ready: Arc<tokio::sync::Notify>,
    /// When the entry was created. Monotonic (`tokio::time::Instant`) so a
    /// wall-clock step can't disable or mis-fire the background sweep. Used to
    /// evict abandoned sessions so the map can't grow without bound (DoS).
    created_at: tokio::time::Instant,
}

impl Default for SessionEntry {
    fn default() -> Self {
        Self {
            raw_attest: None,
            ready: Arc::new(tokio::sync::Notify::new()),
            created_at: tokio::time::Instant::now(),
        }
    }
}

type SessionMap = Arc<RwLock<HashMap<String, SessionEntry>>>;

/// How long any session entry lives before the background sweep evicts it.
/// Generous so the whole creation → MPC → client-side proving → fetch pipeline
/// fits comfortably inside it — yet finite, so produced-but-never-fetched
/// entries can't accumulate without bound.
const SESSION_TTL: std::time::Duration = std::time::Duration::from_secs(1800);

/// How often the background sweep runs.
const SESSION_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Overall deadline for one prover connection (TCP or WebSocket), covering
/// the whole MPC-TLS/ProxyMode session plus the attestation exchange. A real
/// session completes in well under a minute even on a slow link; 5 minutes is
/// generous headroom while staying far inside [`SESSION_TTL`] (30 min), which
/// bounds the session *entry*, not the connection. This is defense in depth:
/// whatever future bug makes a session pend, no connection can pin a handler
/// task (and its MPC buffers) forever.
const CONNECTION_DEADLINE: std::time::Duration = std::time::Duration::from_secs(300);

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

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
        }
    }
}

/// Error for a session driver that finished while session setup was still in
/// flight. The driver only completes once the underlying socket is closed or
/// dead, so a protocol request submitted to it may never resolve — without
/// this check a connect-then-close client (the kubelet `tcpSocket` probe
/// pattern) could wedge the handler forever.
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

/// Evict session entries older than [`SESSION_TTL`]. Returns the count evicted.
/// Age is measured on a monotonic clock (`Instant`), so a wall-clock step never
/// disables the sweep (unbounded-growth DoS) or early-evicts a live session.
/// EVERY entry — in-flight, abandoned, and produced-but-unfetched — is bounded
/// by the TTL; a client that hasn't fetched its attestation within the (very
/// generous) TTL has effectively abandoned it and re-runs the flow.
///
/// An evicted entry wakes any handler blocked on its `ready` notify so the
/// handler re-checks, finds the entry gone, and returns 404 promptly instead of
/// sleeping out its full timeout and reporting a misleading "not ready".
async fn sweep_stale_sessions(sessions: &SessionMap) -> usize {
    let mut map = sessions.write().await;
    let before = map.len();
    map.retain(|_, e| {
        let keep = e.created_at.elapsed() < SESSION_TTL;
        if !keep {
            e.ready.notify_waiters();
        }
        keep
    });
    before.saturating_sub(map.len())
}

#[derive(Clone)]
struct NotaryState {
    /// Notary signing identity (local hex key or AWS KMS). The one path KMS
    /// cannot serve directly is tlsn attestation — see [`HeaderCaptureSigner`].
    signer: Arc<ManagedSigner>,
    sessions: SessionMap,
    /// Max concurrent live sessions (`NOTARY_MAX_SESSIONS`).
    max_sessions: usize,
    public_key_hex: String,
    /// EVM chain id the contracts that consume these attestations run on.
    /// Baked into the signed digest as part of the EIP-712-style domain
    /// separator so a single notary signing key can serve multiple
    /// deployments without cross-chain replay.
    chain_id: u64,
    /// ZK verifier (e.g. `XZkVerifier`) address for the hash-commit digests.
    /// `verifyingContract` for the MPC-TLS digest (`Registry` in wallet
    /// deployments, `GitHubIdentityVerifier` in identity deployments).
    mpc_verifying_contract: [u8; 20],
    /// SNI / `platformName` the verifier on-chain is configured for.
    platform_name: String,
    /// Whether the TCP listener also serves JWKS notarization sessions.
    jwks_enabled: bool,
}

// ─── REST request/response types ────────────────────────────────────────────

// Reserved fields the tlsn-js client sends but we don't act on
// (`clientType`, `maxSentData`, `maxRecvData`). Deserialize into a
// permissive `Value` so unknown fields don't 400.
#[derive(Default, Deserialize)]
struct SessionRequest {
    #[serde(flatten, default)]
    _ignored: serde_json::Map<String, serde_json::Value>,
}

#[derive(Serialize)]
struct SessionResponse {
    #[serde(rename = "sessionId")]
    session_id: String,
}

#[derive(Serialize)]
struct InfoResponse {
    version: String,
    #[serde(rename = "publicKey")]
    public_key: String,
}

#[derive(Deserialize)]
struct NotarizeQuery {
    #[serde(rename = "sessionId")]
    session_id: Option<String>,
}

/// Reject a ProxyMode session whose TLS-cert-verified server identity does not
/// match the platform baked into the attestation digest. Without this a prover
/// could connect the notary to any WebPKI-valid host and obtain a signature
/// claiming `platform` (e.g. "api.x.com"). Case-insensitive: DNS is.
fn check_server_identity(domain: &str, platform_name: &str) -> Result<()> {
    if domain.eq_ignore_ascii_case(platform_name) {
        Ok(())
    } else {
        Err(Error::NotaryServer {
            detail: format!(
                "server identity '{domain}' does not match configured platform '{platform_name}'"
            ),
        })
    }
}

// ─── Server startup ──────────────────────────────────────────────────────────

/// Start the notary server (TCP + optional WebSocket with tlsn-js API).
pub async fn run(config: NotaryServerConfig) -> Result<NotaryServerHandle> {
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
    let mpc_verifying_contract = config.resolve_verifying_contract()?;
    let state = NotaryState {
        signer: Arc::new(signer),
        sessions: Arc::new(RwLock::new(HashMap::new())),
        max_sessions: config.max_sessions,
        public_key_hex,
        chain_id: config.chain_id,
        mpc_verifying_contract,
        platform_name: config.platform_name,
        jwks_enabled: config.jwks_enabled,
    };

    // Broadcast shutdown to every background task (TCP loop, WS server, sweep)
    // so none leaks after NotaryServerHandle::shutdown().
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // ── Background sweep: evict abandoned sessions so the map can't grow
    //    without bound (memory DoS). Exits on shutdown.
    {
        let sessions = Arc::clone(&state.sessions);
        let mut shutdown = shutdown_rx.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(SESSION_SWEEP_INTERVAL);
            loop {
                tokio::select! {
                    _ = tick.tick() => {
                        let evicted = sweep_stale_sessions(&sessions).await;
                        if evicted > 0 {
                            info!("notary: swept {evicted} stale session(s)");
                        }
                    }
                    _ = shutdown.changed() => break,
                }
            }
        });
    }

    // ── TCP listener (Rust client) ────────────────────────────────────
    let tcp_listener =
        TcpListener::bind(format!("{}:{}", config.host, config.port)).await?;
    let local_addr = tcp_listener.local_addr()?;
    info!("Notary TCP listening on {}", local_addr);

    // ── WebSocket HTTP server (browser / tlsn-js) ─────────────────────
    let ws_listener = if config.ws_port == 0 {
        None
    } else {
        let ws_addr = format!("{}:{}", config.host, config.ws_port);
        TcpListener::bind(&ws_addr).await.ok()
    };
    let ws_local_addr = ws_listener.as_ref().and_then(|l| l.local_addr().ok());
    if let Some(addr) = ws_local_addr {
        info!("Notary WebSocket listening on {addr} (tlsn-js compatible API)");
    }

    let tcp_state = state.clone();
    let mut tcp_shutdown = shutdown_rx.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                result = tcp_listener.accept() => {
                    match result {
                        Ok((stream, peer)) => {
                            info!("TCP connection from {}", peer);
                            let s = tcp_state.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_tcp_prover(stream, &s).await {
                                    error!("TCP handler error for {}: {}", peer, e);
                                }
                            });
                        }
                        Err(e) => error!("TCP accept failed: {}", e),
                    }
                }
                _ = tcp_shutdown.changed() => {
                    info!("Notary TCP shutting down");
                    break;
                }
            }
        }
    });

    if let Some(ws_listener) = ws_listener {
        let ws_state = state.clone();
        let cors = CorsLayer::new()
            .allow_origin(Any)
            .allow_headers(Any)
            .allow_methods(Any);

        let app = Router::new()
            .route("/info", get(info_handler))
            .route("/session", post(session_handler))
            .route("/notarize", get(notarize_ws_handler))
            .route("/attestation/{session_id}", get(attestation_handler))
            .route("/proxy", get(ws_proxy_handler))
            .route("/notarize-proxy", get(notarize_proxy_ws_handler))
            .layer(cors)
            .with_state(ws_state);

        let mut ws_shutdown = shutdown_rx.clone();
        tokio::spawn(async move {
            axum::serve(ws_listener, app)
                .with_graceful_shutdown(async move {
                    let _ = ws_shutdown.changed().await;
                })
                .await
                .unwrap_or_else(|e| error!("WS server error: {}", e));
        });
    }

    Ok(NotaryServerHandle {
        local_addr,
        ws_local_addr,
        shutdown: shutdown_tx,
    })
}

// ─── REST handlers ───────────────────────────────────────────────────────────

async fn info_handler(State(state): State<NotaryState>) -> Json<InfoResponse> {
    Json(InfoResponse {
        version: format!("v{}", env!("CARGO_PKG_VERSION")),
        public_key: state.public_key_hex.clone(),
    })
}

async fn session_handler(
    State(state): State<NotaryState>,
    Json(_req): Json<SessionRequest>,
) -> impl IntoResponse {
    let mut sessions = state.sessions.write().await;
    if !admit_session(&mut sessions, state.max_sessions) {
        tracing::warn!(
            cap = state.max_sessions,
            "notary session cap reached — rejecting"
        );
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "notary at capacity, retry shortly"})),
        )
            .into_response();
    }

    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    let session_id = hex::encode(bytes);
    sessions.insert(session_id.clone(), SessionEntry::default());
    drop(sessions);
    info!("Created session {}", session_id);
    (StatusCode::OK, Json(SessionResponse { session_id })).into_response()
}

/// Whether a new session may be admitted under `max` concurrent sessions. At
/// capacity it first reclaims stale entries inline (same predicate + waiter-
/// notify as the background sweep — a burst is usually mostly abandoned sessions
/// past the TTL); returns `false` only if the map is still full of live
/// sessions. The caller must hold the map write lock.
fn admit_session(map: &mut HashMap<String, SessionEntry>, max: usize) -> bool {
    if map.len() >= max {
        map.retain(|_, e| {
            let keep = e.created_at.elapsed() < SESSION_TTL;
            if !keep {
                e.ready.notify_waiters();
            }
            keep
        });
    }
    map.len() < max
}

// ─── Ceremony attestation endpoint, either transport ─────────────────────────

/// Attestation wire JSON.
///
/// The attested data and the signature over it, and nothing else. The notary
/// places no handle, account identifier, client identifier or chain address in
/// the signed bytes (REQ-COMMON-61): every one is derivable from the revealed
/// ranges, and a second signed representation can disagree with the bytes it
/// was taken from. That is why this endpoint no longer takes `handle`,
/// `user_id` or `session_addr` -- the Platform Verifier reads them itself, and
/// the notary deciding them would be the profile-specific judgement
/// REQ-COMMON-33 forbids it.
#[derive(Debug, Serialize)]
struct AttestationWire {
    /// The exact bytes of ceremony-common section 9.1.
    attested_data: Vec<u8>,
    /// EIP-191 over `keccak256(attested_data)`. The verifying side derives the
    /// key from this pair alone and accepts no caller-supplied digest
    /// (REQ-COMMON-49).
    notary_signature: Vec<u8>,
}

/// Fetch a notary-signed attestation for a completed TLSNotary session, of
/// either transport.
///
/// The caller gets no choice at all. Everything in the attested data is either
/// something the notary observed -- the authenticated server name, the
/// transcript lengths, the ranges the client revealed and the commitments over
/// the rest -- or its own clock reading, which REQ-COMMON-57 requires it to
/// supply. There is nothing left for a query parameter to select.
async fn attestation_handler(
    Path(session_id): Path<String>,
    State(state): State<NotaryState>,
) -> impl IntoResponse {
    let start = tokio::time::Instant::now();
    let budget = tokio::time::Duration::from_secs(60);
    let session: SessionAttestation = loop {
        let notify = {
            let sessions = state.sessions.read().await;
            let Some(entry) = sessions.get(&session_id) else {
                return (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({"error": "session not found"})),
                )
                    .into_response();
            };
            if let Some(ref raw) = entry.raw_attest {
                break raw.clone();
            }
            entry.ready.clone()
        };
        let remaining = budget.checked_sub(start.elapsed()).unwrap_or_default();
        if remaining.is_zero() {
            return (
                StatusCode::ACCEPTED,
                Json(serde_json::json!({"error": "attestation not yet ready"})),
            )
                .into_response();
        }
        let _ = tokio::time::timeout(remaining, notify.notified()).await;
    };

    let attested = match libid_tlsn::attest::attested_data(
        &session.partial,
        &session.authority,
        &session.commitments,
        libid_tlsn::attest::AttestationInput {
            created_at: session.created_at,
        },
    ) {
        Ok(a) => a,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("attested data: {e}")})),
            )
                .into_response();
        }
    };

    let encoded = match attested.encode() {
        Ok(bytes) => bytes,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("encode: {e}")})),
            )
                .into_response();
        }
    };

    // The notary signs `keccak256(attestedData)` and no other preimage
    // (REQ-COMMON-47).
    let digest = libid_crypto::keccak256(&encoded);
    match state.signer.sign_claim(&digest).await.map_err(Error::from) {
        Ok(notary_signature) => (
            StatusCode::OK,
            Json(AttestationWire {
                attested_data: encoded,
                notary_signature,
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("sign: {e}")})),
        )
            .into_response(),
    }
}

// ─── ProxyMode WebSocket handler ─────────────────────────────────────────────
//
// The browser (prover) connects here as a WebSocket. The notary runs the
// ProxyMode verifier: it forwards raw TLS bytes between the browser and the
// target server, verifies the TLS transcript via ZK tags, then receives the
// prover's reveal request and captures the raw attestation data.

async fn notarize_proxy_ws_handler(
    ws: WebSocketUpgrade,
    Query(query): Query<NotarizeQuery>,
    State(state): State<NotaryState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws_proxy_notarize(socket, state, query.session_id))
}

async fn handle_ws_proxy_notarize(
    socket: WebSocket,
    state: NotaryState,
    session_id: Option<String>,
) {
    let (io_a, io_b) = tokio::io::duplex(1 << 17);
    let (mut ws_tx, mut ws_rx) = socket.split();

    // Guarded: when this handler returns, the pump is aborted with it —
    // otherwise a client that keeps the WebSocket open after the session
    // failed would pin the pump task (and the socket) indefinitely.
    let _pump_task = AbortOnDrop::new(tokio::spawn(async move {
        let (mut pipe_reader, mut pipe_writer) = tokio::io::split(io_a);
        let ws_to_pipe = async {
            while let Some(Ok(msg)) = ws_rx.next().await {
                match msg {
                    Message::Binary(data)
                        if pipe_writer.write_all(&data).await.is_err() =>
                    {
                        break;
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
        };
        let pipe_to_ws = async {
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
                            break;
                        }
                    }
                }
            }
        };
        tokio::join!(ws_to_pipe, pipe_to_ws);
    }));

    let session = run_proxy_verifier_session(io_b, &state, session_id);
    match tokio::time::timeout(CONNECTION_DEADLINE, session).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => error!("ProxyMode verifier error: {}", e),
        Err(_) => error!(
            "ProxyMode session exceeded the {}s connection deadline; aborting",
            CONNECTION_DEADLINE.as_secs()
        ),
    }
}

async fn run_proxy_verifier_session<T>(
    socket: T,
    state: &NotaryState,
    session_id: Option<String>,
) -> Result<()>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();
    // Guarded spawn: every exit path below — each `?`, panics, the caller
    // dropping this future — aborts the driver instead of detaching it.
    let mut driver_task = AbortOnDrop::new(tokio::spawn(driver));

    let setup = async {
        let verifier = handle
            .new_verifier(
                VerifierConfig::builder()
                    .root_store(libid_tlsn::root_store())
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

        let server_tcp = tokio::net::TcpStream::connect(format!("{server_name_str}:443"))
            .await
            .map_err(|e| Error::NotaryServer {
                detail: format!("TCP connect to {server_name_str}: {e}"),
            })?;

        let verifier = proxy_verifier
            .accept()
            .await
            .map_err(|e| Error::NotaryServer {
                detail: format!("verifier accept: {e}"),
            })?
            .run(server_tcp.compat())
            .await
            .map_err(|e| Error::NotaryServer {
                detail: format!("run_proxy: {e}"),
            })?;

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

        Ok((server_name, transcript, transcript_commitments))
    };
    tokio::pin!(setup);

    // Race setup against the driver. The driver only finishes early when the
    // connection died under the session (e.g. a client that connected and
    // immediately closed) — a protocol request already submitted to it may
    // then never resolve, so fail instead of pending forever.
    let (server_name, transcript, transcript_commitments) = tokio::select! {
        biased;
        res = &mut setup => res?,
        driver_res = driver_task.handle_mut() => {
            return Err(driver_finished_early(driver_res));
        }
    };

    driver_task
        .into_inner()
        .await
        .map_err(|e| Error::NotaryServer {
            detail: format!("driver join: {e}"),
        })?
        .map_err(|e| Error::NotaryServer {
            detail: format!("driver: {e}"),
        })?;

    // Both sessions reveal authed sent bytes: /token the `client_id=` slice,
    // /me the request prefix + CRLF end anchor (H1) plus the recv username.
    let server_name = server_name.ok_or_else(|| Error::NotaryServer {
        detail: "prover did not reveal server name".into(),
    })?;
    let ServerName::Dns(ref dns_name) = server_name;
    let domain = dns_name.as_str().to_string();

    // The digest attests `platform_name`, but the prover picks the server_name
    // and any WebPKI-valid cert passes. Pin the cert-verified server identity
    // to the platform, else a prover attests api.x.com from an attacker server.
    check_server_identity(&domain, &state.platform_name)?;

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

    let created_at = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let raw_attest = SessionAttestation {
        partial,
        authority: dns_name.as_str().to_string(),
        commitments: transcript_commitments.clone(),
        created_at,
    };

    if let Some(ref sid) = session_id {
        let notify = {
            let mut sessions = state.sessions.write().await;
            match sessions.get_mut(sid) {
                Some(entry) => {
                    entry.raw_attest = Some(raw_attest);
                    info!("ProxyMode: stored attestation source for session {sid}");
                    Some(entry.ready.clone())
                }
                None => {
                    warn!(
                        "ProxyMode: session {sid} gone before raw attestation could be stored (evicted/abandoned) — proof dropped"
                    );
                    None
                }
            }
        };
        if let Some(n) = notify {
            n.notify_one();
        }
    }

    info!("ProxyMode: hash-commit attestation built for {domain}");
    Ok(())
}

// ─── WebSocket proxy ─────────────────────────────────────────────────────────
//
// Forwards browser WebSocket connections to a remote HTTPS/TLS server.
// tlsn-js sends raw TLS bytes over this proxy to reach the platform API.
// Query: ?token=<hostname>  (e.g. ?token=api.x.com)

#[derive(Deserialize)]
struct ProxyQuery {
    token: Option<String>,
}

async fn ws_proxy_handler(
    ws: WebSocketUpgrade,
    Query(query): Query<ProxyQuery>,
    State(state): State<NotaryState>,
) -> impl IntoResponse {
    let host = query.token.unwrap_or_else(|| state.platform_name.clone());
    ws.on_upgrade(move |socket| proxy_ws_to_tcp(socket, host))
}

async fn proxy_ws_to_tcp(socket: WebSocket, host: String) {
    let addr = format!("{host}:443");
    let tcp = match tokio::net::TcpStream::connect(&addr).await {
        Ok(s) => s,
        Err(e) => {
            error!("Proxy: failed to connect to {}: {}", addr, e);
            return;
        }
    };

    info!("Proxy: forwarding WS ↔ TCP to {}", addr);

    let (mut ws_tx, mut ws_rx) = socket.split();
    let (mut tcp_rx, mut tcp_tx) = tokio::io::split(tcp);

    let ws_to_tcp = async {
        while let Some(Ok(msg)) = ws_rx.next().await {
            match msg {
                Message::Binary(data) if tcp_tx.write_all(&data).await.is_err() => {
                    break;
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
    };

    let tcp_to_ws = async {
        let mut buf = vec![0u8; 65536];
        loop {
            match tcp_rx.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if ws_tx
                        .send(Message::Binary(buf[..n].to_vec().into()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    };

    tokio::join!(ws_to_tcp, tcp_to_ws);
    info!("Proxy: connection to {} closed", addr);
}

// ─── WebSocket handlers ──────────────────────────────────────────────────────

async fn notarize_ws_handler(
    ws: WebSocketUpgrade,
    Query(query): Query<NotarizeQuery>,
    State(state): State<NotaryState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws_prover(socket, state, query.session_id))
}

async fn handle_ws_prover(
    socket: WebSocket,
    state: NotaryState,
    session_id: Option<String>,
) {
    let (io_a, io_b) = tokio::io::duplex(1 << 17); // 128 KB buffer

    let (mut ws_tx, mut ws_rx) = socket.split();

    // Guarded: when this handler returns, the pump is aborted with it —
    // otherwise a client that keeps the WebSocket open after the session
    // failed would pin the pump task (and the socket) indefinitely.
    let _pump_task = AbortOnDrop::new(tokio::spawn(async move {
        let (mut pipe_reader, mut pipe_writer) = tokio::io::split(io_a);

        let ws_to_pipe = async {
            while let Some(Ok(msg)) = ws_rx.next().await {
                match msg {
                    Message::Binary(data)
                        if pipe_writer.write_all(&data).await.is_err() =>
                    {
                        break;
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
        };

        let pipe_to_ws = async {
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
                            break;
                        }
                    }
                }
            }
        };

        tokio::join!(ws_to_pipe, pipe_to_ws);
    }));

    let session = handle_notary_session(io_b, &state, session_id);
    match tokio::time::timeout(CONNECTION_DEADLINE, session).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => error!("WS notary handler error: {}", e),
        Err(_) => error!(
            "WS notary session exceeded the {}s connection deadline; aborting",
            CONNECTION_DEADLINE.as_secs()
        ),
    }
}

// ─── tlsn attestation signing ────────────────────────────────────────────────
//
// tlsn's `Signer` trait is NOT ours to change — it lives in the pinned tlsn
// crate and is synchronous, while KMS signing is a network call. Rather than
// bridge sync→async inside the trait (runtime hacks), the sign step is lifted
// OUT of tlsn entirely:
//
//   1. `build()` runs with a capture-only signer: pure computation, no IO.
//      It records the serialized attestation header — the exact bytes tlsn
//      would have signed — and returns a placeholder signature.
//   2. The real signature is produced by an ordinary `.await` on
//      ManagedSigner, in the async handler.
//   3. `Attestation`'s fields are public; the placeholder is replaced.
//
// This is sound because the header does not depend on the signature (it is
// id + version + body root), and the verifying key embedded in the body is
// the REAL key — the capture signer reports it truthfully. The format matches
// tlsn's own `Secp256k1EthSigner`: keccak256 the message, sign the bare
// digest, 65 bytes r || s || v with v ∈ {27, 28}.

/// Captures the header bytes `AttestationBuilder::build` asks it to sign.
struct HeaderCaptureSigner {
    /// Real compressed public key — embedded in the attestation body, so it
    /// must be truthful even though this signer never really signs.
    public_key: [u8; 33],
    /// The serialized header, recorded for the async signer.
    captured: Arc<std::sync::Mutex<Option<Vec<u8>>>>,
}

impl TlsnSigner for HeaderCaptureSigner {
    fn alg_id(&self) -> SignatureAlgId {
        SignatureAlgId::SECP256K1ETH
    }

    fn sign(&self, msg: &[u8]) -> std::result::Result<TlsnSignature, TlsnSignatureError> {
        *self.captured.lock().expect("capture mutex") = Some(msg.to_vec());
        // Placeholder, overwritten immediately after build(). 65 zero bytes is
        // structurally a signature but can never verify — if a bug ever ships
        // it, verification fails loudly rather than accepting a forgery.
        Ok(TlsnSignature {
            alg: SignatureAlgId::SECP256K1ETH,
            data: vec![0u8; 65],
        })
    }

    fn verifying_key(&self) -> TlsnVerifyingKey {
        TlsnVerifyingKey {
            alg: KeyAlgId::K256,
            data: self.public_key.to_vec(),
        }
    }
}

// ─── Core notary logic (transport-agnostic) ─────────────────────────────────

/// TCP client (Rust backend prover) — uses the full custom wire protocol.
async fn handle_tcp_prover<T>(socket: T, state: &NotaryState) -> Result<()>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Sync + Unpin + 'static,
{
    // Deadline on the WHOLE connection, not any single step: no TCP client —
    // however broken — may pin this handler task past [`CONNECTION_DEADLINE`].
    tokio::time::timeout(
        CONNECTION_DEADLINE,
        handle_notary_session(socket, state, None),
    )
    .await
    .map_err(|_| Error::NotaryServer {
        detail: format!(
            "connection exceeded the {}s deadline",
            CONNECTION_DEADLINE.as_secs()
        ),
    })?
}

async fn handle_notary_session<T>(
    socket: T,
    state: &NotaryState,
    session_id: Option<String>,
) -> Result<()>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Sync + Unpin + 'static,
{
    let result = libid_tlsn::verifier(socket).await?;
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

    // ── JWKS duty dispatch ──
    //
    // Same listener, same MPC-TLS verification, same signing identity: a
    // session whose TLS-cert-verified server name is the JWKS host is a
    // notarized JWKS reading. Its wire response is a signed
    // `JwksRotationProof` (no attestation-request round trip — the JWKS
    // prover protocol ends with the verifier's response).
    if state.jwks_enabled && domain.eq_ignore_ascii_case(jwks::JWKS_DOMAIN) {
        let handshake = libid_tlsn::extract_handshake_data(&result.tls_transcript)?;
        let response =
            jwks::build_rotation_response(sent, recv, &handshake, &state.signer).await?;
        let mut io = result.recovered_io;
        write_msg(&mut io, &response).await?;
        info!("JWKS rotation proof sent to prover");
        return Ok(());
    }

    // The ceremony record is transport-agnostic. It is built from what the
    // session revealed, the server the notary authenticated, the commitments
    // over the rest, and the notary's own clock -- and an MPC-TLS session
    // produces all four exactly as a ProxyMode one does. Captured here, before
    // `result` is taken apart for the tlsn attestation below.
    let ceremony_partial = result.partial_transcript.clone();
    let ceremony_commitments = result.transcript_commitments.clone();

    let mut io = result.recovered_io;
    let att_request: Request = read_msg(&mut io).await?;
    info!("Received attestation request from prover");

    // See the "tlsn attestation signing" section: build() runs with a
    // capture-only signer, then the real (possibly KMS) signature is applied
    // with an ordinary await — no sync-over-async bridging.
    let captured_header: Arc<std::sync::Mutex<Option<Vec<u8>>>> = Arc::default();
    let mut provider = CryptoProvider::default();
    provider.signer.set_signer(Box::new(HeaderCaptureSigner {
        public_key: state.signer.compressed_public_key(),
        captured: Arc::clone(&captured_header),
    }));

    let mut att_config = AttestationConfig::builder();
    att_config.supported_signature_algs(vec![SignatureAlgId::SECP256K1ETH]);
    let att_config = att_config.build().map_err(|e| Error::NotaryServer {
        detail: format!("attestation config: {e}"),
    })?;

    let tls_tx = &result.tls_transcript;
    let sent_len = u32::try_from(sent.len()).map_err(|_| Error::NotaryServer {
        detail: "sent transcript too large for u32".into(),
    })?;
    let recv_len = u32::try_from(recv.len()).map_err(|_| Error::NotaryServer {
        detail: "recv transcript too large for u32".into(),
    })?;

    let mut att_builder = Attestation::builder(&att_config)
        .accept_request(att_request)
        .map_err(|e| Error::NotaryServer {
            detail: format!("accept attestation request: {e}"),
        })?;
    att_builder
        .connection_info(ConnectionInfo {
            time: tls_tx.time(),
            version: *tls_tx.version(),
            transcript_length: TranscriptLength {
                sent: sent_len,
                received: recv_len,
            },
        })
        .server_ephemeral_key(tls_tx.server_ephemeral_key().clone())
        .transcript_commitments(result.transcript_commitments);

    let mut attestation =
        att_builder
            .build(&provider)
            .map_err(|e| Error::NotaryServer {
                detail: format!("attestation build: {e}"),
            })?;

    // Sign the captured header for real — an actual async call, KMS or local.
    let header_bytes = captured_header
        .lock()
        .expect("capture mutex")
        .take()
        .ok_or_else(|| Error::NotaryServer {
            detail: "attestation build never requested a signature".into(),
        })?;
    let digest = keccak256(&header_bytes);
    attestation.signature = TlsnSignature {
        alg: SignatureAlgId::SECP256K1ETH,
        data: state.signer.sign_prehash(&digest).await?,
    };
    let attestation_bytes = serde_json::to_vec(&attestation)?;
    info!("Attestation built");

    let handshake = libid_tlsn::extract_handshake_data(tls_tx)?;

    let request_line = &sent[find_request_line_range(sent)];
    let request_line_str =
        std::str::from_utf8(request_line).map_err(|e| Error::MalformedRequestLine {
            detail: format!("not valid UTF-8: {e}"),
        })?;
    let (method_path, _version) =
        request_line_str
            .rsplit_once(' ')
            .ok_or_else(|| Error::MalformedRequestLine {
                detail: "missing HTTP version".into(),
            })?;
    let request_path = method_path
        .split_once(' ')
        .map_or(method_path, |(_, path)| path);
    info!("Endpoint from transcript: {}", request_path);

    let mut leaves = vec![
        double_hash_leaf("domain:", domain.as_bytes()),
        double_hash_leaf("endpoint:", request_path.as_bytes()),
    ];
    let recv_authed = transcript.received_authed();
    let recv_data = transcript.received_unsafe();
    let mut recv_segments: Vec<Vec<u8>> = Vec::new();
    for range in recv_authed.iter() {
        let segment = &recv_data[range.clone()];
        leaves.push(double_hash_leaf("recv:", segment));
        recv_segments.push(segment.to_vec());
    }

    let transcript_root = libid_crypto::build_merkle_tree(&leaves);

    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let notary_digest = compute_notary_digest(
        state.chain_id,
        &state.mpc_verifying_contract,
        &domain,
        &handshake.client_random,
        &handshake.server_random,
        &handshake.server_ephemeral_key,
        &transcript_root,
        timestamp,
    );
    let notary_signature = state.signer.sign_claim(&notary_digest).await?;

    let evm_proof = EvmProof {
        domain: domain.clone(),
        endpoint: request_path.to_string(),
        client_random: handshake.client_random,
        server_random: handshake.server_random,
        server_ephemeral_key: handshake.server_ephemeral_key,
        transcript_root,
        leaves,
        timestamp,
        notary_signature,
        recv_segments,
        explicit_nonce: Vec::new(),
        app_ciphertext: Vec::new(),
    };

    let notary_response = NotaryResponse {
        attestation: attestation_bytes,
        evm_proof,
    };

    // The attestation source, for retrieval by session id at
    // `GET /attestation/{id}`. The pre-ceremony `NotaryResponse` goes over the
    // wire below and nowhere else -- the REST endpoint that also served it had
    // no caller, because the only prover on this path reads it from the socket.
    let raw_attest = SessionAttestation {
        partial: ceremony_partial,
        authority: domain.clone(),
        commitments: ceremony_commitments,
        created_at: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };

    if let Some(ref sid) = session_id {
        let notify = {
            let mut sessions = state.sessions.write().await;
            match sessions.get_mut(sid) {
                Some(entry) => {
                    entry.raw_attest = Some(raw_attest);
                    info!("MPC-TLS: stored attestation source for session {sid}");
                    Some(entry.ready.clone())
                }
                None => {
                    warn!(
                        "session {sid} gone before EVM proof could be stored (evicted/abandoned) — proof dropped"
                    );
                    None
                }
            }
        };
        if let Some(n) = notify {
            n.notify_one();
        }
    }

    // For TCP/legacy connections: send over the wire (Rust client protocol)
    write_msg(&mut io, &notary_response).await?;
    info!("NotaryResponse sent to prover");

    Ok(())
}

/// Test-only helper: run one ProxyMode verifier session over `socket`
/// and return the captured `RawAttestationData`. Caller is responsible
/// for signing the typed token or /me attestation digest via
/// `libid_attestations::compute_*_attest_digest`.
///
/// The browser path runs this implicitly via the `/notarize-proxy` WS
/// handler + `GET /attestation/{sid}` HTTP fetch; this helper
/// short-circuits both for in-process e2e tests.
#[doc(hidden)]
pub async fn run_proxy_verifier_for_test<T>(
    socket: T,
    signer: Arc<ManagedSigner>,
    chain_id: u64,
    mpc_verifying_contract: [u8; 20],
    platform_name: String,
) -> Result<SessionAttestation>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let state = NotaryState {
        signer,
        sessions: Arc::new(RwLock::new(HashMap::new())),
        max_sessions: 1024,
        public_key_hex: String::new(),
        chain_id,
        mpc_verifying_contract,
        platform_name,
        jwks_enabled: false,
    };
    let session_id = "test-session".to_string();
    {
        let mut sessions = state.sessions.write().await;
        sessions.insert(session_id.clone(), SessionEntry::default());
    }
    run_proxy_verifier_session(socket, &state, Some(session_id.clone())).await?;
    let sessions = state.sessions.read().await;
    let entry = sessions
        .get(&session_id)
        .ok_or_else(|| Error::NotaryServer {
            detail: "session entry missing".into(),
        })?;
    entry.raw_attest.clone().ok_or_else(|| Error::NotaryServer {
        detail: "raw attestation not populated".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::check_server_identity;

    /// Pins the lifted-out attestation signing (HeaderCaptureSigner +
    /// ManagedSigner::sign_prehash) byte-identical to tlsn's own
    /// Secp256k1EthSigner. Both sides use RFC 6979 deterministic ECDSA, so
    /// equal inputs MUST give equal signatures — any divergence in hashing,
    /// s-normalisation or v encoding fails this test instead of surfacing as
    /// attestations the prover rejects.
    #[tokio::test]
    async fn lifted_signing_matches_tlsn_secp256k1eth_signer() {
        use libid_signer::SignerSource;
        use tlsn::attestation::signing::{
            Secp256k1EthSigner,
            Signer as _,
        };

        // anvil #0 — public test key.
        let key_hex = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let key_bytes = hex::decode(key_hex).unwrap();

        let tlsn_signer = Secp256k1EthSigner::new(&key_bytes).unwrap();
        let managed = SignerSource::from_spec(key_hex)
            .unwrap()
            .build_managed(None)
            .await
            .unwrap();

        // Arbitrary "serialized header" bytes of various shapes.
        for msg in [&b"header"[..], &[0u8; 97], &[0xFF; 32]] {
            let reference = tlsn_signer.sign(msg).expect("tlsn sign");
            let digest = libid_crypto::keccak256(msg);
            let lifted = managed.sign_prehash(&digest).await.expect("managed sign");
            assert_eq!(reference.data, lifted, "msg {msg:02x?}");
            // And the verifying key the capture signer embeds matches tlsn's.
            assert_eq!(
                tlsn_signer.verifying_key().data,
                managed.compressed_public_key().to_vec()
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn session_cap_rejects_when_full_then_reclaims_stale() {
        use tokio::time::Duration;

        use super::{
            admit_session,
            SessionEntry,
            SESSION_TTL,
        };

        const MAX: usize = 3;
        let mut map = std::collections::HashMap::new();
        for i in 0..MAX {
            map.insert(format!("s{i}"), SessionEntry::default());
        }
        // Full of LIVE sessions → a new session is rejected (burst bound).
        assert!(
            !admit_session(&mut map, MAX),
            "cap must reject when full of live sessions"
        );
        assert_eq!(map.len(), MAX);

        // Age every entry past the TTL → the at-capacity path reclaims them
        // inline → the next session is admitted again.
        tokio::time::advance(SESSION_TTL + Duration::from_secs(1)).await;
        assert!(
            admit_session(&mut map, MAX),
            "stale entries reclaimed at capacity → admit"
        );
        assert!(map.is_empty(), "all stale entries evicted");
    }

    #[tokio::test(start_paused = true)]
    async fn sweep_evicts_stale_sessions_by_monotonic_age() {
        use std::sync::Arc;

        use tokio::{
            sync::RwLock,
            time::Duration,
        };

        use tlsn::transcript::Transcript;

        use super::{
            sweep_stale_sessions,
            SessionAttestation,
            SessionEntry,
            SESSION_TTL,
        };

        // Any completed session will do; the sweep only cares that one exists.
        let produced = SessionAttestation {
            partial: Transcript::new(&b"GET / HTTP/1.1"[..], &b"HTTP/1.1 200 OK"[..])
                .to_partial(Default::default(), Default::default()),
            authority: "api.x.com".to_string(),
            commitments: Vec::new(),
            created_at: 0,
        };

        let sessions = Arc::new(RwLock::new(std::collections::HashMap::new()));
        // Two entries at T=0: one abandoned (no result), one that produced an
        // attestation but was never fetched. BOTH must be bounded by the TTL —
        // a produced-but-unfetched entry retained forever is the memory DoS.
        {
            let mut m = sessions.write().await;
            m.insert("abandoned".to_string(), SessionEntry::default());
            m.insert(
                "produced".to_string(),
                SessionEntry {
                    raw_attest: Some(produced),
                    ..SessionEntry::default()
                },
            );
        }

        // Advance a monotonic clock past the TTL, then add a fresh entry.
        tokio::time::advance(SESSION_TTL + Duration::from_secs(60)).await;
        {
            let mut m = sessions.write().await;
            m.insert("fresh".to_string(), SessionEntry::default());
        }

        let evicted = sweep_stale_sessions(&sessions).await;
        assert_eq!(
            evicted, 2,
            "both stale entries evicted regardless of result"
        );
        let m = sessions.read().await;
        assert!(m.contains_key("fresh"), "young entry kept");
        assert!(
            !m.contains_key("abandoned"),
            "abandoned stale entry evicted"
        );
        assert!(
            !m.contains_key("produced"),
            "produced-but-unfetched entry is still bounded by the TTL"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn sweep_wakes_waiters_on_eviction() {
        use std::sync::Arc;

        use tokio::{
            sync::RwLock,
            time::Duration,
        };

        use super::{
            sweep_stale_sessions,
            SessionEntry,
            SESSION_TTL,
        };

        let sessions = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let ready = {
            let mut m = sessions.write().await;
            let entry = SessionEntry::default();
            let ready = entry.ready.clone();
            m.insert("stale".to_string(), entry);
            ready
        };

        // A handler is blocked on this session's readiness.
        let waiter = tokio::spawn(async move { ready.notified().await });
        tokio::task::yield_now().await; // let the waiter register on the Notify

        tokio::time::advance(SESSION_TTL + Duration::from_secs(60)).await;
        let evicted = sweep_stale_sessions(&sessions).await;
        assert_eq!(evicted, 1);

        // Eviction woke the waiter — it completes instead of sleeping to timeout.
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("eviction should wake the blocked waiter")
            .expect("waiter task panicked");
    }

    #[test]
    fn server_identity_accepts_exact_platform() {
        assert!(check_server_identity("api.x.com", "api.x.com").is_ok());
    }

    #[test]
    fn server_identity_accepts_case_insensitive() {
        // DNS names are case-insensitive; a cert SAN may differ in case.
        assert!(check_server_identity("API.X.COM", "api.x.com").is_ok());
    }

    #[test]
    fn server_identity_rejects_attacker_host() {
        // Core of the critical fix: a WebPKI-valid attacker server must not be
        // attested as the configured platform.
        assert!(check_server_identity("evil.example", "api.x.com").is_err());
    }

    #[test]
    fn server_identity_rejects_subdomain_lookalike() {
        // No suffix/substring leniency: only an exact (case-insensitive) match.
        assert!(check_server_identity("api.x.com.evil.example", "api.x.com").is_err());
        assert!(check_server_identity("notapi.x.com", "api.x.com").is_err());
    }

    /// A client that connects and then goes silent forever must not pin the
    /// handler past [`CONNECTION_DEADLINE`] — defense in depth over the
    /// fail-fast fixes, covering whatever future bug makes a session pend.
    /// Paused time: the runtime auto-advances the clock to the deadline the
    /// moment everything is blocked, so the test finishes in milliseconds.
    #[tokio::test(start_paused = true)]
    async fn silent_connection_hits_the_deadline() {
        use std::{
            collections::HashMap,
            sync::Arc,
        };

        use libid_signer::SignerSource;
        use tokio::sync::RwLock;

        use super::{
            handle_tcp_prover,
            NotaryState,
            CONNECTION_DEADLINE,
        };

        // anvil #0 — public test key.
        let key_hex = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let signer = SignerSource::from_spec(key_hex)
            .unwrap()
            .build_managed(None)
            .await
            .unwrap();
        let state = NotaryState {
            public_key_hex: hex::encode(signer.compressed_public_key()),
            signer: Arc::new(signer),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            max_sessions: 8,
            chain_id: 1,
            mpc_verifying_contract: [0x22; 20],
            platform_name: "api.x.com".to_string(),
            jwks_enabled: false,
        };

        // The client half stays open and never writes a byte.
        let (_client, server) = tokio::io::duplex(1 << 16);

        let started = tokio::time::Instant::now();
        let err = handle_tcp_prover(server, &state)
            .await
            .expect_err("a silent connection must fail, not pend");
        assert!(
            err.to_string().contains("deadline"),
            "expected the deadline error, got: {err}"
        );
        assert!(
            started.elapsed() >= CONNECTION_DEADLINE,
            "failed before the deadline — some step errored spuriously"
        );
    }
}
