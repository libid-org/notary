//! Notary server: handles plain-TCP (backend MPC-TLS) and WebSocket connections.
//!
//! # Endpoints
//!
//! - **TCP** (port `NOTARY_PORT`): MPC-TLS verifier for Rust backend provers.
//!   Dispatches on the TLS-cert-verified server name after verification:
//!   `www.googleapis.com` sessions are answered with a signed
//!   [`crate::jwks::JwksNotaryResponse`] (JWKS rotation duty); every other
//!   session with the section 9.1 ceremony attestation, written back down the
//!   socket the prover opened.
//! - **GET  /info**: returns `{version, publicKey}` — compatible with tlsn-js.
//! - **GET /notarize-proxy** (WS upgrade): ProxyMode session followed by one
//!   length-prefixed ceremony attestation on the reclaimed WebSocket.
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
        OriginalUri,
        State,
    },
    http::StatusCode,
    response::{
        IntoResponse,
        Json,
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
use rand::RngCore;
use serde::{
    Deserialize,
    Serialize,
};
use tlsn::{
    config::verifier::VerifierConfig,
    connection::{
        CertBinding,
        CertBindingV1_2,
        ServerName,
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
    sync::Semaphore,
};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tower_http::cors::{
    Any,
    CorsLayer,
};
use tracing::{
    error,
    info,
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

    /// Signals every background task (TCP accept loop and WS server) to stop.
    pub fn shutdown(self) {
        let _ = self.shutdown.send(true);
    }
}

/// Overall deadline for one prover connection (TCP or WebSocket), covering
/// the whole MPC-TLS/ProxyMode session plus the attestation exchange. A real
/// session completes in well under a minute even on a slow link; 5 minutes is
/// generous headroom. This is defense in depth:
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

#[derive(Clone)]
struct NotaryState {
    /// Notary signing identity (local hex key or AWS KMS).
    signer: Arc<ManagedSigner>,
    proxy_sessions: Arc<Semaphore>,
    public_key_hex: String,
    jwks_enabled: bool,
    #[cfg(test)]
    proxy_test: Option<ProxyTestConfig>,
}

#[cfg(test)]
#[derive(Clone)]
struct ProxyTestConfig {
    server_addr: SocketAddr,
    root_store: tlsn::webpki::RootCertStore,
}

#[derive(Serialize)]
struct InfoResponse {
    version: String,
    #[serde(rename = "publicKey")]
    public_key: String,
}

// ─── Server startup ──────────────────────────────────────────────────────────

/// Start the notary server (TCP + optional browser TLSNotary WebSocket).
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
    let state = NotaryState {
        signer: Arc::new(signer),
        proxy_sessions: Arc::new(Semaphore::new(config.max_sessions)),
        public_key_hex,
        jwks_enabled: config.jwks_enabled,
        #[cfg(test)]
        proxy_test: None,
    };

    // Broadcast shutdown to the TCP and WebSocket servers.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

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
        info!("Notary WebSocket listening on {addr} (browser TLSNotary API)");
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

async fn send_attestation<W: tokio::io::AsyncWrite + Unpin>(
    io: &mut W,
    attestation: &AttestationWire,
) -> Result<()> {
    write_msg(io, attestation).await?;
    io.shutdown().await?;
    Ok(())
}

// ─── ProxyMode WebSocket handler ─────────────────────────────────────────────
//
// The browser (prover) connects here as a WebSocket. The notary runs the
// ProxyMode verifier: it forwards raw TLS bytes between the browser and the
// target server, authenticates the transcript against the record layer's own
// tags, then receives the prover's reveal request and captures what the
// session disclosed.

async fn notarize_proxy_ws_handler(
    ws: WebSocketUpgrade,
    OriginalUri(uri): OriginalUri,
    State(state): State<NotaryState>,
) -> impl IntoResponse {
    if uri.query().is_some() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let Ok(permit) = Arc::clone(&state.proxy_sessions).try_acquire_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    ws.on_upgrade(move |socket| handle_ws_proxy_notarize(socket, state, permit))
        .into_response()
}

async fn handle_ws_proxy_notarize(
    socket: WebSocket,
    state: NotaryState,
    _permit: tokio::sync::OwnedSemaphorePermit,
) {
    let (io_a, io_b) = tokio::io::duplex(1 << 17);
    let (mut ws_tx, mut ws_rx) = socket.split();

    // Guarded: when this handler returns, the pump is aborted with it —
    // otherwise a client that keeps the WebSocket open after the session
    // failed would pin the pump task (and the socket) indefinitely.
    let pump_task = AbortOnDrop::new(tokio::spawn(async move {
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
            let _ = ws_tx.send(Message::Close(None)).await;
        };
        tokio::select! {
            _ = ws_to_pipe => {}
            _ = pipe_to_ws => {}
        }
    }));

    let session = run_proxy_verifier_session(io_b, &state);
    match tokio::time::timeout(CONNECTION_DEADLINE, session).await {
        Ok(Ok(())) => {
            if let Err(e) = pump_task.into_inner().await {
                error!("ProxyMode WebSocket pump join error: {e}");
            }
        }
        Ok(Err(e)) => error!("ProxyMode verifier error: {}", e),
        Err(_) => error!(
            "ProxyMode session exceeded the {}s connection deadline; aborting",
            CONNECTION_DEADLINE.as_secs()
        ),
    }
}

async fn run_proxy_verifier_session<T>(socket: T, state: &NotaryState) -> Result<()>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();
    // Guarded spawn: every exit path below — each `?`, panics, the caller
    // dropping this future — aborts the driver instead of detaching it.
    let mut driver_task = AbortOnDrop::new(tokio::spawn(driver));

    let setup = async {
        #[cfg(test)]
        let root_store = state
            .proxy_test
            .as_ref()
            .map(|config| config.root_store.clone())
            .unwrap_or_else(libid_tlsn::root_store);
        #[cfg(not(test))]
        let root_store = libid_tlsn::root_store();
        let verifier = handle
            .new_verifier(
                VerifierConfig::builder()
                    .root_store(root_store)
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

        #[cfg(test)]
        let server_addr = state
            .proxy_test
            .as_ref()
            .map(|config| config.server_addr.to_string())
            .unwrap_or_else(|| format!("{server_name_str}:443"));
        #[cfg(not(test))]
        let server_addr = format!("{server_name_str}:443");
        let server_tcp =
            tokio::net::TcpStream::connect(server_addr)
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

    let mut io = driver_task
        .into_inner()
        .await
        .map_err(|e| Error::NotaryServer {
            detail: format!("driver join: {e}"),
        })?
        .map_err(|e| Error::NotaryServer {
            detail: format!("driver: {e}"),
        })?
        .into_inner();

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
    send_attestation(&mut io, &attestation).await?;
    info!("ProxyMode: ceremony attestation sent for {domain}");
    Ok(())
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

// ─── Core notary logic (transport-agnostic) ─────────────────────────────────

/// TCP client (Rust backend prover) — uses the full custom wire protocol.
async fn handle_tcp_prover<T>(socket: T, state: &NotaryState) -> Result<()>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Sync + Unpin + 'static,
{
    // Deadline on the WHOLE connection, not any single step: no TCP client —
    // however broken — may pin this handler task past [`CONNECTION_DEADLINE`].
    tokio::time::timeout(CONNECTION_DEADLINE, handle_notary_session(socket, state))
        .await
        .map_err(|_| Error::NotaryServer {
            detail: format!(
                "connection exceeded the {}s deadline",
                CONNECTION_DEADLINE.as_secs()
            ),
        })?
}

async fn handle_notary_session<T>(socket: T, state: &NotaryState) -> Result<()>
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
        let handshake = match result.tls_transcript.certificate_binding() {
            CertBinding::V1_2(CertBindingV1_2 {
                client_random,
                server_random,
                server_ephemeral_key,
            }) => jwks::JwksHandshake {
                client_random: *client_random,
                server_random: *server_random,
                server_ephemeral_key: server_ephemeral_key.key.clone(),
            },
            _ => {
                return Err(Error::Jwks {
                    detail: "JWKS proofs require TLS 1.2".into(),
                });
            }
        };
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
    // produces all four exactly as a ProxyMode one does.
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

    #[tokio::test]
    async fn attestation_is_one_length_prefixed_frame_then_eof() {
        use libid_transcript::read_msg;
        use tokio::io::AsyncReadExt;

        use super::{
            send_attestation,
            AttestationWire,
        };

        let (mut notary, mut browser) = tokio::io::duplex(1024);
        let send = tokio::spawn(async move {
            send_attestation(
                &mut notary,
                &AttestationWire {
                    attested_data: vec![1, 2, 3],
                    notary_signature: vec![4; 65],
                },
            )
            .await
            .unwrap();
        });

        let frame: serde_json::Value = read_msg(&mut browser).await.unwrap();
        assert_eq!(frame["attested_data"], serde_json::json!([1, 2, 3]));
        assert_eq!(frame["notary_signature"].as_array().unwrap().len(), 65);
        assert_eq!(browser.read(&mut [0]).await.unwrap(), 0);
        send.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn proxy_protocol_returns_attestation_on_the_reclaimed_websocket() {
        use std::{
            sync::Arc,
            time::Duration,
        };

        use axum::{
            routing::get,
            Router,
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
            sync::Semaphore,
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
            notarize_proxy_ws_handler,
            NotaryState,
            ProxyTestConfig,
        };

        const TEST_KEY: &str =
            "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

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
        let state = NotaryState {
            signer: Arc::new(signer),
            proxy_sessions: Arc::new(Semaphore::new(1)),
            public_key_hex: String::new(),
            jwks_enabled: false,
            proxy_test: Some(ProxyTestConfig {
                server_addr: target_addr,
                root_store: prover_config.root_store.clone(),
            }),
        };
        let notary_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let notary_addr = notary_listener.local_addr().unwrap();
        let notary_task = tokio::spawn(async move {
            axum::serve(
                notary_listener,
                Router::new()
                    .route("/notarize-proxy", get(notarize_proxy_ws_handler))
                    .with_state(state),
            )
            .await
            .unwrap();
        });

        let (websocket, _) = connect_async(format!("ws://{notary_addr}/notarize-proxy"))
            .await
            .unwrap();
        let (mut ws_tx, mut ws_rx) = websocket.split();
        let (browser_io, pump_io) = tokio::io::duplex(1 << 17);
        let pump_task = tokio::spawn(async move {
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
            let mut prover = SdkProver::new(prover_config).unwrap();
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
        target_task.await.unwrap();
        notary_task.abort();
    }

    /// A client that connects and then goes silent forever must not pin the
    /// handler past [`CONNECTION_DEADLINE`] — defense in depth over the
    /// fail-fast fixes, covering whatever future bug makes a session pend.
    /// Paused time: the runtime auto-advances the clock to the deadline the
    /// moment everything is blocked, so the test finishes in milliseconds.
    #[tokio::test(start_paused = true)]
    async fn silent_connection_hits_the_deadline() {
        use std::sync::Arc;

        use libid_signer::SignerSource;
        use tokio::sync::Semaphore;

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
            proxy_sessions: Arc::new(Semaphore::new(8)),
            jwks_enabled: false,
            proxy_test: None,
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
