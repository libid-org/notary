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
//!   length-prefixed ceremony attestation in its own WebSocket message.
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
use libid_signer::{
    ManagedSigner,
    SignerSource,
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

#[derive(Clone)]
struct NotaryState {
    /// Notary signing identity (local hex key or AWS KMS).
    signer: Arc<ManagedSigner>,
    proxy_sessions: Arc<Semaphore>,
    proxy_root_store: Arc<tlsn::webpki::RootCertStore>,
    /// `None` connects to the TLS-authenticated server name on port 443.
    proxy_server_addr: Option<SocketAddr>,
    public_key_hex: String,
    jwks_enabled: bool,
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
        proxy_root_store: Arc::new(libid_tlsn::root_store()),
        proxy_server_addr: None,
        public_key_hex,
        jwks_enabled: config.jwks_enabled,
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
    let attested = libid_tlsn::attest::attested_data(
        partial,
        authority,
        commitments,
        libid_tlsn::attest::AttestationInput { created_at },
    )
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

async fn notarize_proxy_ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<NotaryState>,
) -> impl IntoResponse {
    let Ok(permit) = Arc::clone(&state.proxy_sessions).try_acquire_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    ws.on_upgrade(move |socket| handle_ws_proxy_notarize(socket, state, permit))
        .into_response()
}

async fn handle_ws_proxy_notarize(
    socket: WebSocket,
    state: NotaryState,
    // Held for the connection lifetime; dropping it returns the session slot.
    _permit: tokio::sync::OwnedSemaphorePermit,
) {
    let (io_a, io_b) = tokio::io::duplex(1 << 17);
    let (mut ws_tx, mut ws_rx) = socket.split();
    let (mut pipe_reader, mut pipe_writer) = tokio::io::split(io_a);

    // Keep inbound and outbound ownership separate. Whichever direction ends
    // first must not cancel a write already accepted in the other direction.
    let (attestation_tx, attestation_rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
    let _inbound_task = AbortOnDrop::new(tokio::spawn(async move {
        while let Some(Ok(msg)) = ws_rx.next().await {
            match msg {
                Message::Binary(data) if pipe_writer.write_all(&data).await.is_err() => {
                    break
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
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
        if let Ok(frame) = attestation_rx.await {
            let _ = ws_tx.send(Message::Binary(frame.into())).await;
        }
        let _ = ws_tx.send(Message::Close(None)).await;
    }));

    let protocol = async {
        let result = match run_proxy_verifier_session(io_b, &state).await {
            Ok(attestation) => attestation_frame(&attestation).and_then(|frame| {
                attestation_tx.send(frame).map_err(|_| Error::NotaryServer {
                    detail: "browser disconnected before attestation handoff".into(),
                })
            }),
            Err(error) => {
                drop(attestation_tx);
                Err(error)
            }
        };
        if let Err(error) = outbound_task.into_inner().await {
            error!("ProxyMode WebSocket outbound pump join error: {error}");
        }
        result
    };

    match tokio::time::timeout(CONNECTION_DEADLINE, protocol).await {
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
) -> Result<AttestationWire>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();
    // Guarded spawn: every exit path below — each `?`, panics, the caller
    // dropping this future — aborts the driver instead of detaching it.
    let driver_task = AbortOnDrop::new(tokio::spawn(driver));

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

        Ok::<_, Error>(Ok((server_name, transcript, transcript_commitments)))
    };
    let setup_outcome = setup.await?;
    let (server_name, transcript, transcript_commitments) = match setup_outcome {
        Ok(output) => output,
        Err(error) => {
            let _ = driver_task.into_inner().await;
            return Err(error);
        }
    };

    let io = driver_task
        .into_inner()
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
        use std::{
            sync::Arc,
            time::Duration,
        };

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

        let signer = SignerSource::from_spec(TEST_KEY)
            .unwrap()
            .build_managed(None)
            .await
            .unwrap();
        let expected_pubkey = signer.compressed_public_key().to_vec();
        let state = NotaryState {
            signer: Arc::new(signer),
            proxy_sessions: Arc::new(tokio::sync::Semaphore::new(1)),
            proxy_root_store: Arc::new(libid_tlsn::root_store()),
            proxy_server_addr: None,
            public_key_hex: String::new(),
            jwks_enabled: false,
        };

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
            notarize_proxy_ws_handler,
            NotaryState,
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
            proxy_root_store: Arc::new(prover_config.root_store.clone()),
            proxy_server_addr: Some(target_addr),
            public_key_hex: String::new(),
            jwks_enabled: false,
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
            proxy_root_store: Arc::new(libid_tlsn::root_store()),
            proxy_server_addr: None,
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
