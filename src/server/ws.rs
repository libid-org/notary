//! ProxyMode WebSocket handler.
//!
//! The browser (prover) connects here as a WebSocket. The notary runs the
//! ProxyMode verifier: it forwards raw TLS bytes between the browser and the
//! target server, authenticates the transcript against the record layer's own
//! tags, then receives the prover's reveal request and captures what the
//! session disclosed.

use std::{
    net::SocketAddr,
    sync::{
        atomic::{
            AtomicBool,
            Ordering,
        },
        Arc,
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
        Response,
    },
};
use futures_util::{
    SinkExt,
    StreamExt,
};
use libid_tlsn::AbortOnDrop;
use libid_transcript::AttestationWire;
use tlsn::{
    config::verifier::VerifierConfig,
    connection::ServerName,
    verifier::{
        VerifierCommitStart,
        VerifierOutput,
    },
    Session,
};
use tokio::io::{
    AsyncReadExt,
    AsyncWriteExt,
};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::{
    error,
    info,
    warn,
};
use tungstenite::protocol::frame::coding::CloseCode;

use super::{
    attestation::attestation_frame,
    NotaryState,
    Tier,
    PROXIED_BY,
};
use crate::{
    client_ip::{
        ClientKey,
        ClientSource,
    },
    error::{
        Error,
        Result,
    },
    limits::{
        CappedIo,
        DataCap,
        RELAY_PIPE_BYTES,
        RELAY_READ_BYTES,
    },
    store::{
        self,
        Dimension,
        LeaseId,
        Store,
        WindowLimits,
    },
};

/// Seconds a refused client is told to wait before its next upgrade.
const RETRY_AFTER_SECS: &str = "60";

/// `/notarize-proxy`: the public route, every per-client limit in force.
pub(super) async fn notarize_proxy_ws_handler(
    ws: WebSocketUpgrade,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    State(state): State<NotaryState>,
) -> Response {
    state
        .admit_proxy_upgrade(Tier::Public, ws, peer, headers)
        .await
}

/// `/internal/notarize-proxy`: our own services, nothing counted per client.
///
/// The route is meant to be unreachable from outside: the load balancer
/// answers 403 for `/internal/*` and this route is only ever reached from
/// inside the cluster. The check here is the backstop for a balancer rule
/// that is missing or wrong, not the control. A balancer always names the
/// client it forwarded for, so a request carrying that header came through
/// one, and is refused before anything else is looked at -- draining, the
/// pool, the upgrade itself.
pub(super) async fn internal_notarize_proxy_ws_handler(
    ws: WebSocketUpgrade,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    State(state): State<NotaryState>,
) -> Response {
    if let Some(header) = PROXIED_BY
        .into_iter()
        .find(|header| headers.contains_key(*header))
    {
        warn!(
            %peer,
            header,
            "ProxyMode (internal): request arrived through a proxy; refused with 403. \
             The load balancer must answer 403 for /internal/* itself"
        );
        return (
            StatusCode::FORBIDDEN,
            "internal route is not served through a proxy",
        )
            .into_response();
    }
    state
        .admit_proxy_upgrade(Tier::Internal, ws, peer, headers)
        .await
}

impl NotaryState {
    /// The checks before a ProxyMode upgrade on `tier`, and the upgrade.
    async fn admit_proxy_upgrade(
        self,
        tier: Tier,
        ws: WebSocketUpgrade,
        peer: SocketAddr,
        headers: axum::http::HeaderMap,
    ) -> Response {
        // In flight from here, before the draining check: admission is two
        // store round trips, and an upgrade inside them when the drain starts
        // must be waited for, not raced. Every refusal below drops the guard.
        let in_flight = self.in_flight.token();

        // Nothing new once the process is stopping; the sessions already
        // running finish, and the balancer has been told by the health check.
        if self.draining.load(Ordering::SeqCst) {
            info!(%peer, "ProxyMode: upgrade refused, notary is draining");
            return (StatusCode::SERVICE_UNAVAILABLE, "notary is draining")
                .into_response();
        }

        // The route is the whole classification. The internal one asks nothing
        // about the client and consults no store: our own services are the
        // protocol, not users of it.
        let client = match tier {
            Tier::Internal => {
                if self.internal_proxy_sessions.available_permits() == 0 {
                    info!(%peer, "ProxyMode (internal): all session slots busy; upgrade refused with 503");
                    return StatusCode::SERVICE_UNAVAILABLE.into_response();
                }
                None
            }
            Tier::Public => match self.admit_public_upgrade(peer, &headers).await {
                Ok(client) => Some(client),
                Err(refusal) => return refusal,
            },
        };

        ws.on_upgrade(move |socket| async move {
            self.handle_ws_proxy_notarize(socket, peer, client).await;
            drop(in_flight);
        })
    }

    /// The public route's checks before an upgrade, cheapest first, and the
    /// client the session counts against if it passes them all. A refusal is the
    /// response to send instead.
    async fn admit_public_upgrade(
        &self,
        peer: SocketAddr,
        headers: &axum::http::HeaderMap,
    ) -> std::result::Result<ClientKey, Response> {
        // Who this session counts against. A refusal here is a refusal, never a
        // fallback to the socket peer: behind a load balancer that peer is the
        // balancer, so falling back would quietly turn the per-client cap into a
        // cap on the whole service.
        let client = match self.client_ip_header.resolve(headers) {
            Ok(client) => client,
            Err(reason) => {
                info!(%peer, %reason, "ProxyMode: upgrade refused, client unidentified");
                return Err((StatusCode::BAD_REQUEST, reason.to_string()).into_response());
            }
        };

        // Refuse rather than queue: a browser retries a refused upgrade cheaply,
        // and nothing has been spent on this session yet.
        //
        // No slot is reserved here; it is taken on the browser's first relayed
        // bytes, so an upgraded socket that stays silent holds nothing.
        if self.proxy_sessions.available_permits() == 0 {
            info!(%peer, "ProxyMode: all session slots busy; upgrade refused with 503");
            return Err(StatusCode::SERVICE_UNAVAILABLE.into_response());
        }

        // Upgrades are counted now, bytes when the session ends. A store that
        // cannot answer is a refusal: a limit that fails open under a store
        // outage is a limit an attacker can switch off.
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
        if !self.per_ip_upgrades.is_empty() {
            match self
                .limits
                .count(&client, Dimension::Upgrades, 1, &self.per_ip_upgrades)
                .await
            {
                Ok(true) => {}
                Ok(false) => return Err(too_many("sessions started")),
                Err(error) => return Err(store_down(error)),
            }
        }
        if !self.per_ip_bytes.is_empty() {
            match self
                .limits
                .would_fit(&client, Dimension::Bytes, 1, &self.per_ip_bytes)
                .await
            {
                Ok(true) => {}
                Ok(false) => return Err(too_many("bytes relayed")),
                Err(error) => return Err(store_down(error)),
            }
        }
        Ok(client)
    }

    /// One ProxyMode session on an upgraded socket. `client` is `Some` on the
    /// public route, where the session holds a lease and its bytes are charged,
    /// and `None` on the internal route, where nothing is counted per client.
    async fn handle_ws_proxy_notarize(
        &self,
        socket: WebSocket,
        peer: SocketAddr,
        client: Option<ClientKey>,
    ) {
        let (mut ws_tx, mut ws_rx) = socket.split();

        // The session starts here, not at the upgrade: a slot is worth spending
        // once there is a session to spend it on.
        let first = match tokio::time::timeout(
            self.setup_deadline,
            first_relayed_bytes(&mut ws_rx),
        )
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
                    self.setup_deadline.as_secs()
                );
                let _ = ws_tx
                    .send(Message::Close(Some(CloseFrame {
                        code: CloseCode::Policy.into(),
                        reason: "no session data within the setup deadline".into(),
                    })))
                    .await;
                return;
            }
        };

        // Every relayed byte counts against the session cap on both tiers -- it
        // is what bounds a transcript, not a rate -- and on the public tier the
        // total is charged to the client when the session ends.
        let relayed = DataCap::new(self.proxy_max_bytes);

        // This client's own lease first: one client at its cap must not spend a
        // slot from the shared pool to find that out. Held for the session
        // lifetime, like the pool permit below.
        let (pool, accounting) = match client {
            None => (&self.internal_proxy_sessions, None),
            Some(client) => {
                let lease = if self.max_sessions_per_ip == 0 {
                    None
                } else {
                    match self
                        .limits
                        .try_lease(
                            &client,
                            self.max_sessions_per_ip,
                            self.connection_deadline,
                        )
                        .await
                    {
                        Ok(Some(lease)) => Some(lease),
                        Ok(None) => {
                            info!(
                                %peer, %client,
                                "ProxyMode: client already running {} sessions; refused with 1013",
                                self.max_sessions_per_ip
                            );
                            let _ = ws_tx
                                .send(Message::Close(Some(CloseFrame {
                                    code: CloseCode::Again.into(),
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
                                    code: CloseCode::Again.into(),
                                    reason: "limits store unavailable".into(),
                                })))
                                .await;
                            return;
                        }
                    }
                };
                let accounting = Accounting::new(self, client, lease, &relayed);
                (&self.proxy_sessions, Some(accounting))
            }
        };

        // Held for the session lifetime; dropping it returns the slot.
        let Ok(permit) = Arc::clone(pool).try_acquire_owned() else {
            info!(%peer, "ProxyMode: all session slots busy; session refused with 1013");
            let _ = ws_tx
                .send(Message::Close(Some(CloseFrame {
                    code: CloseCode::Again.into(),
                    reason: "notary is at capacity; retry".into(),
                })))
                .await;
            if let Some(accounting) = accounting {
                accounting.settle().await;
            }
            return;
        };

        let (io_a, io_b) = tokio::io::duplex(RELAY_PIPE_BYTES);
        let (mut pipe_reader, mut pipe_writer) = tokio::io::split(io_a);

        // Keep inbound and outbound ownership separate. Whichever direction ends
        // first must not cancel a write already accepted in the other direction.
        let (end_tx, end_rx) = tokio::sync::oneshot::channel::<SessionEnd>();
        let inbound_task = AbortOnDrop::new(tokio::spawn(async move {
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
            // The browser is gone: shut the pipe so the session reads EOF and
            // frees its slot now. Dropping the write half alone would not -- the
            // outbound pump's read half keeps the pipe open to the deadline.
            let _ = pipe_writer.shutdown().await;
        }));
        let outbound_task = AbortOnDrop::new(tokio::spawn(async move {
            let mut buf = vec![0u8; RELAY_READ_BYTES];
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
            let result = match self.run_proxy_verifier_session(io_b, &relayed).await {
                Ok(attestation) => match attestation_frame(&attestation).await {
                    Ok(frame) => end_tx.send(SessionEnd::Attested(frame)).map_err(|_| {
                        Error::NotaryServer {
                            detail: "browser disconnected before attestation handoff"
                                .into(),
                        }
                    }),
                    Err(error) => Err(error),
                },
                Err(Error::ProxyDataCapExceeded {
                    authority,
                    used,
                    limit,
                }) => {
                    // The browser must learn it was the cap and not the network;
                    // a bare drop would look like any other failure. Fits the
                    // 123-byte reason budget with room to spare.
                    let _ = end_tx.send(SessionEnd::Aborted(CloseFrame {
                        code: CloseCode::Policy.into(),
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

        match tokio::time::timeout(self.connection_deadline, protocol).await {
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
                self.connection_deadline.as_secs()
            ),
        }

        if let Some(accounting) = accounting {
            accounting.settle().await;
        }
        drop(inbound_task);
        drop(permit);
    }

    /// The verifier's half of one ProxyMode session on `socket`; every byte
    /// relayed to the server counts against `relayed`.
    async fn run_proxy_verifier_session<T>(
        &self,
        socket: T,
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
                        .root_store(self.proxy_root_store.as_ref().clone())
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

            let server_name_str =
                proxy_verifier.config().server_name().as_str().to_string();
            info!("ProxyMode: connecting to {server_name_str}:443");

            let server_addr = self
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

        // The host is attested, not restricted: the record carries the
        // cert-verified name as `authorityId`, and the contract that reads it
        // pins the authority its profile expects.
        let server_name = server_name.ok_or_else(|| Error::NotaryServer {
            detail: "prover did not reveal server name".into(),
        })?;
        let ServerName::Dns(ref dns_name) = server_name;
        let domain = dns_name.as_str().to_string();

        let partial_transcript = transcript;
        if let Some(ref pt) = partial_transcript {
            info!(
                "ProxyMode verified: {} sent, {} recv bytes for {domain}",
                pt.sent_unsafe().len(),
                pt.received_unsafe().len()
            );
        } else {
            info!(
                "ProxyMode verified: no transcript revealed for {domain} (commits only)"
            );
        }

        // What the prover revealed is not read or judged here: which ranges a
        // profile expects is the Platform Verifier's (REQ-COMMON-51).
        let Some(partial) = partial_transcript else {
            return Err(Error::NotaryServer {
                detail: "session revealed no transcript".into(),
            });
        };

        let attestation = self
            .attest(&partial, dns_name.as_str(), &transcript_commitments)
            .await?;
        info!("ProxyMode: attestation ready for {domain}");
        Ok(attestation)
    }
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
    bill: Option<Bill>,
}

/// The client a public session ran as, the lease it held, and the bytes it
/// relayed, with the store and the windows they are charged to.
struct Bill {
    store: Store,
    client: ClientKey,
    lease: Option<LeaseId>,
    relayed: Arc<DataCap>,
    windows: WindowLimits,
}

impl Accounting {
    /// `client`'s session on `state`, holding `lease`, with its relayed
    /// bytes counted in `relayed`.
    fn new(
        state: &NotaryState,
        client: ClientKey,
        lease: Option<LeaseId>,
        relayed: &Arc<DataCap>,
    ) -> Self {
        Self {
            bill: Some(Bill {
                store: state.limits.clone(),
                client,
                lease,
                relayed: Arc::clone(relayed),
                windows: state.per_ip_bytes.clone(),
            }),
        }
    }

    async fn settle(mut self) {
        if let Some(bill) = self.bill.take() {
            bill.settle().await;
        }
    }
}

impl Drop for Accounting {
    fn drop(&mut self) {
        let Some(bill) = self.bill.take() else {
            return;
        };
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                runtime.spawn(bill.settle());
            }
            // The runtime itself is going away; the lease expires by itself.
            Err(_) => {
                warn!(client = %bill.client, "ProxyMode: no runtime to settle a session's accounting")
            }
        }
    }
}

impl Bill {
    async fn settle(self) {
        let used = self.relayed.used();
        if used > 0 {
            if let Err(error) = self
                .store
                .charge(&self.client, Dimension::Bytes, used as u64, &self.windows)
                .await
            {
                warn!(client = %self.client, used, %error, "ProxyMode: relayed bytes not charged");
            }
        }
        if let Some(lease) = self.lease {
            if let Err(error) = self.store.release(&lease).await {
                warn!(client = %self.client, %error, "ProxyMode: session lease not released; it expires by itself");
            }
        }
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

#[cfg(test)]
mod tests {
    use crate::server::tests::ONE_SESSION_AT_A_TIME;

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
            NotaryState,
            Tier,
        };
        use crate::server::routes::router;

        const TEST_KEY: &str =
            "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

        let session_slot = ONE_SESSION_AT_A_TIME.lock().await;
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
        // The protocol is the same on both tiers; the internal route asks
        // nothing about the client.
        let notary_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let notary_addr = notary_listener.local_addr().unwrap();
        let notary_task = tokio::spawn(async move {
            axum::serve(
                notary_listener,
                router(state, true).into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });

        let (websocket, _) =
            connect_async(format!("ws://{notary_addr}{}", Tier::Internal.route()))
                .await
                .unwrap();
        let (mut ws_tx, mut ws_rx) = websocket.split();
        let (browser_io, pump_io) = tokio::io::duplex(crate::limits::RELAY_PIPE_BYTES);
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
                let mut buf = vec![0u8; crate::limits::RELAY_READ_BYTES];
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
        let (websocket, _) =
            connect_async(format!("ws://{notary_addr}{}", Tier::Internal.route()))
                .await
                .unwrap();
        let (mut ws_tx, mut ws_rx) = websocket.split();
        let (browser_io, pump_io) = tokio::io::duplex(crate::limits::RELAY_PIPE_BYTES);
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
                let mut buf = vec![0u8; crate::limits::RELAY_READ_BYTES];
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
        drop(session_slot);
    }

    /// The limits an operator sets, tripped for real: the ProxyMode data cap.
    /// (The ProxyMode 503 and the flag parsing are integration tests in
    /// `tests/resource_limits.rs`, through the public surface.)
    mod limits {
        use std::{
            net::SocketAddr,
            sync::Arc,
            time::Duration,
        };

        use futures_util::{
            SinkExt,
            StreamExt,
        };
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

        use super::super::{
            store::{
                Dimension,
                LeaseId,
                StoreError,
            },
            AttestationWire,
            ClientKey,
            NotaryState,
            Store,
            Tier,
            WindowLimits,
        };
        use crate::{
            server::{
                routes::router,
                tests::{
                    test_signer,
                    ONE_SESSION_AT_A_TIME,
                },
            },
            store::LimitStore,
        };

        /// What the browser saw of one ProxyMode WebSocket: every binary
        /// message, and the close frame if the notary sent one.
        struct BrowserSide {
            binary: Vec<Vec<u8>>,
            close: Option<(u16, String)>,
        }

        /// The client a session on `tier` is opened as: named in
        /// `X-Forwarded-For` on the public route, as the load balancer
        /// would; nothing on the internal route, which refuses the header.
        fn client_on(tier: Tier) -> Option<&'static str> {
            match tier {
                Tier::Public => Some("203.0.113.7"),
                Tier::Internal => None,
            }
        }

        /// The upgrade request for `tier`'s route on `notary_addr`, naming
        /// the client in `X-Forwarded-For` when the tier has one.
        fn upgrade_from(
            notary_addr: SocketAddr,
            tier: Tier,
        ) -> tokio_tungstenite::tungstenite::http::Request<()> {
            let mut request = format!("ws://{notary_addr}{}", tier.route())
                .into_client_request()
                .unwrap();
            if let Some(client) = client_on(tier) {
                request
                    .headers_mut()
                    .insert("x-forwarded-for", HeaderValue::from_str(client).unwrap());
            }
            request
        }

        /// Open a ProxyMode WebSocket on `tier`'s route and pump it to and
        /// from a duplex the prover drives, the way tlsn_wasm's transport
        /// does in the browser.
        async fn browser(
            notary_addr: SocketAddr,
            tier: Tier,
        ) -> (DuplexStream, tokio::task::JoinHandle<BrowserSide>) {
            let (websocket, _) = connect_async(upgrade_from(notary_addr, tier))
                .await
                .unwrap();
            let (mut ws_tx, mut ws_rx) = websocket.split();
            let (browser_io, pump_io) =
                tokio::io::duplex(crate::limits::RELAY_PIPE_BYTES);
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
                    let mut buf = vec![0u8; crate::limits::RELAY_READ_BYTES];
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

        /// Serve `router(state, true)` -- both routes -- on an ephemeral
        /// port; the task is aborted by the test that spawned it.
        async fn serve(state: NotaryState) -> (SocketAddr, tokio::task::JoinHandle<()>) {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let task = tokio::spawn(async move {
                axum::serve(
                    listener,
                    router(state, true)
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
            state.limits = Store::from(ParkedStore(Arc::clone(&gate)));
            let in_flight = state.in_flight.clone();
            let (notary_addr, notary_task) = serve(state).await;

            let upgrade = tokio::spawn(async move {
                connect_async(upgrade_from(notary_addr, Tier::Public))
                    .await
                    .expect("the upgrade is admitted once the store answers")
            });
            tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
                .await
                .expect("admission never asked the store");
            assert_eq!(
                in_flight.len(),
                1,
                "an upgrade inside admission is in flight"
            );

            // Let admission through; the socket is dropped unstarted, and
            // the handler's return takes the connection out of flight.
            gate.go.add_permits(2);
            let (socket, _) = upgrade.await.unwrap();
            drop(socket);
            let idle = async {
                while !in_flight.is_empty() {
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
        /// per session on both tiers; the internal route needs no client.
        #[tokio::test(flavor = "multi_thread")]
        async fn proxy_session_over_the_data_cap_is_aborted_without_attestation() {
            let session_slot = ONE_SESSION_AT_A_TIME.lock().await;
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
            let (notary_addr, notary_task) = serve(state).await;

            let (browser_io, mut pump) = browser(notary_addr, Tier::Internal).await;
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
            drop(session_slot);
        }

        /// A public WebSocket upgrade as an HTTP client sends it, so a
        /// refusal's status and body can be read whole: tungstenite keeps
        /// only what arrived in the same read as the headers.
        async fn upgrade_request(notary_addr: SocketAddr) -> reqwest::Response {
            reqwest::Client::new()
                .get(format!("http://{notary_addr}{}", Tier::Public.route()))
                .header("x-forwarded-for", client_on(Tier::Public).unwrap())
                .header("connection", "upgrade")
                .header("upgrade", "websocket")
                .header("sec-websocket-version", "13")
                .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
                .send()
                .await
                .expect("the notary answers the upgrade")
        }

        /// One complete ProxyMode session against the fixture server, on
        /// `tier`'s route: the browser's request, its reveal,
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
            let (notary_addr, notary_task) = serve(state).await;

            let (browser_io, pump) = browser(notary_addr, tier).await;
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
            let session_slot = ONE_SESSION_AT_A_TIME.lock().await;
            let mut state = NotaryState::for_tests(test_signer().await);
            state.per_ip_bytes = "1KB/1h".parse::<WindowLimits>().unwrap();
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
            drop(session_slot);
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

        /// A store the internal route must never reach: every call panics,
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
                panic!("the internal route asked the store for a lease")
            }

            async fn release(&self, _: &LeaseId) -> std::result::Result<(), StoreError> {
                panic!("the internal route released a lease")
            }

            async fn count(
                &self,
                _: &ClientKey,
                _: Dimension,
                _: u64,
                _: &WindowLimits,
            ) -> std::result::Result<bool, StoreError> {
                panic!("the internal route counted in the store")
            }

            async fn would_fit(
                &self,
                _: &ClientKey,
                _: Dimension,
                _: u64,
                _: &WindowLimits,
            ) -> std::result::Result<bool, StoreError> {
                panic!("the internal route asked the store for room")
            }

            async fn charge(
                &self,
                _: &ClientKey,
                _: Dimension,
                _: u64,
                _: &WindowLimits,
            ) -> std::result::Result<(), StoreError> {
                panic!("the internal route charged the store")
            }

            async fn sweep(&self) -> std::result::Result<u64, StoreError> {
                panic!("the internal route swept the store")
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
                state.limits = Store::from(DownStore);
                state.per_ip_upgrades = upgrades.parse::<WindowLimits>().unwrap();
                state.per_ip_bytes = bytes.parse::<WindowLimits>().unwrap();
                let (notary_addr, notary_task) = serve(state).await;

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
            state.limits = Store::from(DownStore);
            state.per_ip_upgrades = WindowLimits::default();
            state.per_ip_bytes = WindowLimits::default();
            let (notary_addr, notary_task) = serve(state).await;

            let (mut socket, _) = connect_async(upgrade_from(notary_addr, Tier::Public))
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
            assert_eq!(
                u16::from(frame.code),
                u16::from(CloseCode::Again),
                "reason: {}",
                frame.reason
            );
            assert_eq!(frame.reason, "limits store unavailable");

            notary_task.abort();
        }

        /// The internal route never touches the store: a full session
        /// completes, attestation and all, against a store that panics on
        /// every call.
        #[tokio::test(flavor = "multi_thread")]
        async fn the_internal_route_never_touches_the_store() {
            let session_slot = ONE_SESSION_AT_A_TIME.lock().await;
            let mut state = NotaryState::for_tests(test_signer().await);
            state.limits = Store::from(PanickingStore);
            let (_, seen, notary_task) = complete_session(Tier::Internal, state).await;
            assert!(
                seen.close.is_none(),
                "the session did not end cleanly: {:?}",
                seen.close
            );
            notary_task.abort();
            drop(session_slot);
        }
    }
}
