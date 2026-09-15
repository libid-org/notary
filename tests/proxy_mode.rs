//! ProxyMode end to end: the whole server booted the way `smoke.rs` boots it,
//! a WebSocket client on `/notarize-proxy` driving tlsn's prover core the way
//! the browser does (`tlsn_wasm` is built on `tlsn-sdk-core`), and TLSNotary's
//! own TLS server fixture as the upstream.
//!
//! The fixture rather than a public host: the session is then deterministic
//! and offline. The notary is pointed at it through [`ProxyUpstream`], which
//! `run_with` takes and no flag sets.

use std::{
    net::SocketAddr,
    time::Duration,
};

use futures_util::{
    SinkExt,
    StreamExt,
};
use libid_transcript::{
    read_msg,
    AttestationWire,
};
use notary::{
    server,
    ProxyUpstream,
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
    sync::mpsc,
    task::JoinHandle,
};
use tokio_tungstenite::{
    connect_async,
    tungstenite::Message,
};
use tokio_util::compat::{
    FuturesAsyncReadCompatExt,
    TokioAsyncReadCompatExt,
};

mod common;
use common::{
    assert_attests,
    free_port,
    test_config,
};

/// One TLS server for `SERVER_DOMAIN`, answering a single connection.
async fn fixture() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        tlsn_server_fixture::bind(socket.compat()).await.unwrap();
    });
    addr
}

/// What came down the WebSocket, in order.
#[derive(Debug)]
enum Frame {
    Binary(Vec<u8>),
    Close,
}

/// The browser's transport: a WebSocket to `/notarize-proxy`, pumped into a
/// byte stream the prover core reads and writes -- what `tlsn_wasm` does over a
/// JS WebSocket. The pump ends when the notary closes; join it for the frames.
async fn browser_transport(
    ws_addr: SocketAddr,
) -> (DuplexStream, JoinHandle<Vec<Frame>>) {
    let (websocket, _) = connect_async(format!("ws://{ws_addr}/notarize-proxy"))
        .await
        .expect("WebSocket upgrade on /notarize-proxy");
    let (mut ws_tx, mut ws_rx) = websocket.split();
    let (prover_io, pump_io) = tokio::io::duplex(1 << 17);
    let (frame_tx, mut frame_rx) = mpsc::unbounded_channel();
    let pump = tokio::spawn(async move {
        let (mut pipe_reader, mut pipe_writer) = tokio::io::split(pump_io);
        let ws_to_pipe = async {
            while let Some(Ok(message)) = ws_rx.next().await {
                match message {
                    Message::Binary(data) => {
                        let _ = frame_tx.send(Frame::Binary(data.to_vec()));
                        if pipe_writer.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                    Message::Close(_) => {
                        let _ = frame_tx.send(Frame::Close);
                        let _ = pipe_writer.shutdown().await;
                        break;
                    }
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
        tokio::select! {
            _ = ws_to_pipe => {}
            _ = pipe_to_ws => {}
        }
        drop(frame_tx);
        let mut frames = Vec::new();
        while let Ok(frame) = frame_rx.try_recv() {
            frames.push(frame);
        }
        frames
    });
    (prover_io, pump)
}

fn prover() -> SdkProver {
    SdkProver::new(
        ProverConfig::builder(SERVER_DOMAIN)
            .mode(ProverMode::Proxy)
            .root_certs(vec![CA_CERT_DER.to_vec()])
            .build()
            .unwrap(),
    )
    .unwrap()
}

fn request() -> HttpRequest {
    HttpRequest::get(format!("https://{SERVER_DOMAIN}/bytes?size=16"))
        .header("Host", SERVER_DOMAIN)
        .header("Connection", "close")
}

fn shape(frames: &[Frame]) -> Vec<String> {
    frames
        .iter()
        .map(|frame| match frame {
            Frame::Binary(data) => format!("binary({})", data.len()),
            Frame::Close => "close".into(),
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn proxy_session_ends_in_one_signed_attestation_message() {
    let upstream = fixture().await;
    let handle = server::run_with(
        test_config(free_port().await),
        ProxyUpstream {
            addr: Some(upstream),
            extra_roots: vec![CA_CERT_DER.to_vec()],
        },
    )
    .await
    .expect("server starts");
    let ws_addr = handle.ws_local_addr().expect("ws server enabled");

    // The identity the notary advertises is the one the record must recover to.
    let info: serde_json::Value = reqwest::Client::new()
        .get(format!("http://{ws_addr}/info"))
        .send()
        .await
        .expect("GET /info")
        .json()
        .await
        .expect("info json");
    let notary_pubkey = info["publicKey"].as_str().expect("publicKey").to_string();

    let (prover_io, pump) = browser_transport(ws_addr).await;
    let session = async {
        let mut prover = prover();
        prover
            .setup(prover_io.compat())
            .await
            .expect("ProxyMode setup");
        let response = prover
            .send_request_proxy(request())
            .await
            .expect("request relayed through the notary");
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
            .expect("reveal accepted");

        // The prover core hands the transport back once the session's mux has
        // closed. The attestation is what arrives on it next, and nothing after.
        let mut io = prover.finish().await.expect("session finished").compat();
        let attestation: AttestationWire = read_msg(&mut io)
            .await
            .expect("an attestation follows the session");
        assert_eq!(
            io.read(&mut [0]).await.unwrap(),
            0,
            "bytes after the attestation"
        );
        (transcript, attestation)
    };
    let (transcript, attestation) =
        tokio::time::timeout(Duration::from_secs(30), session)
            .await
            .expect("ProxyMode session timed out");
    let frames = pump.await.unwrap();

    // One length-prefixed frame in its own WebSocket message, then Close.
    let [.., Frame::Binary(last), Frame::Close] = frames.as_slice() else {
        panic!(
            "the WebSocket did not end in one message then Close: {:?}",
            shape(&frames)
        );
    };
    let declared = u32::from_be_bytes(last[..4].try_into().unwrap()) as usize;
    assert_eq!(
        declared,
        last.len() - 4,
        "the attestation frame is split across messages or padded"
    );
    let framed: AttestationWire =
        serde_json::from_slice(&last[4..]).expect("the final message is an attestation");
    assert_eq!(framed.attested_data, attestation.attested_data);
    assert_eq!(framed.notary_signature, attestation.notary_signature);

    assert_attests(
        &attestation,
        SERVER_DOMAIN,
        &transcript.sent,
        &transcript.recv,
        &notary_pubkey,
    );
    handle.shutdown();
}

/// The notary authenticates the upstream itself, at the reveal: the relay is
/// blind to the certificate, so the request goes through, and the session is
/// refused where the server identity is checked. Nothing is signed, and the
/// browser gets a Close with no attestation message before it.
#[tokio::test(flavor = "multi_thread")]
async fn proxy_session_with_an_untrusted_upstream_is_refused_unsigned() {
    let upstream = fixture().await;
    let handle = server::run_with(
        test_config(free_port().await),
        ProxyUpstream {
            addr: Some(upstream),
            extra_roots: Vec::new(),
        },
    )
    .await
    .expect("server starts");
    let ws_addr = handle.ws_local_addr().expect("ws server enabled");

    let (prover_io, pump) = browser_transport(ws_addr).await;
    let mut prover = prover();
    prover
        .setup(prover_io.compat())
        .await
        .expect("ProxyMode setup");
    let response = prover
        .send_request_proxy(request())
        .await
        .expect("the relay itself is blind to the certificate");
    assert_eq!(response.status, 200);
    let transcript = prover.transcript().unwrap();

    // Whether the prover core surfaces the refusal is its own business -- this
    // build leaves `reveal` pending once its transport dies. The notary's is
    // to refuse, close the WebSocket, and sign nothing.
    let reveal = tokio::spawn(async move {
        prover
            .reveal(
                Reveal::new()
                    .sent(0..transcript.sent.len())
                    .recv(0..transcript.recv.len())
                    .server_identity(true),
                None,
            )
            .await
            .map(drop)
    });
    let frames = tokio::time::timeout(Duration::from_secs(30), pump)
        .await
        .expect("the notary did not close the WebSocket after refusing")
        .unwrap();
    assert!(
        matches!(frames.last(), Some(Frame::Close)),
        "the WebSocket did not end in Close: {:?}",
        shape(&frames)
    );
    let signed = frames.iter().any(|frame| match frame {
        Frame::Binary(data) if data.len() > 4 => {
            serde_json::from_slice::<AttestationWire>(&data[4..]).is_ok()
        }
        _ => false,
    });
    assert!(!signed, "an attestation message reached the browser");

    if reveal.is_finished() {
        assert!(
            reveal.await.unwrap().is_err(),
            "the prover core reported an accepted reveal after the refusal"
        );
    } else {
        reveal.abort();
    }
    handle.shutdown();
}
