//! The port is the classifier: what the internal HTTP listener does not
//! count, what both listeners answer on `/healthcheck`, how a store that
//! cannot be reached fails the start, and what SIGTERM does to the real
//! binary.

use std::{
    process::{
        Child,
        Command,
        Stdio,
    },
    time::Duration,
};

use clap::Parser;
use futures_util::{
    SinkExt,
    StreamExt,
};
use notary::{
    server,
    NotaryServerConfig,
};
use tokio::io::AsyncWriteExt;
use tokio_tungstenite::{
    connect_async,
    tungstenite,
    tungstenite::{
        client::IntoClientRequest,
        http::HeaderValue,
        Message,
    },
};

/// anvil #0 — public test key.
const TEST_KEY: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

type Socket = tokio_tungstenite::WebSocketStream<
    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
>;

/// The CLI as `main` parses it, on top of the signing key alone.
fn parse(args: &[&str]) -> NotaryServerConfig {
    let mut all = vec!["notary", "--signing-key", TEST_KEY];
    all.extend_from_slice(args);
    NotaryServerConfig::parse_from(all)
}

/// Reserve an ephemeral port for the public HTTP server: ws_port 0 means
/// "disabled", so bind-then-drop to learn a free port number.
async fn free_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

/// Open a ProxyMode session and start it, the way the browser does, naming
/// `client` in `X-Forwarded-For` as the load balancer would.
async fn session_from(url: &str, client: &str) -> Result<Socket, tungstenite::Error> {
    let mut request = url.into_client_request().unwrap();
    request
        .headers_mut()
        .insert("x-forwarded-for", HeaderValue::from_str(client).unwrap());
    let (mut socket, _) = connect_async(request).await?;
    socket
        .send(Message::Binary(b"\x16\x03\x01".to_vec().into()))
        .await
        .expect("the browser sends its first TLS bytes");
    Ok(socket)
}

/// The session is still running `wait` later: the notary may talk on the
/// socket -- its session does -- but has not closed it.
async fn holds(socket: &mut Socket, wait: Duration) -> bool {
    let closed = async {
        loop {
            match socket.next().await {
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => return,
                Some(Ok(_)) => {}
            }
        }
    };
    tokio::time::timeout(wait, closed).await.is_err()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_internal_http_listener_is_off_unless_configured() {
    let handle = server::run(parse(&["--ws-port", "0"]))
        .await
        .expect("server starts");
    assert!(handle.internal_ws_local_addr().is_none());
    assert!(handle.ws_local_addr().is_none());
    handle.shutdown();

    let handle = server::run(parse(&["--ws-port", "0", "--internal-ws-port", "0"]))
        .await
        .expect("server starts");
    let addr = handle
        .internal_ws_local_addr()
        .expect("an ephemeral internal port");
    assert_ne!(addr.port(), 0);
    handle.shutdown();
}

/// Every per-client limit is on and set to one; the internal port ignores
/// all of them, and the public port refuses the second session -- at the
/// upgrade, with 429, because the upgrades window is checked before the
/// session's lease is taken.
#[tokio::test(flavor = "multi_thread")]
async fn the_internal_port_counts_nothing_per_client() {
    let ws_port = free_port().await;
    let config = parse(&[
        "--ws-port",
        &ws_port.to_string(),
        "--internal-ws-port",
        "0",
        "--max-sessions-per-ip",
        "1",
        "--per-ip-upgrades",
        "1/1h",
        "--per-ip-bytes",
        "1KB/1h",
    ]);
    let handle = server::run(config).await.expect("server starts");
    let internal = format!(
        "ws://{}/notarize-proxy",
        handle.internal_ws_local_addr().unwrap()
    );
    let public = format!("ws://{}/notarize-proxy", handle.ws_local_addr().unwrap());

    // Three at once from one peer, all past the upgrade and the first
    // frame, and all still running: no lease, no window, no header read.
    let mut internal_sessions = Vec::new();
    for n in 1..=3 {
        let socket = session_from(&internal, "203.0.113.7")
            .await
            .unwrap_or_else(|e| panic!("internal session {n}: {e}"));
        internal_sessions.push(socket);
    }
    for (n, socket) in internal_sessions.iter_mut().enumerate() {
        assert!(
            holds(socket, Duration::from_millis(300)).await,
            "internal session {} was refused or closed",
            n + 1
        );
    }

    // The same client on the public port: one session, then 429.
    let mut first = session_from(&public, "203.0.113.7")
        .await
        .expect("the first public session");
    assert!(holds(&mut first, Duration::from_millis(300)).await);
    let refused = session_from(&public, "203.0.113.7")
        .await
        .expect_err("a second public session from one client must be refused");
    let tungstenite::Error::Http(response) = refused else {
        panic!("expected an HTTP refusal, got: {refused}");
    };
    assert_eq!(response.status(), 429);
    assert_eq!(
        response
            .headers()
            .get("retry-after")
            .map(|v| v.to_str().unwrap()),
        Some("60")
    );

    // Still nothing on the internal side has been touched by it.
    for socket in internal_sessions.iter_mut() {
        assert!(holds(socket, Duration::from_millis(100)).await);
    }

    handle.shutdown();
}

/// A store that cannot be reached is a startup error naming the store, not
/// a notary that comes up and refuses every public client.
#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_limits_store_fails_the_start() {
    let ws_port = free_port().await;
    let config = parse(&[
        "--host",
        "0.0.0.0",
        "--ws-port",
        &ws_port.to_string(),
        "--limits-store",
        "postgres://127.0.0.1:1/x",
    ]);
    let error = server::run(config)
        .await
        .err()
        .expect("an unreachable store must not start the notary")
        .to_string();
    assert!(error.contains("limits store"), "{error}");
    assert!(error.contains("postgres://127.0.0.1:1/x"), "{error}");
}

#[tokio::test(flavor = "multi_thread")]
async fn healthcheck_is_ok_on_both_listeners() {
    let ws_port = free_port().await;
    let handle = server::run(parse(&[
        "--ws-port",
        &ws_port.to_string(),
        "--internal-ws-port",
        "0",
    ]))
    .await
    .expect("server starts");
    let client = reqwest::Client::new();
    for addr in [
        handle.ws_local_addr().unwrap(),
        handle.internal_ws_local_addr().unwrap(),
    ] {
        let response = client
            .get(format!("http://{addr}/healthcheck"))
            .send()
            .await
            .expect("GET /healthcheck");
        assert_eq!(response.status(), 200, "{addr}");
        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(body["status"], "ok", "{addr}");
    }
    handle.shutdown();
}

/// The three listeners of a spawned notary, on ports reserved up front:
/// its stdout is not read, so ephemeral ports could not be learned.
struct Ports {
    mpc: u16,
    public: u16,
    internal: u16,
}

impl Ports {
    async fn free() -> Self {
        Self {
            mpc: free_port().await,
            public: free_port().await,
            internal: free_port().await,
        }
    }

    fn ws(&self, port: u16) -> String {
        format!("ws://127.0.0.1:{port}/notarize-proxy")
    }
}

/// The real binary, on `ports`, with the memory store; returns once its
/// public health check answers 200.
async fn spawn_notary(ports: &Ports) -> Spawned {
    let notary = Spawned(
        Command::new(env!("CARGO_BIN_EXE_notary"))
            .args([
                "--host",
                "127.0.0.1",
                "--port",
                &ports.mpc.to_string(),
                "--ws-port",
                &ports.public.to_string(),
                "--internal-ws-port",
                &ports.internal.to_string(),
                "--limits-store",
                "memory",
                "--signing-key",
                TEST_KEY,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("the notary binary starts"),
    );
    let up = async {
        loop {
            if health(ports.public).await == Some(200) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(20), up)
        .await
        .expect("the notary never answered its health check");
    notary
}

/// The health check's status on `port`, or `None` while nothing answers.
async fn health(port: u16) -> Option<u16> {
    reqwest::Client::new()
        .get(format!("http://127.0.0.1:{port}/healthcheck"))
        .send()
        .await
        .ok()
        .map(|r| r.status().as_u16())
}

/// Wait for the health check to say `draining`, within 2s of the signal.
async fn until_draining(port: u16) {
    let draining = async {
        while health(port).await != Some(503) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let body: serde_json::Value = reqwest::Client::new()
            .get(format!("http://127.0.0.1:{port}/healthcheck"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(body["status"], "draining");
    };
    tokio::time::timeout(Duration::from_secs(2), draining)
        .await
        .expect("the health check did not flip to 503 within 2s of SIGTERM");
}

/// A ProxyMode session past its first frame on `url`: the drain must wait
/// for it. `client` is named in `X-Forwarded-For`, which the public port
/// requires and the internal port never reads.
async fn ws_session(url: &str, client: Option<&str>) -> Socket {
    let mut request = url.into_client_request().unwrap();
    if let Some(client) = client {
        request
            .headers_mut()
            .insert("x-forwarded-for", HeaderValue::from_str(client).unwrap());
    }
    let (mut socket, _) = connect_async(request).await.expect("upgrade");
    socket
        .send(Message::Binary(b"\x16\x03\x01".to_vec().into()))
        .await
        .unwrap();
    assert!(holds(&mut socket, Duration::from_millis(200)).await);
    socket
}

/// The process's exit status within `within`, or a panic.
async fn exit_status(notary: &mut Spawned, within: Duration) -> std::process::ExitStatus {
    let exited = async {
        loop {
            if let Some(status) = notary.0.try_wait().unwrap() {
                return status;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    tokio::time::timeout(within, exited)
        .await
        .unwrap_or_else(|_| panic!("the notary did not exit within {within:?}"))
}

/// Which listener's session is the last one a drain waits for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Last {
    Public,
    Internal,
    Mpc,
}

/// The real binary under SIGTERM: the health check flips to 503 at once,
/// new upgrades are refused with 503, and the process exits -- with 0 --
/// only once the last session has ended. One session is held on every
/// listener, the other two are closed first, and `last` alone must keep
/// the process alive: each listener's sessions are counted on their own.
async fn sigterm_drains_then_exits_zero(last: Last) {
    let ports = Ports::free().await;
    let mut notary = spawn_notary(&ports).await;

    // One session on every listener, each past the point where it counts:
    // the browser's first frame on both HTTP ports, the prover's first byte
    // on the MPC port.
    let mut public = Some(ws_session(&ports.ws(ports.public), Some("203.0.113.7")).await);
    let mut internal = Some(ws_session(&ports.ws(ports.internal), None).await);
    let mut mpc = tokio::net::TcpStream::connect(("127.0.0.1", ports.mpc))
        .await
        .expect("MPC connect");
    mpc.write_all(b"\x16")
        .await
        .expect("the prover's first byte");
    let mut mpc = Some(mpc);
    tokio::time::sleep(Duration::from_millis(100)).await;

    notary.signal(libc::SIGTERM);
    until_draining(ports.public).await;
    assert!(
        notary.0.try_wait().unwrap().is_none(),
        "the notary exited with sessions still in flight"
    );

    // Nothing new is taken while draining -- and the listener is still
    // open to say so, because a closed port reads as a crash. The client is
    // named, so the draining check is the only thing that can refuse.
    let mut request = ports.ws(ports.public).into_client_request().unwrap();
    request
        .headers_mut()
        .insert("x-forwarded-for", HeaderValue::from_static("203.0.113.7"));
    let refused = connect_async(request)
        .await
        .expect_err("a new session was accepted while draining");
    let tungstenite::Error::Http(response) = refused else {
        panic!("expected an HTTP 503 while draining, got: {refused}");
    };
    assert_eq!(response.status(), 503);
    assert!(
        holds(public.as_mut().unwrap(), Duration::from_millis(200)).await,
        "the public session in flight was cut off by the drain"
    );
    assert!(
        holds(internal.as_mut().unwrap(), Duration::from_millis(200)).await,
        "the internal session in flight was cut off by the drain"
    );

    // Everything but `last` ends; `last` alone keeps the process alive.
    let mut end = |which: Last| match which {
        Last::Public => drop(public.take()),
        Last::Internal => drop(internal.take()),
        Last::Mpc => drop(mpc.take()),
    };
    for which in [Last::Public, Last::Internal, Last::Mpc] {
        if which != last {
            end(which);
        }
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        notary.0.try_wait().unwrap().is_none(),
        "the notary exited with a {last:?} session still in flight"
    );

    end(last);
    let status = exit_status(&mut notary, Duration::from_secs(5)).await;
    assert!(status.success(), "exit status: {status}");
}

#[tokio::test(flavor = "multi_thread")]
async fn sigterm_waits_for_the_public_session_then_exits_zero() {
    sigterm_drains_then_exits_zero(Last::Public).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sigterm_waits_for_the_internal_session_then_exits_zero() {
    sigterm_drains_then_exits_zero(Last::Internal).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sigterm_waits_for_the_mpc_session_then_exits_zero() {
    sigterm_drains_then_exits_zero(Last::Mpc).await;
}

/// A second SIGTERM while draining is an operator who will not wait: the
/// process exits at once, still with 0, and the session it was waiting for
/// is cut off. Any session will do; the internal port's needs no client.
#[tokio::test(flavor = "multi_thread")]
async fn a_second_sigterm_exits_zero_without_waiting() {
    let ports = Ports::free().await;
    let mut notary = spawn_notary(&ports).await;
    let mut holder = ws_session(&ports.ws(ports.internal), None).await;

    notary.signal(libc::SIGTERM);
    until_draining(ports.public).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        notary.0.try_wait().unwrap().is_none(),
        "one SIGTERM must wait for the session in flight"
    );

    notary.signal(libc::SIGTERM);
    let status = exit_status(&mut notary, Duration::from_secs(2)).await;
    assert!(status.success(), "exit status: {status}");
    assert!(
        !holds(&mut holder, Duration::from_secs(2)).await,
        "the session outlived the process"
    );
}

/// The spawned notary, killed if the test fails before it exits.
struct Spawned(Child);

impl Spawned {
    fn signal(&self, signal: libc::c_int) {
        let pid = libc::pid_t::try_from(self.0.id()).expect("a pid");
        // SAFETY: kill(2) on a pid this test spawned and still owns.
        let rc = unsafe { libc::kill(pid, signal) };
        assert_eq!(rc, 0, "kill: {}", std::io::Error::last_os_error());
    }
}

impl Drop for Spawned {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
