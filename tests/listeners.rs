//! The route is the classifier: when the internal ProxyMode route exists,
//! what it refuses and what it does not count, how a store that cannot be
//! reached fails the start, and what SIGTERM does to the real binary.

mod common;

use std::{
    io::Read,
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
use tokio::{
    io::{
        AsyncReadExt,
        AsyncWriteExt,
    },
    net::TcpStream,
};
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

/// The public ProxyMode route on `addr`.
fn public_url(addr: impl std::fmt::Display) -> String {
    format!("ws://{addr}/notarize-proxy")
}

/// The internal ProxyMode route, on the same port as the public one.
fn internal_url(addr: impl std::fmt::Display) -> String {
    format!("ws://{addr}/internal/notarize-proxy")
}

/// Open a ProxyMode session and start it, the way the browser does, naming
/// `client` in `X-Forwarded-For` as the load balancer would -- or naming
/// nobody, as a service inside the cluster does on the internal route.
async fn session_from(
    url: &str,
    client: Option<&str>,
) -> Result<Socket, tungstenite::Error> {
    let mut request = url.into_client_request().unwrap();
    if let Some(client) = client {
        request
            .headers_mut()
            .insert("x-forwarded-for", HeaderValue::from_str(client).unwrap());
    }
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

/// How an upgrade was refused, as the browser sees it.
fn refusal(error: tungstenite::Error) -> (u16, String) {
    let tungstenite::Error::Http(response) = error else {
        panic!("expected an HTTP refusal, got: {error}");
    };
    let body = response
        .body()
        .as_deref()
        .map(|body| String::from_utf8_lossy(body).into_owned())
        .unwrap_or_default();
    (response.status().as_u16(), body)
}

/// Without `--internal-proxy-route` the internal route does not exist: a
/// 404 like any other path, header or no header.
#[tokio::test(flavor = "multi_thread")]
async fn the_internal_route_is_absent_unless_configured() {
    let (handle, _) =
        common::start_server(|ws_port| parse(&["--ws-port", &ws_port.to_string()])).await;
    let internal = internal_url(handle.ws_local_addr().unwrap());

    for client in [None, Some("203.0.113.7")] {
        let (status, _) = refusal(
            session_from(&internal, client)
                .await
                .expect_err("the internal route must not exist"),
        );
        assert_eq!(status, 404, "client {client:?}");
    }
    handle.shutdown();
}

/// With `--internal-proxy-route` the route admits a request that came from
/// inside the cluster -- no forwarding header -- and refuses one that came
/// through a proxy, whichever header the proxy set, with 403 and a body
/// that names the rule. The balancer is meant to answer that 403 itself;
/// this is the backstop.
#[tokio::test(flavor = "multi_thread")]
async fn the_internal_route_refuses_a_proxied_request_and_admits_a_direct_one() {
    let (handle, _) = common::start_server(|ws_port| {
        parse(&["--ws-port", &ws_port.to_string(), "--internal-proxy-route"])
    })
    .await;
    let internal = internal_url(handle.ws_local_addr().unwrap());

    for header in ["x-forwarded-for", "cf-connecting-ip"] {
        let mut request = internal.as_str().into_client_request().unwrap();
        request
            .headers_mut()
            .insert(header, HeaderValue::from_static("203.0.113.7"));
        let (status, body) = refusal(
            connect_async(request)
                .await
                .expect_err("a proxied request must be refused"),
        );
        assert_eq!(status, 403, "{header}");
        assert_eq!(
            body, "internal route is not served through a proxy",
            "{header}"
        );
    }

    let mut direct = session_from(&internal, None)
        .await
        .expect("a direct request is admitted");
    assert!(
        holds(&mut direct, Duration::from_millis(300)).await,
        "the direct session was closed"
    );
    handle.shutdown();
}

/// The route rides the public port, so asking for it with that port off is
/// a configuration that cannot mean anything: a startup error, not a
/// notary that comes up without the route it was told to serve.
#[tokio::test(flavor = "multi_thread")]
async fn the_internal_route_needs_the_public_port() {
    let error = server::run(parse(&["--ws-port", "0", "--internal-proxy-route"]))
        .await
        .err()
        .expect("--internal-proxy-route with --ws-port 0 must not start")
        .to_string();
    assert!(error.contains("--internal-proxy-route"), "{error}");
    assert!(error.contains("--ws-port 0"), "{error}");
}

/// Every per-client limit is on and set to one; the internal route ignores
/// all of them, and the public route refuses the second session -- at the
/// upgrade, with 429, because the upgrades window is checked before the
/// session's lease is taken.
#[tokio::test(flavor = "multi_thread")]
async fn the_internal_route_counts_nothing_per_client() {
    let (handle, _) = common::start_server(|ws_port| {
        parse(&[
            "--ws-port",
            &ws_port.to_string(),
            "--internal-proxy-route",
            "--max-sessions-per-ip",
            "1",
            "--per-ip-upgrades",
            "1/1h",
            "--per-ip-bytes",
            "1KB/1h",
        ])
    })
    .await;
    let internal = internal_url(handle.ws_local_addr().unwrap());
    let public = public_url(handle.ws_local_addr().unwrap());

    // Three at once from one peer, all past the upgrade and the first
    // frame, and all still running: no lease, no window, no header.
    let mut internal_sessions = Vec::new();
    for n in 1..=3 {
        let socket = session_from(&internal, None)
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

    // One client on the public route: one session, then 429.
    let mut first = session_from(&public, Some("203.0.113.7"))
        .await
        .expect("the first public session");
    assert!(holds(&mut first, Duration::from_millis(300)).await);
    let refused = session_from(&public, Some("203.0.113.7"))
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
    let ws_port = common::free_port().await;
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

/// `/healthcheck` answers 200 on the public port, with or without the
/// internal route mounted beside it.
#[tokio::test(flavor = "multi_thread")]
async fn healthcheck_is_ok_with_and_without_the_internal_route() {
    for flags in [&[][..], &["--internal-proxy-route"][..]] {
        let (handle, _) = common::start_server(|ws_port| {
            let mut args = vec!["--ws-port"];
            let port = ws_port.to_string();
            args.push(&port);
            args.extend_from_slice(flags);
            parse(&args)
        })
        .await;
        let addr = handle.ws_local_addr().unwrap();
        let response = reqwest::Client::new()
            .get(format!("http://{addr}/healthcheck"))
            .send()
            .await
            .expect("GET /healthcheck");
        assert_eq!(response.status(), 200, "{flags:?}");
        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(body["status"], "ok", "{flags:?}");
        handle.shutdown();
    }
}

/// Everything `socket` receives until the server closes it. A socket still
/// open after `wait` fails the test.
async fn until_closed(socket: &mut TcpStream, wait: Duration) -> String {
    let mut received = Vec::new();
    tokio::time::timeout(wait, socket.read_to_end(&mut received))
        .await
        .expect("the server must close the connection")
        .unwrap();
    String::from_utf8_lossy(&received).into_owned()
}

/// A connection that has not sent its request headers by the setup deadline
/// is closed, whether it sent nothing or half a request. Until then it holds
/// nothing a limit counts, so the deadline is its only bound.
#[tokio::test(flavor = "multi_thread")]
async fn a_connection_without_a_request_is_closed_at_the_setup_deadline() {
    let deadline = Duration::from_secs(1);
    let (handle, _) = common::start_server(|ws_port| {
        parse(&[
            "--ws-port",
            &ws_port.to_string(),
            "--setup-deadline-secs",
            &deadline.as_secs().to_string(),
        ])
    })
    .await;
    let addr = handle.ws_local_addr().unwrap();

    for opening in ["", "GET /info HTTP/1.1\r\nHost: notary\r\n"] {
        let mut socket = TcpStream::connect(addr).await.unwrap();
        socket.write_all(opening.as_bytes()).await.unwrap();
        let started = std::time::Instant::now();
        let reply = until_closed(&mut socket, deadline * 5).await;
        assert!(
            started.elapsed() >= deadline,
            "closed before the deadline on {opening:?}"
        );
        assert_eq!(reply, "", "opening {opening:?}");
    }
    handle.shutdown();
}

/// The public port speaks HTTP/1.1 only: the HTTP/2 preface ends the
/// connection without a reply, at once.
#[tokio::test(flavor = "multi_thread")]
async fn the_http2_preface_is_refused() {
    let (handle, _) =
        common::start_server(|ws_port| parse(&["--ws-port", &ws_port.to_string()])).await;
    let mut socket = TcpStream::connect(handle.ws_local_addr().unwrap())
        .await
        .unwrap();
    socket
        .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(until_closed(&mut socket, Duration::from_secs(5)).await, "");
    handle.shutdown();
}

/// The two listeners of a spawned notary, on ports reserved up front: its
/// stdout is not read, so ephemeral ports could not be learned.
struct Ports {
    mpc: u16,
    public: u16,
}

impl Ports {
    async fn free() -> Self {
        Self {
            mpc: common::free_port().await,
            public: common::free_port().await,
        }
    }

    fn public(&self) -> String {
        public_url(format!("127.0.0.1:{}", self.public))
    }

    fn internal(&self) -> String {
        internal_url(format!("127.0.0.1:{}", self.public))
    }
}

/// The real binary, with the memory store and the internal route, on two
/// ports reserved up front; returns once its public health check answers
/// 200. A start that
/// lost a port race exits at once instead, and is retried on fresh ports,
/// up to [`common::TRIES`] times; an exit for any other reason fails the
/// test with the process's stderr.
async fn spawn_notary() -> (Spawned, Ports) {
    for _ in 0..common::TRIES {
        let ports = Ports::free().await;
        let mut notary = spawn_on(&ports);
        match until_up(&mut notary, ports.public).await {
            Ok(()) => return (notary, ports),
            Err(stderr) if common::is_addr_in_use(&stderr) => continue,
            Err(stderr) => {
                panic!("the notary exited before answering its health check:\n{stderr}")
            }
        }
    }
    panic!("no free ports in {} tries", common::TRIES)
}

/// The real binary, on `ports`, with the memory store and the internal
/// route, its stderr kept.
fn spawn_on(ports: &Ports) -> Spawned {
    let mut child = Command::new(env!("CARGO_BIN_EXE_notary"))
        .args([
            "--host",
            "127.0.0.1",
            "--port",
            &ports.mpc.to_string(),
            "--ws-port",
            &ports.public.to_string(),
            "--internal-proxy-route",
            "--limits-store",
            "memory",
            "--signing-key",
            TEST_KEY,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the notary binary starts");
    // Drained as it is written: a full pipe would block the notary's logs,
    // and with them the notary.
    let mut pipe = child.stderr.take().expect("stderr is piped");
    let stderr = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = pipe.read_to_end(&mut bytes);
        bytes
    });
    Spawned {
        child,
        stderr: Some(stderr),
    }
}

/// Wait for `notary`'s public health check on `port` to answer 200, or for
/// the process to exit first -- an `Err` carrying its stderr.
async fn until_up(notary: &mut Spawned, port: u16) -> Result<(), String> {
    let up = async {
        loop {
            if health(port).await == Some(200) {
                return Ok(());
            }
            if notary.child.try_wait().unwrap().is_some() {
                return Err(notary.stderr());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };
    match tokio::time::timeout(Duration::from_secs(20), up).await {
        Ok(result) => result,
        Err(_) => panic!(
            "the notary never answered its health check:\n{}",
            notary.stderr()
        ),
    }
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
/// for it. `client` is named in `X-Forwarded-For`, which the public route
/// requires and the internal route refuses.
async fn ws_session(url: &str, client: Option<&str>) -> Socket {
    let mut socket = session_from(url, client).await.expect("upgrade");
    assert!(holds(&mut socket, Duration::from_millis(200)).await);
    socket
}

/// The process's exit status within `within`, or a panic.
async fn exit_status(notary: &mut Spawned, within: Duration) -> std::process::ExitStatus {
    let exited = async {
        loop {
            if let Some(status) = notary.child.try_wait().unwrap() {
                return status;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    tokio::time::timeout(within, exited)
        .await
        .unwrap_or_else(|_| panic!("the notary did not exit within {within:?}"))
}

/// Whose session is the last one a drain waits for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Last {
    Public,
    Internal,
    Mpc,
}

/// The real binary under SIGTERM: the health check flips to 503 at once,
/// new upgrades are refused with 503, and the process exits -- with 0 --
/// only once the last session has ended. One session is held on each
/// route and on the MPC port, the other two are closed first, and `last`
/// alone must keep the process alive: each is counted on its own.
async fn sigterm_drains_then_exits_zero(last: Last) {
    let (mut notary, ports) = spawn_notary().await;

    // One session on each route and on the MPC port, each past the point
    // where it counts: the browser's first frame, the prover's first byte.
    let mut public = Some(ws_session(&ports.public(), Some("203.0.113.7")).await);
    let mut internal = Some(ws_session(&ports.internal(), None).await);
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
        notary.child.try_wait().unwrap().is_none(),
        "the notary exited with sessions still in flight"
    );

    // Nothing new is taken while draining -- and the listener is still
    // open to say so, because a closed port reads as a crash. The client is
    // named, so the draining check is the only thing that can refuse.
    let mut request = ports.public().into_client_request().unwrap();
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
        notary.child.try_wait().unwrap().is_none(),
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
/// is cut off. Any session will do; the internal route's needs no client.
#[tokio::test(flavor = "multi_thread")]
async fn a_second_sigterm_exits_zero_without_waiting() {
    let (mut notary, ports) = spawn_notary().await;
    let mut holder = ws_session(&ports.internal(), None).await;

    notary.signal(libc::SIGTERM);
    until_draining(ports.public).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        notary.child.try_wait().unwrap().is_none(),
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
struct Spawned {
    child: Child,
    /// Everything the process writes to stderr, collected until it exits;
    /// taken by [`Spawned::stderr`].
    stderr: Option<std::thread::JoinHandle<Vec<u8>>>,
}

impl Spawned {
    fn signal(&self, signal: libc::c_int) {
        let pid = libc::pid_t::try_from(self.child.id()).expect("a pid");
        // SAFETY: kill(2) on a pid this test spawned and still owns.
        let rc = unsafe { libc::kill(pid, signal) };
        assert_eq!(rc, 0, "kill: {}", std::io::Error::last_os_error());
    }

    /// Kill the process if it is still running, reap it, and return all it
    /// wrote to stderr.
    fn stderr(&mut self) -> String {
        self.reap();
        let bytes = self
            .stderr
            .take()
            .and_then(|drained| drained.join().ok())
            .unwrap_or_default();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    fn reap(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

impl Drop for Spawned {
    fn drop(&mut self) {
        self.reap();
    }
}
