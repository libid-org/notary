//! Every limit on the deployed shape: the real binary, the real Postgres
//! store, real ProxyMode sessions over a WebSocket, and two replicas on
//! one database. The in-process tests beside each handler prove a limit
//! with a stalled three-byte session; this suite is the proof that the
//! whole thing holds as deployed.
//!
//! Needs `NOTARY_TEST_DATABASE_URL`, and skips itself without it -- except
//! under CI, where an unset URL is a broken workflow and fails, the same
//! rule as the Postgres store's own tests. The tests take turns: each
//! spawns one or two notaries and drives a session that is CPU-heavy in a
//! debug build, and one of them counts whole tables.
//!
//! The upstream is a local TLS fixture holding a certificate for
//! `test-server.io`, reached through the `notary-e2e` binary's `--upstream`
//! with its CA in `--upstream-ca`. Every client is a fresh `10.x.y.z`: the tables
//! are shared across tests and runs.

#![cfg(feature = "e2e")]

mod common;

use std::{
    io::Read,
    net::SocketAddr,
    process::{
        Child,
        Command,
        Stdio,
    },
    str::FromStr,
    sync::{
        atomic::{
            AtomicU64,
            Ordering,
        },
        Arc,
        Mutex,
    },
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
use sqlx::{
    postgres::PgConnectOptions,
    PgPool,
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
    },
    net::{
        TcpListener,
        TcpStream,
    },
    task::JoinHandle,
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
use tokio_util::compat::{
    FuturesAsyncReadCompatExt,
    TokioAsyncReadCompatExt,
};

/// anvil #0 — public test key.
const TEST_KEY: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
/// The compressed SEC1 public key for [`TEST_KEY`].
const TEST_PUBKEY: &str =
    "038318535b54105d4a7aae60c08fc45f9687181b4fdfc625bd1a753fa7397fed75";

type Socket = tokio_tungstenite::WebSocketStream<
    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
>;

/// The headers an upgrade carries, as the load balancer would set them.
type Headers<'a> = &'a [(&'static str, &'a str)];

/// One test at a time; see the module docs.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

// ─── The lab: the database, the fixture, and the notaries ───────────────────

/// `NOTARY_TEST_DATABASE_URL`, or `None` with a note; under CI, unset is a
/// broken workflow and panics. The same rule as `src/store/postgres.rs`.
fn pg_url() -> Option<String> {
    match std::env::var("NOTARY_TEST_DATABASE_URL") {
        Ok(url) if !url.trim().is_empty() => Some(url),
        _ if std::env::var_os("CI").is_some() => panic!(
            "NOTARY_TEST_DATABASE_URL is unset under CI: the end-to-end limits tests \
             would skip silently. Restore the env line on the test step in \
             .github/workflows/ci.yml"
        ),
        _ => {
            println!("skipped: NOTARY_TEST_DATABASE_URL not set");
            None
        }
    }
}

/// What every test needs: its turn, the database, the TLS fixture every
/// notary dials, and the fixture's CA on disk for `--upstream-ca`.
struct Lab {
    _turn: tokio::sync::MutexGuard<'static, ()>,
    pg_url: String,
    pool: PgPool,
    fixture: Fixture,
    ca_path: std::path::PathBuf,
}

impl Lab {
    /// `None` when there is no database to run against.
    async fn open() -> Option<Self> {
        let pg_url = pg_url()?;
        let turn = SERIAL.lock().await;
        let pool = PgPool::connect(&pg_url).await.expect("the test database");
        let ca_path = std::env::temp_dir()
            .join(format!("notary-e2e-{}-fixture-ca.der", std::process::id()));
        std::fs::write(&ca_path, CA_CERT_DER).expect("the CA file");
        Some(Self {
            _turn: turn,
            pg_url,
            pool,
            fixture: Fixture::start().await,
            ca_path,
        })
    }

    /// The real binary on the lab's database, with `extra` flags.
    async fn spawn(&self, label: &str, extra: &[&str]) -> Notary {
        self.spawn_on_store(label, &self.pg_url, extra).await
    }

    /// The real binary on `store`, with `extra` flags: two free ports,
    /// retried when the bind-then-drop race is lost, up to the public
    /// health check answering 200. Any other exit fails the test with the
    /// process's output.
    async fn spawn_on_store(&self, label: &str, store: &str, extra: &[&str]) -> Notary {
        for _ in 0..common::TRIES {
            let ports = Ports::free().await;
            let mut notary = self.spawn_on(label, &ports, store, extra);
            match notary.until_up().await {
                Ok(()) => return notary,
                Err(output) if common::is_addr_in_use(&output) => continue,
                Err(output) => panic!(
                    "notary {label} exited before answering its health check:\n{output}"
                ),
            }
        }
        panic!("no free ports in {} tries", common::TRIES)
    }

    fn spawn_on(
        &self,
        label: &str,
        ports: &Ports,
        store: &str,
        extra: &[&str],
    ) -> Notary {
        let mut child = Command::new(env!("CARGO_BIN_EXE_notary-e2e"))
            .args([
                "--host",
                "127.0.0.1",
                "--port",
                &ports.mpc.to_string(),
                "--ws-port",
                &ports.public.to_string(),
                "--internal-proxy-route",
                "--limits-store",
                store,
                "--upstream",
                &self.fixture.addr.to_string(),
                "--upstream-ca",
                self.ca_path.to_str().unwrap(),
                "--signing-key",
                TEST_KEY,
            ])
            .args(extra)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the notary binary starts");
        // Both pipes drained as they are written: a full pipe would block
        // the notary's logs, and with them the notary.
        let stdout = drain(child.stdout.take().expect("stdout is piped"));
        let stderr = drain(child.stderr.take().expect("stderr is piped"));
        Notary {
            label: label.to_string(),
            child,
            ports: ports.clone(),
            output: Some((stdout, stderr)),
        }
    }
}

/// A background thread draining one of a child's pipes to a buffer.
type Drained = std::thread::JoinHandle<Vec<u8>>;

fn drain(mut pipe: impl Read + Send + 'static) -> Drained {
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = pipe.read_to_end(&mut bytes);
        bytes
    })
}

/// A local TLS server holding the fixture certificate for `SERVER_DOMAIN`;
/// every connection gets the fixture's HTTP app.
struct Fixture {
    addr: SocketAddr,
    accept: JoinHandle<()>,
}

impl Fixture {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let _ = tlsn_server_fixture::bind(socket.compat()).await;
                });
            }
        });
        Self { addr, accept }
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.ca_path);
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.accept.abort();
    }
}

/// The two listeners of a spawned notary, on ports reserved up front: an
/// ephemeral port is only logged, so it could not be learned back.
#[derive(Clone)]
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
}

/// The spawned notary: killed when dropped, and its output printed then if
/// the test is failing.
struct Notary {
    label: String,
    child: Child,
    ports: Ports,
    output: Option<(Drained, Drained)>,
}

impl Notary {
    fn public(&self) -> String {
        format!("ws://127.0.0.1:{}/notarize-proxy", self.ports.public)
    }

    /// The internal route, on the public port.
    fn internal(&self) -> String {
        format!(
            "ws://127.0.0.1:{}/internal/notarize-proxy",
            self.ports.public
        )
    }

    fn signal(&self, signal: libc::c_int) {
        let pid = libc::pid_t::try_from(self.child.id()).expect("a pid");
        // SAFETY: kill(2) on a pid this test spawned and still owns.
        let rc = unsafe { libc::kill(pid, signal) };
        assert_eq!(rc, 0, "kill: {}", std::io::Error::last_os_error());
    }

    /// Wait for the public health check to answer 200, or for the process
    /// to exit first -- an `Err` carrying its output.
    async fn until_up(&mut self) -> Result<(), String> {
        let port = self.ports.public;
        let up = async {
            loop {
                if health(port).await == Some(200) {
                    return Ok(());
                }
                if self.child.try_wait().unwrap().is_some() {
                    return Err(self.output());
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        };
        match tokio::time::timeout(Duration::from_secs(20), up).await {
            Ok(result) => result,
            Err(_) => {
                let label = self.label.clone();
                panic!(
                    "notary {label} never answered its health check:\n{}",
                    self.output()
                )
            }
        }
    }

    /// The process's exit status within `within`, or a panic.
    async fn exit_status(&mut self, within: Duration) -> std::process::ExitStatus {
        let exited = async {
            loop {
                if let Some(status) = self.child.try_wait().unwrap() {
                    return status;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };
        tokio::time::timeout(within, exited)
            .await
            .unwrap_or_else(|_| {
                panic!("notary {} did not exit within {within:?}", self.label)
            })
    }

    /// Kill the process if it is still running, reap it, and return
    /// everything it wrote to stdout (the logs) and stderr.
    fn output(&mut self) -> String {
        self.reap();
        let Some((stdout, stderr)) = self.output.take() else {
            return String::new();
        };
        let mut out =
            String::from_utf8_lossy(&stdout.join().unwrap_or_default()).into_owned();
        out.push_str(&String::from_utf8_lossy(&stderr.join().unwrap_or_default()));
        out
    }

    /// SIGTERM first, so a notary that is still up releases its leases and
    /// the shared tables do not fill with rows only a sweep would clear;
    /// SIGKILL if it has not gone within a second.
    fn reap(&mut self) {
        if self.child.try_wait().ok().flatten().is_some() {
            return;
        }
        let pid = libc::pid_t::try_from(self.child.id()).expect("a pid");
        // SAFETY: kill(2) on a pid this test spawned and still owns.
        unsafe { libc::kill(pid, libc::SIGTERM) };
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while std::time::Instant::now() < deadline {
            if self.child.try_wait().ok().flatten().is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Notary {
    fn drop(&mut self) {
        if std::thread::panicking() {
            let output = self.output();
            println!("---- notary {} output ----\n{output}", self.label);
        }
        self.reap();
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

// ─── Clients and sessions ───────────────────────────────────────────────────

/// A client no other test or run has used.
fn fresh_client() -> String {
    let b = uuid::Uuid::new_v4().into_bytes();
    format!("10.{}.{}.{}", b[0], b[1], b[2])
}

fn xff(client: &str) -> [(&'static str, &str); 1] {
    [("x-forwarded-for", client)]
}

fn cf(client: &str) -> [(&'static str, &str); 1] {
    [("cf-connecting-ip", client)]
}

/// How an upgrade was refused: the status, `Retry-After` if any, and the
/// body -- what a browser would see.
#[derive(Debug)]
struct Refused {
    status: u16,
    retry_after: Option<String>,
    body: String,
}

/// Upgrade `url` with `headers`. A refusal is `Err`; any other failure is
/// the test's.
async fn upgrade(url: &str, headers: Headers<'_>) -> Result<Socket, Refused> {
    let mut request = url.into_client_request().unwrap();
    for (name, value) in headers {
        request
            .headers_mut()
            .insert(*name, HeaderValue::from_str(value).unwrap());
    }
    match connect_async(request).await {
        Ok((socket, _)) => Ok(socket),
        Err(tungstenite::Error::Http(response)) => Err(Refused {
            status: response.status().as_u16(),
            retry_after: response
                .headers()
                .get("retry-after")
                .map(|v| v.to_str().unwrap().to_string()),
            body: String::from_utf8_lossy(response.body().as_deref().unwrap_or_default())
                .into_owned(),
        }),
        Err(error) => panic!("upgrade {url}: {error}"),
    }
}

/// An upgrade that must be refused: the refusal, or a panic naming `what`.
async fn refused(url: &str, headers: Headers<'_>, what: &str) -> Refused {
    match upgrade(url, headers).await {
        Ok(_) => panic!("{what}"),
        Err(refused) => refused,
    }
}

/// A session past its first frame, the way the in-process tests hold one:
/// upgraded, three bytes sent, nothing more. It holds a lease and a slot
/// until it is dropped or the notary closes it.
async fn held_session(url: &str, headers: Headers<'_>) -> Result<Socket, Refused> {
    let mut socket = upgrade(url, headers).await?;
    socket
        .send(Message::Binary(b"\x16\x03\x01".to_vec().into()))
        .await
        .expect("the browser sends its first TLS bytes");
    Ok(socket)
}

/// The close code and reason the notary ended a session with.
async fn close_reason(socket: &mut Socket) -> (u16, String) {
    let next = tokio::time::timeout(Duration::from_secs(5), socket.next())
        .await
        .expect("the notary never answered");
    match next {
        Some(Ok(Message::Close(Some(frame)))) => {
            (frame.code.into(), frame.reason.to_string())
        }
        other => panic!("expected a close frame, got: {other:?}"),
    }
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

/// A held session the notary has admitted: not closed within 300 ms.
async fn admitted(url: &str, headers: Headers<'_>) -> Socket {
    let mut socket = held_session(url, headers)
        .await
        .unwrap_or_else(|refused| panic!("refused at the upgrade: {refused:?}"));
    assert!(
        holds(&mut socket, Duration::from_millis(300)).await,
        "the session was closed"
    );
    socket
}

/// What a session came to.
#[derive(Debug)]
enum Outcome {
    /// The attestation the notary wrote, and the bytes the WebSocket
    /// carried both ways to get it.
    Attested {
        attestation: AttestationWire,
        wire_bytes: u64,
    },
    /// Upgraded, then closed by the notary before any attestation.
    Closed { code: u16, reason: String },
}

impl Outcome {
    fn attested(&self) -> &AttestationWire {
        match self {
            Self::Attested { attestation, .. } => attestation,
            Self::Closed { code, reason } => panic!("closed {code}: {reason}"),
        }
    }
}

/// The real prover's ProxyMode flow on an upgraded socket: setup, one GET
/// to the fixture, reveal everything, finish, and read the attestation
/// frame off the reclaimed channel. The socket is pumped to and from a
/// duplex the prover drives, the way tlsn_wasm's transport does it, and
/// every byte over the WebSocket is counted so a caller can size a window
/// from a measurement.
async fn session(socket: Socket) -> Outcome {
    let prover_config = ProverConfig::builder(SERVER_DOMAIN)
        .mode(ProverMode::Proxy)
        .root_certs(vec![CA_CERT_DER.to_vec()])
        .build()
        .unwrap();
    let (mut ws_tx, mut ws_rx) = socket.split();
    let (browser_io, pump_io) = tokio::io::duplex(1 << 17);
    let wire = Arc::new(AtomicU64::new(0));
    let pump_wire = Arc::clone(&wire);
    let pump = tokio::spawn(async move {
        let (mut pipe_reader, mut pipe_writer) = tokio::io::split(pump_io);
        // Browser -> notary, its own task so its end does not stop the
        // read of the attestation and close that follow.
        let out_wire = Arc::clone(&pump_wire);
        let outbound = tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                match pipe_reader.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        out_wire.fetch_add(n as u64, Ordering::Relaxed);
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
        });
        // Notary -> browser, until the notary closes the socket.
        let mut close = None;
        while let Some(message) = ws_rx.next().await {
            match message {
                Ok(Message::Binary(data)) => {
                    pump_wire.fetch_add(data.len() as u64, Ordering::Relaxed);
                    if pipe_writer.write_all(&data).await.is_err() {
                        break;
                    }
                }
                Ok(Message::Close(frame)) => {
                    close = frame
                        .map(|frame| (u16::from(frame.code), frame.reason.to_string()));
                    let _ = pipe_writer.shutdown().await;
                    break;
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        outbound.abort();
        close
    });

    let mut prover = SdkProver::new(prover_config).unwrap();
    let session = async {
        prover
            .setup(browser_io.compat())
            .await
            .map_err(|e| format!("setup: {e}"))?;
        let response = prover
            .send_request_proxy(
                HttpRequest::get(format!("https://{SERVER_DOMAIN}/bytes?size=16"))
                    .header("Host", SERVER_DOMAIN)
                    .header("Connection", "close"),
            )
            .await
            .map_err(|e| format!("request: {e}"))?;
        if response.status != 200 {
            return Err(format!("fixture answered {}", response.status));
        }
        let transcript = prover
            .transcript()
            .map_err(|e| format!("transcript: {e}"))?;
        prover
            .reveal(
                Reveal::new()
                    .sent(0..transcript.sent.len())
                    .recv(0..transcript.recv.len())
                    .server_identity(true),
                None,
            )
            .await
            .map_err(|e| format!("reveal: {e}"))?;
        let mut io = prover
            .finish()
            .await
            .map_err(|e| format!("finish: {e}"))?
            .compat();
        let attestation: AttestationWire = read_msg(&mut io)
            .await
            .map_err(|e| format!("attestation frame: {e}"))?;
        Ok::<_, String>(attestation)
    };
    let result = tokio::time::timeout(Duration::from_secs(30), session).await;
    // The prover is done; browser_io is dropped, so the pump's inbound half
    // sees the notary's close and returns.
    let close = tokio::time::timeout(Duration::from_secs(5), pump)
        .await
        .expect("the notary never closed the socket")
        .expect("the pump task");
    let wire_bytes = wire.load(Ordering::Relaxed);
    match (result, close) {
        (Ok(Ok(attestation)), _) => Outcome::Attested {
            attestation,
            wire_bytes,
        },
        (_, Some((code, reason))) => Outcome::Closed { code, reason },
        (Ok(Err(error)), None) => {
            panic!("session failed without a close frame: {error}")
        }
        (Err(_), None) => panic!("session timed out without a close frame"),
    }
}

/// Upgrade and run a session in one go.
async fn run_session(url: &str, headers: Headers<'_>) -> Result<Outcome, Refused> {
    Ok(session(upgrade(url, headers).await?).await)
}

/// The attestation is the notary's: the record names the fixture's server,
/// and the signature recovers to the notary's public key.
fn assert_signed(attestation: &AttestationWire) {
    assert_eq!(
        &attestation.attested_data[..32],
        &libid_crypto::keccak256(SERVER_DOMAIN.as_bytes())
    );
    assert_eq!(attestation.notary_signature.len(), 65);
    let recovered = libid_crypto::recover_eth_claim(
        &attestation.notary_signature,
        &libid_crypto::keccak256(&attestation.attested_data),
    )
    .expect("the signature recovers");
    assert_eq!(
        hex::encode(recovered.to_encoded_point(true).as_bytes()),
        TEST_PUBKEY
    );
}

// ─── The store, read directly ───────────────────────────────────────────────

/// `client`'s live leases.
async fn live_leases(pool: &PgPool, client: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM notary_leases WHERE client_key = $1 AND expires_at > now()",
    )
    .bind(client)
    .fetch_one(pool)
    .await
    .expect("count leases")
}

/// The bytes charged to `client` in its fullest window.
async fn bytes_charged(pool: &PgPool, client: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT coalesce(max(units), 0) FROM notary_windows
         WHERE client_key = $1 AND dimension = 'bytes'",
    )
    .bind(client)
    .fetch_one(pool)
    .await
    .expect("read the bytes window")
}

/// Every row of `table`.
async fn rows(pool: &PgPool, table: &str) -> i64 {
    sqlx::query_scalar(&format!("SELECT count(*) FROM {table}"))
        .fetch_one(pool)
        .await
        .expect("count rows")
}

/// Poll `check` every 50 ms until it answers, or fail with `what`.
async fn poll<T, F, Fut>(within: Duration, what: &str, mut check: F) -> T
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    let deadline = tokio::time::Instant::now() + within;
    loop {
        if let Some(value) = check().await {
            return value;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "not within {within:?}: {what}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Wait until `client` holds exactly `n` live leases.
async fn until_leases(pool: &PgPool, client: &str, n: i64) {
    poll(
        Duration::from_secs(5),
        &format!("{client} holds {n} leases"),
        || async move { (live_leases(pool, client).await == n).then_some(()) },
    )
    .await;
}

/// Wait until `client` has been charged more than `above` bytes; the total.
async fn until_charged(pool: &PgPool, client: &str, above: i64) -> i64 {
    poll(
        Duration::from_secs(5),
        &format!("{client} charged past {above} bytes"),
        || async move {
            let charged = bytes_charged(pool, client).await;
            (charged > above).then_some(charged)
        },
    )
    .await
}

// ─── A TCP forwarder, so the store can be cut and restored ──────────────────

/// Forwards `127.0.0.1:port` to `upstream`; every task it spawned is
/// aborted by [`Forwarder::stop`], which breaks the connections through it.
struct Forwarder {
    port: u16,
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl Forwarder {
    /// Bind `port` (`0` for an ephemeral one) and forward to `upstream`.
    async fn start(port: u16, upstream: (String, u16)) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", port))
            .await
            .expect("the forwarder binds");
        let port = listener.local_addr().unwrap().port();
        let tasks = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::clone(&tasks);
        let accept = tokio::spawn(async move {
            while let Ok((mut down, _)) = listener.accept().await {
                let upstream = upstream.clone();
                let task = tokio::spawn(async move {
                    if let Ok(mut up) = TcpStream::connect(upstream).await {
                        let _ = tokio::io::copy_bidirectional(&mut down, &mut up).await;
                    }
                });
                connections.lock().unwrap().push(task);
            }
        });
        tasks.lock().unwrap().push(accept);
        Self { port, tasks }
    }

    fn stop(&self) {
        for task in self.tasks.lock().unwrap().drain(..) {
            task.abort();
        }
    }
}

impl Drop for Forwarder {
    fn drop(&mut self) {
        self.stop();
    }
}

/// `url` with its host and port replaced, the rest kept.
fn with_host(url: &str, host: &str, port: u16) -> String {
    let (scheme, rest) = url.split_once("://").expect("a URL");
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let userinfo = authority
        .rfind('@')
        .map(|at| &authority[..=at])
        .unwrap_or_default();
    format!("{scheme}://{userinfo}{host}:{port}{tail}")
}

/// Where `url` points.
fn host_port(url: &str) -> (String, u16) {
    let options = PgConnectOptions::from_str(url).expect("a Postgres URL");
    (options.get_host().to_string(), options.get_port())
}

// ─── The tests ──────────────────────────────────────────────────────────────

/// The baseline: a real session through the public port ends in an
/// attestation the notary signed, and the lease it held is gone.
#[tokio::test(flavor = "multi_thread")]
async fn a_real_session_completes_through_the_public_port() {
    let Some(lab) = Lab::open().await else { return };
    let notary = lab.spawn("A", &[]).await;
    let client = fresh_client();

    let outcome = run_session(&notary.public(), &xff(&client))
        .await
        .expect("admitted");
    assert_signed(outcome.attested());
    let Outcome::Attested { wire_bytes, .. } = outcome else {
        unreachable!()
    };
    assert!(wire_bytes > 0, "the WebSocket carried no bytes");

    until_leases(&lab.pool, &client, 0).await;
}

/// `--max-sessions-per-ip` counts what a client holds on every replica: two
/// held on A leave nothing for a third on B, and one ending on A lets B
/// admit.
#[tokio::test(flavor = "multi_thread")]
async fn the_concurrency_cap_holds_across_two_replicas() {
    let Some(lab) = Lab::open().await else { return };
    let flags = ["--max-sessions-per-ip", "2", "--per-ip-upgrades", ""];
    let a = lab.spawn("A", &flags).await;
    let b = lab.spawn("B", &flags).await;
    let client = fresh_client();

    let first = admitted(&a.public(), &xff(&client)).await;
    let second = admitted(&a.public(), &xff(&client)).await;
    until_leases(&lab.pool, &client, 2).await;

    let mut third = held_session(&b.public(), &xff(&client))
        .await
        .expect("the upgrade itself is not refused");
    let (code, reason) = close_reason(&mut third).await;
    assert_eq!(code, 1013, "{reason}");
    assert!(reason.contains("this client"), "{reason}");

    drop(first);
    let url = b.public();
    let client = client.as_str();
    let reopened: Socket = poll(Duration::from_secs(10), "B admits", || async {
        let mut socket = held_session(&url, &xff(client)).await.expect("upgrade");
        holds(&mut socket, Duration::from_millis(200))
            .await
            .then_some(socket)
    })
    .await;
    drop(reopened);
    drop(second);
}

/// `--per-ip-upgrades` counts what a client started on every replica: three
/// in the hour, split across A and B, and the fourth is 429 on either; a
/// different client on B still gets in.
#[tokio::test(flavor = "multi_thread")]
async fn the_upgrades_window_holds_across_two_replicas() {
    let Some(lab) = Lab::open().await else { return };
    let flags = ["--per-ip-upgrades", "3/1h"];
    let a = lab.spawn("A", &flags).await;
    let b = lab.spawn("B", &flags).await;
    let client = fresh_client();

    let one = admitted(&a.public(), &xff(&client)).await;
    let two = admitted(&a.public(), &xff(&client)).await;
    let three = admitted(&b.public(), &xff(&client)).await;

    for (label, url) in [("A", a.public()), ("B", b.public())] {
        let refused = upgrade(&url, &xff(&client))
            .await
            .err()
            .unwrap_or_else(|| panic!("{label} admitted a fourth upgrade"));
        assert_eq!(refused.status, 429, "{label}: {refused:?}");
        assert_eq!(refused.retry_after.as_deref(), Some("60"), "{label}");
        assert!(
            refused.body.contains("sessions started"),
            "{label}: {refused:?}"
        );
    }

    let other = fresh_client();
    let other = admitted(&b.public(), &xff(&other)).await;
    drop(other);
    drop(three);
    drop(two);
    drop(one);
}

/// `--per-ip-bytes` is charged with what a session really relayed. One
/// session is measured first, on a notary with a wide window; on one whose
/// window is one and a half of that, the first session fits, the second
/// fits -- the window only has to have room -- and the third is refused with
/// 429 naming the bytes window. The upgrades window is off, so nothing else
/// can be what refuses.
#[tokio::test(flavor = "multi_thread")]
async fn the_bytes_window_is_charged_by_real_ceremonies() {
    let Some(lab) = Lab::open().await else { return };
    let measure = lab
        .spawn(
            "measure",
            &["--per-ip-upgrades", "", "--per-ip-bytes", "1GB/1h"],
        )
        .await;
    let client = fresh_client();
    run_session(&measure.public(), &xff(&client))
        .await
        .expect("admitted")
        .attested();
    let one_session = until_charged(&lab.pool, &client, 0).await;
    assert!(
        one_session > 1000,
        "a TLS handshake alone is over a kilobyte"
    );
    drop(measure);

    let limit = one_session * 3 / 2;
    let notary = lab
        .spawn(
            "limited",
            &[
                "--per-ip-upgrades",
                "",
                "--per-ip-bytes",
                &format!("{limit}/1h"),
            ],
        )
        .await;
    let client = fresh_client();

    run_session(&notary.public(), &xff(&client))
        .await
        .expect("the first session is admitted")
        .attested();
    let charged = until_charged(&lab.pool, &client, 0).await;
    assert!(charged <= limit, "{charged} > {limit}");

    run_session(&notary.public(), &xff(&client))
        .await
        .expect("the second session is admitted: the window has room")
        .attested();
    let charged = until_charged(&lab.pool, &client, charged).await;
    assert!(charged > limit, "{charged} <= {limit}");

    let refused = refused(
        &notary.public(),
        &xff(&client),
        "the third session finds the window full",
    )
    .await;
    assert_eq!(refused.status, 429, "{refused:?}");
    assert_eq!(refused.retry_after.as_deref(), Some("60"));
    assert!(refused.body.contains("bytes"), "{refused:?}");
}

/// `--max-sessions` is the whole pool: past it the upgrade is 503 -- not the
/// client's 429, not a session closed 1013.
#[tokio::test(flavor = "multi_thread")]
async fn the_global_pool_refuses_with_503() {
    let Some(lab) = Lab::open().await else { return };
    let notary = lab
        .spawn("A", &["--max-sessions", "1", "--per-ip-upgrades", ""])
        .await;
    let client = fresh_client();

    let holder = admitted(&notary.public(), &xff(&client)).await;
    let url = notary.public();
    let client = client.as_str();
    let refused = poll(Duration::from_secs(5), "the pool refuses", || async {
        upgrade(&url, &xff(client)).await.err()
    })
    .await;
    assert_eq!(refused.status, 503, "{refused:?}");
    assert_eq!(refused.retry_after, None);
    drop(holder);
}

/// Every public limit at its minimum, and the internal route ignores them
/// all: three held sessions and a whole session, with no client header,
/// and the store's tables are exactly as they were. A public session
/// afterwards shows the store would have recorded one. The same route
/// reached through a proxy -- `X-Forwarded-For` set -- is 403.
#[tokio::test(flavor = "multi_thread")]
async fn the_internal_route_ignores_every_limit() {
    let Some(lab) = Lab::open().await else { return };
    let notary = lab
        .spawn(
            "A",
            &[
                "--max-sessions",
                "1",
                "--max-sessions-per-ip",
                "1",
                "--per-ip-upgrades",
                "1/1h",
                "--per-ip-bytes",
                "1KB/1h",
            ],
        )
        .await;
    let before = (
        rows(&lab.pool, "notary_leases").await,
        rows(&lab.pool, "notary_windows").await,
    );

    let one = admitted(&notary.internal(), &[]).await;
    let two = admitted(&notary.internal(), &[]).await;
    let three = admitted(&notary.internal(), &[]).await;
    let outcome = run_session(&notary.internal(), &[])
        .await
        .expect("the internal route admits");
    assert_signed(outcome.attested());

    let after = (
        rows(&lab.pool, "notary_leases").await,
        rows(&lab.pool, "notary_windows").await,
    );
    // A notary still draining from the previous test may sweep expired rows
    // meanwhile; only a row that appeared is the internal route's doing.
    assert!(
        after.0 <= before.0 && after.1 <= before.1,
        "internal traffic touched the store: {before:?} -> {after:?}"
    );

    let client = fresh_client();
    let proxied = refused(
        &notary.internal(),
        &xff(&client),
        "the internal route admitted a request that came through a proxy",
    )
    .await;
    assert_eq!(proxied.status, 403, "{proxied:?}");
    assert_eq!(proxied.body, "internal route is not served through a proxy");

    run_session(&notary.public(), &xff(&client))
        .await
        .expect("one public session fits every minimum")
        .attested();
    until_charged(&lab.pool, &client, 0).await;
    assert!(
        rows(&lab.pool, "notary_windows").await > before.1,
        "the public session left no window rows"
    );
    drop(three);
    drop(two);
    drop(one);
}

/// With `--client-ip-header cf-connecting-ip` the client is that header and
/// nothing else: `X-Forwarded-For` alone is 400, `CF-Connecting-IP` carries
/// a session through, and the per-client cap counts its value -- two values
/// both hold, the same value twice is closed 1013.
#[tokio::test(flavor = "multi_thread")]
async fn a_missing_header_is_400_and_cf_mode_switches_the_source() {
    let Some(lab) = Lab::open().await else { return };
    let notary = lab
        .spawn(
            "A",
            &[
                "--client-ip-header",
                "cf-connecting-ip",
                "--max-sessions-per-ip",
                "1",
                "--per-ip-upgrades",
                "",
            ],
        )
        .await;
    let client = fresh_client();

    let refused = refused(
        &notary.public(),
        &xff(&client),
        "X-Forwarded-For names no client in cf-connecting-ip mode",
    )
    .await;
    assert_eq!(refused.status, 400, "{refused:?}");

    let outcome = run_session(&notary.public(), &cf(&client))
        .await
        .expect("the Cloudflare header names the client");
    assert_signed(outcome.attested());
    until_leases(&lab.pool, &client, 0).await;

    let other = fresh_client();
    let same = admitted(&notary.public(), &cf(&client)).await;
    let other = admitted(&notary.public(), &cf(&other)).await;
    let mut again = held_session(&notary.public(), &cf(&client))
        .await
        .expect("the upgrade itself is not refused");
    let (code, reason) = close_reason(&mut again).await;
    assert_eq!(code, 1013, "{reason}");
    drop(other);
    drop(same);
}

/// The store cut off at runtime: the public port refuses with 503 naming the
/// store -- a limit that fails open is one an attacker can switch off -- and
/// admits again once the store is back, with nothing restarted.
#[tokio::test(flavor = "multi_thread")]
async fn a_store_outage_fails_closed_and_recovers() {
    let Some(lab) = Lab::open().await else { return };
    let upstream = host_port(&lab.pg_url);
    let forwarder = Forwarder::start(0, upstream.clone()).await;
    let port = forwarder.port;
    // The bytes window off, so the upgrades window's own count() is the
    // check that has to fail closed -- with both on, would_fit(Bytes) would
    // refuse first and a count() that fails open would go unnoticed.
    let notary = lab
        .spawn_on_store(
            "A",
            &with_host(&lab.pg_url, "127.0.0.1", port),
            &["--per-ip-upgrades", "1000/1m", "--per-ip-bytes", ""],
        )
        .await;
    let client = fresh_client();

    run_session(&notary.public(), &xff(&client))
        .await
        .expect("admitted through the forwarder")
        .attested();

    forwarder.stop();
    drop(forwarder);
    let url = notary.public();
    let client = client.as_str();
    let refused = poll(
        Duration::from_secs(10),
        "the upgrade is refused",
        || async { upgrade(&url, &xff(client)).await.err() },
    )
    .await;
    assert_eq!(refused.status, 503, "{refused:?}");
    assert!(
        refused.body.contains("limits store unavailable"),
        "{refused:?}"
    );

    let forwarder = Forwarder::start(port, upstream).await;
    let recovered: Socket =
        poll(Duration::from_secs(10), "the upgrade recovers", || async {
            upgrade(&url, &xff(client)).await.ok()
        })
        .await;
    drop(forwarder);
    drop(recovered);
}

/// A replica killed with leases held: they expire on the connection
/// deadline, so B refuses until then and admits after. The TTL is the leak
/// bound.
#[tokio::test(flavor = "multi_thread")]
async fn limits_recover_when_a_replica_dies_holding_leases() {
    let Some(lab) = Lab::open().await else { return };
    let flags = [
        "--max-sessions-per-ip",
        "2",
        "--connection-deadline-secs",
        "5",
        "--per-ip-upgrades",
        "",
    ];
    let mut a = lab.spawn("A", &flags).await;
    let b = lab.spawn("B", &flags).await;
    let client = fresh_client();

    let one = admitted(&a.public(), &xff(&client)).await;
    let two = admitted(&a.public(), &xff(&client)).await;
    until_leases(&lab.pool, &client, 2).await;

    a.signal(libc::SIGKILL);
    let status = a.exit_status(Duration::from_secs(5)).await;
    assert!(!status.success(), "SIGKILL should not exit 0: {status}");

    let mut third = held_session(&b.public(), &xff(&client))
        .await
        .expect("the upgrade itself is not refused");
    assert_eq!(close_reason(&mut third).await.0, 1013);

    let url = b.public();
    let client = client.as_str();
    let reopened: Socket = poll(Duration::from_secs(10), "B admits", || async {
        let mut socket = held_session(&url, &xff(client)).await.expect("upgrade");
        holds(&mut socket, Duration::from_millis(200))
            .await
            .then_some(socket)
    })
    .await;
    drop(reopened);
    drop(two);
    drop(one);
}

/// SIGTERM with a session in flight: the session finishes with its
/// attestation, and the process exits 0 once it has.
#[tokio::test(flavor = "multi_thread")]
async fn a_session_started_before_sigterm_completes() {
    let Some(lab) = Lab::open().await else { return };
    let mut notary = lab.spawn("A", &[]).await;
    let client = fresh_client();

    let socket = upgrade(&notary.public(), &xff(&client))
        .await
        .expect("admitted");
    let running = tokio::spawn(session(socket));
    tokio::time::sleep(Duration::from_millis(100)).await;
    notary.signal(libc::SIGTERM);

    // The drain is observable while the session runs: the health check
    // flips to 503 and a new upgrade is refused as draining, not admitted.
    let port = notary.ports.public;
    poll(
        Duration::from_secs(5),
        "health reports draining",
        || async { (health(port).await == Some(503)).then_some(()) },
    )
    .await;
    let late = refused(
        &notary.public(),
        &xff(&fresh_client()),
        "an upgrade during the drain",
    )
    .await;
    assert_eq!(late.status, 503, "{late:?}");
    assert!(late.body.contains("draining"), "{late:?}");

    let outcome = running.await.expect("the session task");
    assert_signed(outcome.attested());
    let status = notary.exit_status(Duration::from_secs(5)).await;
    assert!(status.success(), "exit status: {status}");
}
