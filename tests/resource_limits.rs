//! The resource limits through the public surface: the flags an operator
//! sets, and the ProxyMode session caps and windows refusing an upgrade on
//! the real HTTP server. The limits that need a session to trip (the
//! ProxyMode data cap, the bytes window, the MPC-TLS queue) are unit tests
//! beside the handlers.

use std::{
    num::NonZeroUsize,
    time::Duration,
};

use clap::Parser;
use futures_util::{
    SinkExt,
    StreamExt,
};
use notary::{
    limits::Concurrency,
    server,
    NotaryServerConfig,
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

/// Parse the CLI as `main` does, on top of the arguments a bare start needs.
fn parse(extra: &[&str]) -> Result<NotaryServerConfig, clap::Error> {
    let mut args = vec![
        "notary",
        "--host",
        "127.0.0.1",
        "--port",
        "0",
        "--signing-key",
        TEST_KEY,
    ];
    args.extend_from_slice(extra);
    NotaryServerConfig::try_parse_from(args)
}

fn nz(n: usize) -> NonZeroUsize {
    NonZeroUsize::new(n).unwrap()
}

#[test]
fn every_limit_has_a_default() {
    let config = parse(&[]).unwrap();
    assert_eq!(config.max_sessions, 1024);
    assert_eq!(config.proxy_max_bytes, 10_000_000);
    assert_eq!(config.mpc_max_sessions, Concurrency::PerCore(nz(4)));
    assert_eq!(config.connection_deadline_secs, 300);
    assert_eq!(config.connection_deadline(), Duration::from_secs(300));
    assert_eq!(config.setup_deadline_secs, 15);
    assert_eq!(config.setup_deadline(), Duration::from_secs(15));
    assert_eq!(config.max_sessions_per_ip, 4);
    assert_eq!(config.trusted_proxies, "");
    assert_eq!(config.limits_store, "");
    // `parse` passes `--port 0`; unset is off.
    assert_eq!(config.port, Some(0));
    assert_eq!(
        NotaryServerConfig::try_parse_from(["notary", "--signing-key", TEST_KEY])
            .unwrap()
            .port,
        None
    );
    assert_eq!(config.ws_port, 7048);
    assert_eq!(config.internal_ws_port, None);
    assert_eq!(config.internal_max_sessions, 1024);
    assert_eq!(config.per_ip_upgrades, "10/1m,60/30m,100/1h");
    assert_eq!(config.per_ip_bytes, "100MB/1m,600MB/30m,1GB/1h");
}

/// A per-client cap with nothing to key on is a cap on the whole service, and
/// it looks exactly like ordinary load. The notary refuses to start instead --
/// unless it is bound to loopback, where there is no load balancer to hide
/// behind and `cargo run` must keep working.
#[test]
fn a_per_ip_cap_without_trusted_proxies_refuses_to_start() {
    let public = NotaryServerConfig::try_parse_from([
        "notary",
        "--port",
        "0",
        "--signing-key",
        TEST_KEY,
        "--host",
        "0.0.0.0",
    ])
    .unwrap();
    let error = public
        .trusted_proxies()
        .expect_err("a public bind with a per-client cap and no proxy must not start");
    assert!(error.contains("--trusted-proxies"), "{error}");
    assert!(error.contains("direct"), "{error}");

    for allowed in ["direct", "10.60.200.0/24"] {
        let config = NotaryServerConfig::try_parse_from([
            "notary",
            "--port",
            "0",
            "--signing-key",
            TEST_KEY,
            "--host",
            "0.0.0.0",
            "--trusted-proxies",
            allowed,
        ])
        .unwrap();
        config
            .trusted_proxies()
            .unwrap_or_else(|e| panic!("{allowed:?} must start: {e}"));
    }

    // Every per-client limit off needs no proxy setting at all; any one of
    // them on does.
    let uncapped = NotaryServerConfig::try_parse_from([
        "notary",
        "--port",
        "0",
        "--signing-key",
        TEST_KEY,
        "--host",
        "0.0.0.0",
        "--max-sessions-per-ip",
        "0",
        "--per-ip-upgrades",
        "",
        "--per-ip-bytes",
        "",
    ])
    .unwrap();
    assert!(uncapped.trusted_proxies().unwrap().is_empty());
    let windows_only = NotaryServerConfig::try_parse_from([
        "notary",
        "--port",
        "0",
        "--signing-key",
        TEST_KEY,
        "--host",
        "0.0.0.0",
        "--max-sessions-per-ip",
        "0",
    ])
    .unwrap();
    assert!(windows_only.trusted_proxies().is_err());

    // The default bind is loopback, so the whole suite above it still starts.
    assert!(parse(&[]).unwrap().trusted_proxies().unwrap().is_empty());
}

#[test]
fn mpc_max_sessions_takes_a_raw_count_or_a_core_multiplier() {
    let raw = parse(&["--mpc-max-sessions", "16"]).unwrap();
    assert_eq!(raw.mpc_max_sessions, Concurrency::Raw(nz(16)));
    assert_eq!(raw.mpc_max_sessions.resolve(Some(nz(10))), 16);

    let per_core = parse(&["--mpc-max-sessions", "4x"]).unwrap();
    assert_eq!(per_core.mpc_max_sessions, Concurrency::PerCore(nz(4)));
    assert_eq!(per_core.mpc_max_sessions.resolve(Some(nz(10))), 40);
}

/// A value that is neither form is a startup error naming both, never a
/// silent fallback to the default.
#[test]
fn bad_mpc_max_sessions_fails_at_startup_naming_the_accepted_forms() {
    for bad in ["abc", "0", "0x", "x", "4 x"] {
        let error = parse(&["--mpc-max-sessions", bad])
            .expect_err(&format!("{bad:?} must not start the notary"))
            .to_string();
        assert!(error.contains("--mpc-max-sessions"), "{error}");
        assert!(
            error.contains("\"16\"") && error.contains("\"4x\""),
            "{error}"
        );
    }
}

#[test]
fn other_limits_are_plain_numbers_and_the_deadline_is_never_zero() {
    let config = parse(&[
        "--max-sessions",
        "2",
        "--proxy-max-bytes",
        "4096",
        "--connection-deadline-secs",
        "7",
    ])
    .unwrap();
    assert_eq!(config.max_sessions, 2);
    assert_eq!(config.proxy_max_bytes, 4096);
    assert_eq!(config.connection_deadline(), Duration::from_secs(7));

    let error = parse(&["--connection-deadline-secs", "0"])
        .expect_err("a zero deadline would fail every connection")
        .to_string();
    assert!(error.contains("--connection-deadline-secs"), "{error}");

    let error = parse(&["--setup-deadline-secs", "0"])
        .expect_err("a zero setup deadline would fail every connection")
        .to_string();
    assert!(error.contains("--setup-deadline-secs"), "{error}");
}

/// Reserve an ephemeral port for the HTTP server: ws_port 0 means "disabled",
/// so bind-then-drop to learn a free port number.
async fn free_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

/// Past `--max-sessions`, the upgrade is refused with 503 -- not queued --
/// and the slot comes back as soon as the session holding it ends.
#[tokio::test(flavor = "multi_thread")]
async fn proxy_upgrade_past_max_sessions_is_refused_with_503() {
    let ws_port = free_port().await;
    let config =
        parse(&["--ws-port", &ws_port.to_string(), "--max-sessions", "1"]).unwrap();
    let handle = server::run(config).await.expect("server starts");
    let url = format!(
        "ws://{}/notarize-proxy",
        handle.ws_local_addr().expect("ws server enabled")
    );

    // The first browser takes the only slot by starting a session -- sending
    // the bytes it wants relayed. Upgrading alone reserves nothing.
    let (mut holder, _) = connect_async(&url).await.expect("first upgrade");
    holder
        .send(Message::Binary(b"\x16\x03\x01".to_vec().into()))
        .await
        .expect("the browser sends its first TLS bytes");

    let refused = until_refused(&url).await;
    let tungstenite::Error::Http(response) = refused else {
        panic!("expected an HTTP refusal, got: {refused}");
    };
    assert_eq!(response.status(), 503);

    // Closing the holder ends its session and frees the slot; the next
    // upgrade succeeds within moments, so nothing was stuck.
    drop(holder);
    let reopened = async {
        loop {
            if connect_async(&url).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(5), reopened)
        .await
        .expect("the slot was not released after the holder went away");

    handle.shutdown();
}

/// The attack the slot-on-connect design allowed: upgrade, then say nothing.
/// One socket per slot, ~150 bytes each, and every browser is refused for the
/// whole connection deadline. An upgraded-but-silent socket must cost a
/// socket and nothing else.
#[tokio::test(flavor = "multi_thread")]
async fn a_silent_upgrade_holds_no_session_slot() {
    let ws_port = free_port().await;
    let config =
        parse(&["--ws-port", &ws_port.to_string(), "--max-sessions", "1"]).unwrap();
    let handle = server::run(config).await.expect("server starts");
    let url = format!(
        "ws://{}/notarize-proxy",
        handle.ws_local_addr().expect("ws server enabled")
    );

    // Upgraded and held open, but never a byte of session data.
    let (_silent, _) = connect_async(&url).await.expect("first upgrade");

    // A ping keeps the socket warm without starting a session; it must not
    // buy a slot either.
    let (mut pinger, _) = connect_async(&url).await.expect("second upgrade");
    pinger
        .send(Message::Ping(Vec::new().into()))
        .await
        .expect("ping");

    // The only slot is still free, so a real browser gets in.
    let (mut real, _) = connect_async(&url)
        .await
        .expect("a real browser must not be refused because of idle sockets");
    real.send(Message::Binary(b"\x16\x03\x01".to_vec().into()))
        .await
        .expect("the real browser starts its session");

    // And now that a session is running, the cap applies as it should.
    let refused = until_refused(&url).await;
    let tungstenite::Error::Http(response) = refused else {
        panic!("expected an HTTP refusal, got: {refused}");
    };
    assert_eq!(response.status(), 503);

    handle.shutdown();
}

/// Connect until the server refuses, or fail the test. The slot is taken
/// asynchronously, once the server has read the first frame, so the refusal
/// arrives a moment after the frame is sent.
async fn until_refused(url: &str) -> tungstenite::Error {
    let refused = async {
        loop {
            match connect_async(url).await {
                Err(error) => return error,
                Ok((socket, _)) => drop(socket),
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(5), refused)
        .await
        .expect("the session cap never refused an upgrade")
}

/// Open a ProxyMode session claiming to come from `client`, as the load
/// balancer would say it: the notary trusts loopback as its proxy, so the
/// header this sets is the one the walk lands on.
async fn session_from(url: &str, client: &str) -> Result<Socket, tungstenite::Error> {
    let mut request = url.into_client_request().unwrap();
    request
        .headers_mut()
        .insert("x-forwarded-for", HeaderValue::from_str(client).unwrap());
    let (mut socket, _) = connect_async(request).await?;
    // The slot is spent on a session, so start one.
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

/// A client gets `--max-sessions-per-ip` sessions at once and no more, counted
/// against the address the load balancer forwarded -- not against the balancer,
/// which every browser shares -- and gets one back when a session ends.
#[tokio::test(flavor = "multi_thread")]
async fn the_per_ip_cap_counts_the_forwarded_client_not_the_proxy() {
    let ws_port = free_port().await;
    let config = parse(&[
        "--ws-port",
        &ws_port.to_string(),
        "--max-sessions",
        "64",
        "--max-sessions-per-ip",
        "2",
        "--trusted-proxies",
        "127.0.0.0/8",
        // Off, so the retries below are refused by the cap or by nothing.
        "--per-ip-upgrades",
        "",
    ])
    .unwrap();
    let handle = server::run(config).await.expect("server starts");
    let url = format!(
        "ws://{}/notarize-proxy",
        handle.ws_local_addr().expect("ws server enabled")
    );

    let first = session_from(&url, "203.0.113.7")
        .await
        .expect("first session");
    let _second = session_from(&url, "203.0.113.7")
        .await
        .expect("second session");

    // A third from the same client is upgraded -- the notary has 64 slots --
    // and then closed, because this client has none.
    let mut third = session_from(&url, "203.0.113.7")
        .await
        .expect("the upgrade itself is not refused");
    let (code, reason) = close_reason(&mut third).await;
    assert_eq!(code, 1013, "reason: {reason}");
    assert!(reason.contains("this client"), "{reason}");

    // A forged prefix does not buy a fresh budget: the balancer's entry is
    // still the rightmost, and still this client.
    let mut forged = session_from(&url, "9.9.9.9, 203.0.113.7")
        .await
        .expect("upgrade");
    assert_eq!(close_reason(&mut forged).await.0, 1013);

    // Another client is unaffected -- the cap is per client, and the key is
    // the forwarded address rather than the proxy every one of these shares.
    let _other = session_from(&url, "198.51.100.4")
        .await
        .expect("a different client must not share the budget");

    // A session that ends gives its lease back: the moment the first is
    // gone, the same client is under its cap and a new session holds.
    drop(first);
    let reopened = async {
        loop {
            let mut socket = session_from(&url, "203.0.113.7").await.expect("upgrade");
            if holds(&mut socket, Duration::from_millis(200)).await {
                return socket;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    let _reopened = tokio::time::timeout(Duration::from_secs(5), reopened)
        .await
        .expect("the lease was not released when its session ended");

    handle.shutdown();
}

/// `--per-ip-upgrades` counts sessions started per window, at the upgrade:
/// past it the client gets 429 and a `Retry-After`, before anything has been
/// spent on it, and another client is not affected.
#[tokio::test(flavor = "multi_thread")]
async fn the_upgrades_window_refuses_the_next_upgrade_with_429() {
    let ws_port = free_port().await;
    let config = parse(&[
        "--ws-port",
        &ws_port.to_string(),
        "--per-ip-upgrades",
        "2/1h",
        "--trusted-proxies",
        "127.0.0.0/8",
    ])
    .unwrap();
    let handle = server::run(config).await.expect("server starts");
    let url = format!(
        "ws://{}/notarize-proxy",
        handle.ws_local_addr().expect("ws server enabled")
    );

    // Two sessions in the hour, finished or not: the window counts starts.
    let first = session_from(&url, "203.0.113.7")
        .await
        .expect("first session");
    drop(first);
    let _second = session_from(&url, "203.0.113.7")
        .await
        .expect("second session");

    let refused = session_from(&url, "203.0.113.7")
        .await
        .expect_err("a third upgrade in the window must be refused");
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

    let _other = session_from(&url, "198.51.100.4")
        .await
        .expect("a different client has its own window");

    handle.shutdown();
}

/// A trusted proxy that names no client is refused at the upgrade, never
/// counted against the proxy itself -- which every browser shares.
#[tokio::test(flavor = "multi_thread")]
async fn an_unattributable_request_is_refused_at_the_upgrade() {
    let ws_port = free_port().await;
    let config = parse(&[
        "--ws-port",
        &ws_port.to_string(),
        "--trusted-proxies",
        "127.0.0.0/8",
    ])
    .unwrap();
    let handle = server::run(config).await.expect("server starts");
    let url = format!(
        "ws://{}/notarize-proxy",
        handle.ws_local_addr().expect("ws server enabled")
    );

    let refused = connect_async(&url)
        .await
        .expect_err("no forwarded client must not be keyed to the proxy");
    let tungstenite::Error::Http(response) = refused else {
        panic!("expected an HTTP refusal, got: {refused}");
    };
    assert_eq!(response.status(), 400);

    let mut request = url.as_str().into_client_request().unwrap();
    request
        .headers_mut()
        .append("x-forwarded-for", HeaderValue::from_static("203.0.113.7"));
    request
        .headers_mut()
        .append("x-forwarded-for", HeaderValue::from_static("9.9.9.9"));
    let repeated = connect_async(request)
        .await
        .expect_err("two forwarded-for lines must not be joined and guessed at");
    let tungstenite::Error::Http(response) = repeated else {
        panic!("expected an HTTP refusal, got: {repeated}");
    };
    assert_eq!(response.status(), 400);

    handle.shutdown();
}
