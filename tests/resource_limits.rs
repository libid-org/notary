//! The resource limits through the public surface: the flags an operator
//! sets, and the ProxyMode session caps and windows refusing an upgrade on
//! the real HTTP server. The limits that need a session to trip (the
//! ProxyMode data cap, the bytes window, the MPC-TLS queue) are unit tests
//! beside the handlers.

mod common;

use std::{
    num::NonZeroUsize,
    time::Duration,
};
use tungstenite::protocol::frame::coding::CloseCode;

use clap::Parser;
use futures_util::{
    SinkExt,
    StreamExt,
};
use notary::{
    config::ClientIpHeader,
    limits::Concurrency,
    store::WindowLimits,
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
    assert_eq!(config.max_sessions, notary::limits::DEFAULT_MAX_SESSIONS);
    assert_eq!(config.proxy_max_bytes, 10_000_000);
    assert_eq!(config.mpc_max_sessions, Concurrency::PerCore(nz(4)));
    assert_eq!(config.connection_deadline_secs, 300);
    assert_eq!(config.connection_deadline(), Duration::from_secs(300));
    assert_eq!(config.setup_deadline_secs, 15);
    assert_eq!(config.setup_deadline(), Duration::from_secs(15));
    assert_eq!(config.max_sessions_per_ip, 4);
    assert_eq!(config.client_ip_header, ClientIpHeader::XForwardedFor);
    assert_eq!(config.limits_store, None);
    // `parse` passes `--port 0`; unset is off.
    assert_eq!(config.port, Some(0));
    assert_eq!(
        NotaryServerConfig::try_parse_from(["notary", "--signing-key", TEST_KEY])
            .unwrap()
            .port,
        None
    );
    assert_eq!(config.ws_port, 7048);
    assert!(!config.internal_proxy_route);
    assert_eq!(
        config.internal_max_sessions,
        notary::limits::DEFAULT_MAX_SESSIONS
    );
    assert_eq!(
        config.per_ip_upgrades,
        "10/1m,60/30m,100/1h".parse::<WindowLimits>().unwrap()
    );
    assert_eq!(
        config.per_ip_bytes,
        "100MB/1m,600MB/30m,1GB/1h".parse::<WindowLimits>().unwrap()
    );
}

/// Attribution is explicit; the default continues to require X-Forwarded-For.
#[test]
fn client_attribution_defaults_to_x_forwarded_for() {
    assert_eq!(
        parse(&[]).unwrap().client_ip_header,
        ClientIpHeader::XForwardedFor
    );
    for (value, expected) in [
        ("none", ClientIpHeader::None),
        ("x-forwarded-for", ClientIpHeader::XForwardedFor),
        ("cf-connecting-ip", ClientIpHeader::CfConnectingIp),
    ] {
        assert_eq!(
            parse(&["--client-ip-header", value])
                .unwrap()
                .client_ip_header,
            expected,
            "{value:?}"
        );
    }

    let error = parse(&["--client-ip-header", "true-client-ip"])
        .expect_err("an unknown header must not start the notary")
        .to_string();
    assert!(error.contains("--client-ip-header"), "{error}");
    assert!(
        error.contains("x-forwarded-for") && error.contains("cf-connecting-ip"),
        "{error}"
    );
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

/// The one client the tests that are not about clients speak as.
const A_CLIENT: &str = "203.0.113.7";

/// The upgrade request for `url` with `header` set to `value`, the way the
/// load balancer names the client.
fn upgrade_with(
    url: &str,
    header: &'static str,
    value: &str,
) -> tungstenite::http::Request<()> {
    let mut request = url.into_client_request().unwrap();
    request
        .headers_mut()
        .insert(header, HeaderValue::from_str(value).unwrap());
    request
}

/// The upgrade request for `url` naming `client` in `X-Forwarded-For`.
fn upgrade_from(url: &str, client: &str) -> tungstenite::http::Request<()> {
    upgrade_with(url, "x-forwarded-for", client)
}

/// Past `--max-sessions`, the upgrade is refused with 503 -- not queued --
/// and the slot comes back as soon as the session holding it ends.
#[tokio::test(flavor = "multi_thread")]
async fn proxy_upgrade_past_max_sessions_is_refused_with_503() {
    let (handle, _) = common::start_server(|ws_port| {
        parse(&["--ws-port", &ws_port.to_string(), "--max-sessions", "1"]).unwrap()
    })
    .await;
    let url = format!(
        "ws://{}/notarize-proxy",
        handle.ws_local_addr().expect("ws server enabled")
    );

    // The first browser takes the only slot by starting a session -- sending
    // the bytes it wants relayed. Upgrading alone reserves nothing.
    let (mut holder, _) = connect_async(upgrade_from(&url, A_CLIENT))
        .await
        .expect("first upgrade");
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
            if connect_async(upgrade_from(&url, A_CLIENT)).await.is_ok() {
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
    let (handle, _) = common::start_server(|ws_port| {
        parse(&["--ws-port", &ws_port.to_string(), "--max-sessions", "1"]).unwrap()
    })
    .await;
    let url = format!(
        "ws://{}/notarize-proxy",
        handle.ws_local_addr().expect("ws server enabled")
    );

    // Upgraded and held open, but never a byte of session data.
    let (silent, _) = connect_async(upgrade_from(&url, A_CLIENT))
        .await
        .expect("first upgrade");

    // A ping keeps the socket warm without starting a session; it must not
    // buy a slot either.
    let (mut pinger, _) = connect_async(upgrade_from(&url, A_CLIENT))
        .await
        .expect("second upgrade");
    pinger
        .send(Message::Ping(Vec::new().into()))
        .await
        .expect("ping");

    // The only slot is still free, so a real browser gets in.
    let (mut real, _) = connect_async(upgrade_from(&url, A_CLIENT))
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
    drop(silent);

    handle.shutdown();
}

/// Connect until the server refuses, or fail the test. The slot is taken
/// asynchronously, once the server has read the first frame, so the refusal
/// arrives a moment after the frame is sent.
async fn until_refused(url: &str) -> tungstenite::Error {
    let refused = async {
        loop {
            match connect_async(upgrade_from(url, A_CLIENT)).await {
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

/// Open a ProxyMode session with `header` naming `client`, and start it.
async fn session_with(
    url: &str,
    header: &'static str,
    client: &str,
) -> Result<Socket, tungstenite::Error> {
    let (mut socket, _) = connect_async(upgrade_with(url, header, client)).await?;
    // The slot is spent on a session, so start one.
    socket
        .send(Message::Binary(b"\x16\x03\x01".to_vec().into()))
        .await
        .expect("the browser sends its first TLS bytes");
    Ok(socket)
}

/// Open a ProxyMode session claiming to come from `client`, as the load
/// balancer would say it: the rightmost `X-Forwarded-For` entry.
async fn session_from(url: &str, client: &str) -> Result<Socket, tungstenite::Error> {
    session_with(url, "x-forwarded-for", client).await
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
/// against the address the load balancer forwarded -- the rightmost entry,
/// whatever the caller put before it -- and gets one back when a session
/// ends.
#[tokio::test(flavor = "multi_thread")]
async fn the_per_ip_cap_counts_the_rightmost_forwarded_address() {
    let (handle, _) = common::start_server(|ws_port| {
        parse(&[
            "--ws-port",
            &ws_port.to_string(),
            "--max-sessions",
            "64",
            "--max-sessions-per-ip",
            "2",
            // Off, so the retries below are refused by the cap or by nothing.
            "--per-ip-upgrades",
            "",
        ])
        .unwrap()
    })
    .await;
    let url = format!(
        "ws://{}/notarize-proxy",
        handle.ws_local_addr().expect("ws server enabled")
    );

    let first = session_from(&url, "203.0.113.7")
        .await
        .expect("first session");
    let second = session_from(&url, "203.0.113.7")
        .await
        .expect("second session");

    // A third from the same client is upgraded -- the notary has 64 slots --
    // and then closed, because this client has none.
    let mut third = session_from(&url, "203.0.113.7")
        .await
        .expect("the upgrade itself is not refused");
    let (code, reason) = close_reason(&mut third).await;
    assert_eq!(code, u16::from(CloseCode::Again), "reason: {reason}");
    assert!(reason.contains("this client"), "{reason}");

    // A forged prefix does not buy a fresh budget: the balancer's entry is
    // still the rightmost, and still this client.
    let mut forged = session_from(&url, "9.9.9.9, 203.0.113.7")
        .await
        .expect("upgrade");
    assert_eq!(
        close_reason(&mut forged).await.0,
        u16::from(CloseCode::Again)
    );

    // Another client is unaffected -- the cap is per client, and the key is
    // the forwarded address rather than the peer every one of these shares.
    let other = session_from(&url, "198.51.100.4")
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
    let reopened = tokio::time::timeout(Duration::from_secs(5), reopened)
        .await
        .expect("the lease was not released when its session ended");

    handle.shutdown();
    drop(reopened);
    drop(other);
    drop(second);
}

/// `--per-ip-upgrades` counts sessions started per window, at the upgrade:
/// past it the client gets 429 and a `Retry-After`, before anything has been
/// spent on it, and another client is not affected.
#[tokio::test(flavor = "multi_thread")]
async fn the_upgrades_window_refuses_the_next_upgrade_with_429() {
    let (handle, _) = common::start_server(|ws_port| {
        parse(&[
            "--ws-port",
            &ws_port.to_string(),
            "--per-ip-upgrades",
            "2/1h",
        ])
        .unwrap()
    })
    .await;
    let url = format!(
        "ws://{}/notarize-proxy",
        handle.ws_local_addr().expect("ws server enabled")
    );

    // Two sessions in the hour, finished or not: the window counts starts.
    let first = session_from(&url, "203.0.113.7")
        .await
        .expect("first session");
    drop(first);
    let second = session_from(&url, "203.0.113.7")
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

    let other = session_from(&url, "198.51.100.4")
        .await
        .expect("a different client has its own window");

    handle.shutdown();
    drop(other);
    drop(second);
}

/// A public upgrade that names no client is refused with 400, never counted
/// against the socket peer -- which every browser shares -- and so is one
/// that names it twice. The same upgrade with the header goes through.
#[tokio::test(flavor = "multi_thread")]
async fn an_unattributable_request_is_refused_at_the_upgrade() {
    let (handle, _) = common::start_server(|ws_port| {
        parse(&["--ws-port", &ws_port.to_string()]).unwrap()
    })
    .await;
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

    let malformed = connect_async(upgrade_from(&url, "not-an-ip"))
        .await
        .expect_err("an invalid header must not fall back to the peer");
    let tungstenite::Error::Http(response) = malformed else {
        panic!("expected an HTTP refusal, got: {malformed}");
    };
    assert_eq!(response.status(), 400);

    let (named, response) = connect_async(upgrade_from(&url, A_CLIENT))
        .await
        .expect("the same upgrade with the header is admitted");
    assert_eq!(response.status(), 101);
    drop(named);

    handle.shutdown();
}

/// Direct clients need no forwarding header, and forged headers cannot buy
/// another peer's upgrade-window budget.
#[tokio::test(flavor = "multi_thread")]
async fn direct_mode_keys_the_upgrade_window_on_the_peer() {
    let (handle, _) = common::start_server(|ws_port| {
        parse(&[
            "--ws-port",
            &ws_port.to_string(),
            "--client-ip-header",
            "none",
            "--per-ip-upgrades",
            "4/1h",
        ])
        .unwrap()
    })
    .await;
    let url = format!(
        "ws://{}/notarize-proxy",
        handle.ws_local_addr().expect("ws server enabled")
    );
    let (first, response) = connect_async(&url)
        .await
        .expect("a direct browser needs no custom headers");
    assert_eq!(response.status(), 101);
    drop(first);

    let mut forged = upgrade_from(&url, "203.0.113.7");
    forged
        .headers_mut()
        .insert("cf-connecting-ip", HeaderValue::from_static("198.51.100.4"));
    let mut malformed = upgrade_from(&url, "not-an-ip");
    malformed
        .headers_mut()
        .insert("cf-connecting-ip", HeaderValue::from_static("invalid"));
    let mut repeated = forged.clone();
    repeated
        .headers_mut()
        .append("x-forwarded-for", HeaderValue::from_static("9.9.9.9"));
    repeated
        .headers_mut()
        .append("cf-connecting-ip", HeaderValue::from_static("8.8.8.8"));

    for request in [forged, malformed, repeated] {
        let (socket, response) = connect_async(request).await.expect(
            "direct mode ignores forwarded headers even when malformed or repeated",
        );
        assert_eq!(response.status(), 101);
        drop(socket);
    }

    let refused = connect_async(upgrade_from(&url, "192.0.2.1"))
        .await
        .expect_err("all four upgrades count against the socket peer");
    let tungstenite::Error::Http(response) = refused else {
        panic!("expected an HTTP refusal, got: {refused}");
    };
    assert_eq!(response.status(), 429);
    handle.shutdown();
}

/// With `--client-ip-header cf-connecting-ip` the client is `CF-Connecting-IP`
/// and nothing else: an upgrade carrying only `X-Forwarded-For` is refused
/// with 400, one carrying the Cloudflare header goes through, and the
/// per-client cap counts that header's value.
#[tokio::test(flavor = "multi_thread")]
async fn cf_connecting_ip_mode_keys_on_the_cloudflare_header() {
    let (handle, _) = common::start_server(|ws_port| {
        parse(&[
            "--ws-port",
            &ws_port.to_string(),
            "--client-ip-header",
            "cf-connecting-ip",
            "--max-sessions-per-ip",
            "1",
            // Off, so the cap is the only thing that can close a session.
            "--per-ip-upgrades",
            "",
        ])
        .unwrap()
    })
    .await;
    let url = format!(
        "ws://{}/notarize-proxy",
        handle.ws_local_addr().expect("ws server enabled")
    );

    let refused = session_from(&url, "203.0.113.7")
        .await
        .expect_err("X-Forwarded-For names no client in cf-connecting-ip mode");
    let tungstenite::Error::Http(response) = refused else {
        panic!("expected an HTTP refusal, got: {refused}");
    };
    assert_eq!(response.status(), 400);

    let mut first = session_with(&url, "cf-connecting-ip", "203.0.113.7")
        .await
        .expect("the Cloudflare header names the client");
    assert!(holds(&mut first, Duration::from_millis(200)).await);

    // The key is the header's value: another value is another client, with
    // a budget of its own; the same value is this client, at its cap.
    let mut other = session_with(&url, "cf-connecting-ip", "198.51.100.4")
        .await
        .expect("a different client must not share the budget");
    assert!(holds(&mut other, Duration::from_millis(200)).await);
    let mut same = session_with(&url, "cf-connecting-ip", "203.0.113.7")
        .await
        .expect("the upgrade itself is not refused");
    let (code, reason) = close_reason(&mut same).await;
    assert_eq!(code, u16::from(CloseCode::Again), "reason: {reason}");
    assert!(reason.contains("this client"), "{reason}");

    handle.shutdown();
}
