//! The resource limits through the public surface: the flags an operator
//! sets, and the ProxyMode session cap refusing an upgrade on the real HTTP
//! server. The limits that need a session to trip (the ProxyMode data cap,
//! the MPC-TLS queue) are unit tests beside the handlers.

use std::{
    num::NonZeroUsize,
    time::Duration,
};

use clap::Parser;
use futures_util::SinkExt;
use notary::{
    limits::Concurrency,
    server,
    NotaryServerConfig,
};
use tokio_tungstenite::{
    connect_async,
    tungstenite,
    tungstenite::Message,
};

/// anvil #0 — public test key.
const TEST_KEY: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

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
