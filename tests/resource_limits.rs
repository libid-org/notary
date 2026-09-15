//! The resource limits through the public surface: the ProxyMode session cap
//! refusing an upgrade on the real HTTP server, and giving the slot back the
//! moment the browser that held it goes away.

use std::time::Duration;

use clap::Parser;
use notary::{
    server,
    NotaryServerConfig,
};
use tokio_tungstenite::{
    connect_async,
    tungstenite,
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

    // The first browser takes the only slot and just holds the socket open.
    let (holder, _) = connect_async(&url).await.expect("first upgrade");

    let refused = connect_async(&url)
        .await
        .expect_err("second upgrade must be refused while the slot is taken");
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
