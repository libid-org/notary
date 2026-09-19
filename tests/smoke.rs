//! Boot the whole server on ephemeral ports with a local hex key and drive
//! the HTTP API the way the browser prover does.

mod common;

use clap::Parser;
use notary::{
    server,
    NotaryServerConfig,
};

/// anvil #0 — public test key.
const TEST_KEY: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/// The compressed SEC1 public key for [`TEST_KEY`], as `/info` must serve it.
const TEST_PUBKEY: &str =
    "038318535b54105d4a7aae60c08fc45f9687181b4fdfc625bd1a753fa7397fed75";

fn test_config(ws_port: u16) -> NotaryServerConfig {
    // Build through clap so defaults and the smoke test stay honest to the
    // real CLI surface.
    NotaryServerConfig::parse_from([
        "notary",
        "--host",
        "127.0.0.1",
        "--port",
        "0",
        "--ws-port",
        &ws_port.to_string(),
        "--signing-key",
        TEST_KEY,
    ])
}

#[tokio::test(flavor = "multi_thread")]
async fn info_works() {
    let (handle, _) = common::start_server(test_config).await;
    let ws_addr = handle.ws_local_addr().expect("ws server enabled");
    let base = format!("http://{ws_addr}");
    let client = reqwest::Client::new();

    // GET /info serves the version and the notary's compressed public key.
    let info: serde_json::Value = client
        .get(format!("{base}/info"))
        .send()
        .await
        .expect("GET /info")
        .json()
        .await
        .expect("info json");
    assert_eq!(info["publicKey"], TEST_PUBKEY);
    assert_eq!(info["version"], format!("v{}", env!("CARGO_PKG_VERSION")));

    handle.shutdown();
}

#[tokio::test(flavor = "multi_thread")]
async fn ws_port_zero_disables_http_server() {
    let handle = server::run(test_config(0)).await.expect("server starts");
    assert!(handle.ws_local_addr().is_none());
    handle.shutdown();
}
