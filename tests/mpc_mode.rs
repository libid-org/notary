//! MPC-TLS end to end through the TCP listener, with the prover the keeper
//! runs: `libid_tlsn::prover_generic` against a booted server, and the signed
//! record read back off the socket the session reclaimed.
//!
//! Live, against the host the keeper reads in production, and therefore
//! `#[ignore]`d from the default run. CI runs it as its own step; locally:
//!
//! ```text
//! cargo test --test mpc_mode -- --ignored
//! ```
//!
//! It cannot be made offline from this repository. The TCP path is
//! `handle_notary_session` → `libid_tlsn::verifier(socket)`, which takes only
//! the socket and authenticates the server against libid-tlsn's compiled-in
//! WebPKI roots (`libid-tlsn/src/session.rs`: `verifier` builds its
//! `VerifierConfig` from `root_store()`), so no server signed by a local root
//! can complete it. The in-crate test
//! `mpc_protocol_returns_attestation_on_the_recovered_socket` covers the same
//! session offline by building the verifier itself around the fixture's root,
//! and so never enters `libid_tlsn::verifier` or the listener. This one does.

use std::time::Duration;

use libid_tlsn::{
    Bytes,
    HttpBody,
    HttpRequest,
};
use libid_transcript::{
    ceremony::Layout,
    read_msg,
    AttestationWire,
};
use notary::server;
use tokio::{
    io::AsyncReadExt,
    net::TcpStream,
};

mod common;
use common::{
    assert_attests,
    test_config,
    TEST_PUBKEY,
};

/// The keeper's reading: Google's OIDC key set, over TLS 1.2 with a cipher
/// suite TLSNotary's MPC-TLS supports.
const HOST: &str = "www.googleapis.com";
const PATH: &str = "/oauth2/v3/certs";

/// Generous for a debug build on a CI runner; a real session is well under it.
const SESSION_DEADLINE: Duration = Duration::from_secs(240);

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live MPC-TLS session against www.googleapis.com; run with --ignored"]
async fn mpc_session_over_the_tcp_listener_ends_in_a_signed_attestation() {
    let handle = server::run(test_config(0)).await.expect("server starts");
    let socket = TcpStream::connect(handle.local_addr())
        .await
        .expect("TCP wire port");

    // The same request the keeper's prover sends, minus its user agent.
    let request = HttpRequest::builder()
        .method("GET")
        .uri(format!("https://{HOST}{PATH}"))
        .header("Host", HOST)
        .header("Connection", "close")
        .header("Accept", "application/json")
        .header(
            "User-Agent",
            concat!("libid-notary-test/", env!("CARGO_PKG_VERSION")),
        )
        .body(HttpBody::new(Bytes::new()))
        .unwrap();

    // The prover chooses its layout from the transcript it just made, and that
    // callback is the one place the transcript is visible: `ProverResult`
    // carries the response body only. Keep a copy to check the record against.
    let mut transcript = None;
    let result = tokio::time::timeout(
        SESSION_DEADLINE,
        libid_tlsn::prover_generic(
            socket,
            request,
            |sent, recv| {
                transcript = Some((sent.to_vec(), recv.to_vec()));
                let whole = |bytes: &[u8]| Layout {
                    reveal: std::iter::once(0..bytes.len()).collect(),
                    commit: Vec::new(),
                };
                Ok((whole(sent), whole(recv)))
            },
            |_| {},
        ),
    )
    .await
    .expect("MPC-TLS session timed out")
    .expect("MPC-TLS session against the notary");
    let (sent, recv) = transcript.expect("the prover chose a layout");
    assert!(
        sent.starts_with(format!("GET {PATH} HTTP/1.1\r\n").as_bytes()),
        "sent transcript does not open with the request line"
    );
    assert!(
        recv.starts_with(b"HTTP/1.1 200"),
        "received transcript does not open with a 200"
    );

    // The record comes back down the socket the session reclaimed, then EOF.
    let mut io = result.recovered_io;
    let attestation: AttestationWire = read_msg(&mut io)
        .await
        .expect("an attestation follows the session");
    assert_eq!(
        io.read(&mut [0]).await.unwrap(),
        0,
        "bytes after the attestation"
    );
    assert_attests(&attestation, HOST, &sent, &recv, TEST_PUBKEY);
    handle.shutdown();
}
