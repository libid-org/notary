//! What the session tests share: the server `smoke.rs` boots, and the checks
//! a signed record must pass whichever transport carried it.

// Each test binary compiles this module on its own and uses its own subset.
#![allow(dead_code)]

use std::time::SystemTime;

use clap::Parser;
use libid_ceremony::{
    attestation::HEADER_LEN,
    AttestedData,
    DirectionBlock,
    RevealedRange,
};
use libid_transcript::AttestationWire;
use notary::NotaryServerConfig;

/// anvil #0 — public test key.
pub const TEST_KEY: &str =
    "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/// The compressed SEC1 public key for [`TEST_KEY`], as `/info` serves it.
pub const TEST_PUBKEY: &str =
    "038318535b54105d4a7aae60c08fc45f9687181b4fdfc625bd1a753fa7397fed75";

/// A clock skew no test machine should exceed between the notary stamping
/// `created_at` and the test reading it back.
const CLOCK_SLACK_SECS: u64 = 300;

/// Reserve an ephemeral port for the HTTP server: ws_port 0 means "disabled",
/// so bind-then-drop to learn a free port number. (The tiny race with another
/// process is acceptable in a test.)
pub async fn free_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

/// The TCP wire port ephemeral, the HTTP server on `ws_port` (0 disables it),
/// [`TEST_KEY`] as the identity. Built through clap so the tests stay honest
/// to the real CLI surface.
pub fn test_config(ws_port: u16) -> NotaryServerConfig {
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

/// The record one completed session must have produced, given what the prover
/// saw of it.
///
/// Rebuilds the section 9.1 attested data from the prover's own transcript --
/// everything revealed, nothing committed -- and requires the notary's bytes
/// to equal it, so a record that names another host, drops a byte or moves a
/// field fails here rather than on chain. `created_at` is the notary's clock:
/// it is read back out of the record and only required to be recent. The
/// signature must recover to `notary_pubkey_hex`, compressed SEC1 as `/info`
/// serves it.
pub fn assert_attests(
    attestation: &AttestationWire,
    authority: &str,
    sent: &[u8],
    recv: &[u8],
    notary_pubkey_hex: &str,
) {
    let data = &attestation.attested_data;
    assert!(
        data.len() >= HEADER_LEN,
        "attested data is {} bytes, shorter than its header",
        data.len()
    );
    let created_at = u64::from_be_bytes(data[32..40].try_into().unwrap());
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(
        now.abs_diff(created_at) <= CLOCK_SLACK_SECS,
        "created_at {created_at} is not the notary's clock (now {now})"
    );

    let whole = |bytes: &[u8]| DirectionBlock {
        revealed: vec![RevealedRange {
            start: 0,
            bytes: bytes.to_vec(),
        }],
        commitments: Vec::new(),
    };
    let expected = AttestedData {
        authority_id: AttestedData::authority_id_of(authority),
        created_at,
        sent_transcript_length: u32::try_from(sent.len()).unwrap(),
        recv_transcript_length: u32::try_from(recv.len()).unwrap(),
        sent: whole(sent),
        received: whole(recv),
    }
    .encode()
    .unwrap();
    assert!(
        *data == expected,
        "attested data is not the record of this session against {authority}"
    );

    let recovered = libid_crypto::recover_eth_claim(
        &attestation.notary_signature,
        &libid_crypto::keccak256(data),
    )
    .expect("the notary signature recovers to a key");
    assert_eq!(
        hex::encode(recovered.to_encoded_point(true).as_bytes()),
        notary_pubkey_hex,
        "the record is signed by a key other than the notary's"
    );
}
