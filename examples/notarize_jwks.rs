//! Capture a real notarized JWKS reading from a running notary.
//!
//! Connects to the notary's TCP wire port, runs the MPC-TLS JWKS prover against
//! Google (`https://www.googleapis.com/oauth2/v3/certs`) exactly as the keeper
//! does, and writes the signed record to a JSON file: the bytes
//! `GoogleJwtRoots.rotate` takes, plus who signed them and when, so the record
//! can be replayed as a test fixture against the real contract.
//!
//! ```sh
//! notary --port 7047 --ws-port 0 \
//!     --signing-key ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
//! cargo run --example notarize_jwks -- --out google-jwks-session.json
//! ```
//!
//! The notary is the MPC verifier, so the session costs what a real one costs
//! (about ten seconds against a local notary). `RUST_LOG=info` shows the
//! phases.

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use libid_crypto::{
    keccak256,
    pubkey_to_eth_address,
    recover_eth_claim,
};
use notary::jwks::prover::notarize_jwks;
use serde::Serialize;
use tokio::net::TcpStream;

/// The endpoint the reading requests, recorded in the file for whoever reads
/// it later.
const ENDPOINT: &str = "https://www.googleapis.com/oauth2/v3/certs";

#[derive(Parser)]
#[command(about = "Capture a real notarized JWKS reading from a running notary")]
struct Args {
    /// The notary's TCP wire port (`--port`, not `--ws-port`).
    #[arg(long, default_value = "127.0.0.1:7047")]
    notary: String,
    /// Where to write the captured session.
    #[arg(long)]
    out: PathBuf,
}

/// The file written: the record and its signature as `0x`-hex, the address
/// the signature recovers to, and the notary's clock as it stamped it.
#[derive(Serialize)]
struct CapturedSession {
    /// Address that signed the record -- what the deployment trusts in its
    /// `NotaryService` before the record verifies.
    notary: String,
    /// The record's `createdAt`: unix seconds from the notary's clock, read out
    /// of the header (bytes 32..40, big-endian). The contract's freshness
    /// window is anchored to it, so a test replaying the record warps to it.
    created_at: u64,
    /// The exact bytes of ceremony-common section 9.1.
    attested_data: String,
    /// EIP-191 over `keccak256(attested_data)`.
    notary_signature: String,
    /// When this file was written, from the system clock.
    captured_at: String,
    /// What was read.
    endpoint: &'static str,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".parse().expect("static filter parses")),
        )
        .init();
    let args = Args::parse();

    let socket = TcpStream::connect(&args.notary)
        .await
        .with_context(|| format!("connect to the notary at {}", args.notary))?;
    let session = notarize_jwks(socket)
        .await
        .context("notarize the JWKS reading")?;

    // Recover the signer from the record and the signature alone, the way the
    // contract does, rather than asking the notary who it is.
    let signer = recover_eth_claim(
        &session.notary_signature,
        &keccak256(&session.attested_data),
    )
    .context("recover the signer of the record")?;
    let created_at = session
        .attested_data
        .get(32..40)
        .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
        .map(u64::from_be_bytes)
        .context("the record is shorter than its header")?;

    let captured = CapturedSession {
        notary: format!("0x{}", hex::encode(pubkey_to_eth_address(&signer))),
        created_at,
        attested_data: format!("0x{}", hex::encode(&session.attested_data)),
        notary_signature: format!("0x{}", hex::encode(&session.notary_signature)),
        captured_at: chrono::Utc::now()
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        endpoint: ENDPOINT,
    };
    let json = serde_json::to_string_pretty(&captured)?;
    std::fs::write(&args.out, format!("{json}\n"))
        .with_context(|| format!("write {}", args.out.display()))?;

    println!(
        "wrote {}: {} bytes of attested data signed by {} at created_at={}",
        args.out.display(),
        session.attested_data.len(),
        captured.notary,
        created_at,
    );
    Ok(())
}
