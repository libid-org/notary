//! Runtime configuration (clap + environment).

use clap::Parser;

use crate::error::{
    Error,
    Result,
};

/// Configuration for the notary server.
#[derive(Parser, Debug)]
#[command(name = "notary", version, about)]
pub struct NotaryServerConfig {
    /// Host to bind on.
    #[arg(long, env = "NOTARY_HOST", default_value = "127.0.0.1")]
    pub host: String,

    /// TCP wire-protocol port (backend provers: platform MPC-TLS sessions and
    /// JWKS notarization sessions). `0` binds an ephemeral port.
    #[arg(long, env = "NOTARY_PORT", default_value = "7047")]
    pub port: u16,

    /// HTTP/WebSocket port (browser / tlsn-js / tlsn_wasm clients). `0`
    /// disables the HTTP server entirely.
    #[arg(long, env = "NOTARY_WS_PORT", default_value = "7048")]
    pub ws_port: u16,

    /// Notary signing key: a hex-encoded secp256k1 private key, or
    /// `kms:<key-id-or-alias>` for an AWS KMS key.
    #[arg(long, env = "SIGNING_KEY")]
    pub signing_key: String,

    /// EVM chain id of the deployment these attestations target. Baked
    /// into the signed digest so a single notary key can't replay across
    /// chains.
    #[arg(long, env = "CHAIN_ID", default_value = "31337")]
    pub chain_id: u64,

    /// Address (`0x...`) of the contract that recovers the MPC-TLS notary
    /// signature (bound into the digest as the EIP-712-style
    /// `verifyingContract`). In wallet deployments this is the `Registry`;
    /// in identity deployments it is `GitHubIdentityVerifier` — hence the
    /// honest name. `--registry-contract-address` and the
    /// `REGISTRY_CONTRACT_ADDRESS` env var are accepted as legacy aliases.
    #[arg(
        long = "verifying-contract",
        visible_alias = "registry-contract-address",
        env = "VERIFYING_CONTRACT_ADDRESS",
        default_value = ""
    )]
    pub verifying_contract: String,

    /// SNI / `platformName` the ZK verifier on-chain is configured for.
    /// The notary hashes this value into the token + me attestation digests
    /// so a deployment that changes `platformName` will not accidentally
    /// accept signatures issued for a different platform.
    #[arg(long, env = "NOTARY_PLATFORM_NAME", default_value = "api.x.com")]
    pub platform_name: String,

    /// Max concurrent live sessions before `POST /session` is rejected (503).
    /// A capacity / DoS-defense knob — tune per deployment (notary RAM,
    /// expected concurrent provers). The background sweep bounds each entry's
    /// lifetime; this bounds the burst rate.
    #[arg(long, env = "NOTARY_MAX_SESSIONS", default_value_t = 1024)]
    pub max_sessions: usize,

    /// Serve JWKS notarization sessions on the TCP wire listener (an MPC-TLS
    /// session whose TLS-verified SNI is `www.googleapis.com` is answered
    /// with a signed `JwksRotationProof` instead of the platform
    /// `NotaryResponse`). Same notary identity, same listener.
    #[arg(
        long,
        env = "NOTARY_JWKS_ENABLED",
        default_value_t = true,
        action = clap::ArgAction::Set
    )]
    pub jwks_enabled: bool,
}

/// The zero address, used when no MPC verifying contract is configured
/// (matches the digest a contract-less dev deployment verifies against).
const ZERO_ADDRESS: &str = "0x0000000000000000000000000000000000000000";

impl NotaryServerConfig {
    /// Resolve the MPC-TLS `verifyingContract` address, honouring the legacy
    /// `REGISTRY_CONTRACT_ADDRESS` environment variable when neither the
    /// `--verifying-contract` flag nor `VERIFYING_CONTRACT_ADDRESS` was set.
    pub fn resolve_verifying_contract(&self) -> Result<[u8; 20]> {
        let spec = if !self.verifying_contract.is_empty() {
            self.verifying_contract.clone()
        } else if let Ok(legacy) = std::env::var("REGISTRY_CONTRACT_ADDRESS") {
            legacy
        } else {
            ZERO_ADDRESS.to_string()
        };
        parse_hex_address(&spec)
    }
}

/// Parse a `0x`-prefixed 20-byte address string into raw bytes.
pub(crate) fn parse_hex_address(s: &str) -> Result<[u8; 20]> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    if stripped.len() != 40 {
        return Err(Error::NotaryServer {
            detail: format!("invalid contract address length: '{s}' (want 0x + 40 hex)"),
        });
    }
    let bytes = hex::decode(stripped).map_err(|e| Error::NotaryServer {
        detail: format!("invalid contract address hex: {e}"),
    })?;
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::parse_hex_address;

    #[test]
    fn parse_hex_address_accepts_0x_prefix() {
        let got =
            parse_hex_address("0x1234567890123456789012345678901234567890").unwrap();
        assert_eq!(got[0], 0x12);
        assert_eq!(got[19], 0x90);
    }

    #[test]
    fn parse_hex_address_accepts_no_prefix() {
        let got = parse_hex_address("1234567890123456789012345678901234567890").unwrap();
        assert_eq!(got[0], 0x12);
        assert_eq!(got[19], 0x90);
    }

    #[test]
    fn parse_hex_address_rejects_short() {
        assert!(parse_hex_address("0xdeadbeef").is_err());
    }

    #[test]
    fn parse_hex_address_rejects_long() {
        assert!(
            parse_hex_address("0x12345678901234567890123456789012345678901234").is_err()
        );
    }

    #[test]
    fn parse_hex_address_rejects_non_hex() {
        assert!(parse_hex_address("0xZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ").is_err());
    }
}
