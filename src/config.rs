//! Runtime configuration (clap + environment).

use clap::Parser;

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

    /// Max concurrent live sessions before `POST /session` is rejected (503).
    /// A capacity / DoS-defense knob — tune per deployment (notary RAM,
    /// expected concurrent provers). The background sweep bounds each entry's
    /// lifetime; this bounds the burst rate.
    #[arg(long, env = "NOTARY_MAX_SESSIONS", default_value_t = 1024)]
    pub max_sessions: usize,

    /// Serve JWKS notarization sessions on the TCP wire listener (an MPC-TLS
    /// session whose TLS-verified SNI is `www.googleapis.com` is answered
    /// with a signed `JwksRotationProof` instead of the platform's ceremony
    /// attestation). Same notary identity, same listener.
    #[arg(
        long,
        env = "NOTARY_JWKS_ENABLED",
        default_value_t = true,
        action = clap::ArgAction::Set
    )]
    pub jwks_enabled: bool,
}
