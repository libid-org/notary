//! Runtime configuration (clap + environment).

use clap::Parser;

use crate::limits::Concurrency;

/// Configuration for the notary server.
#[derive(Parser, Debug)]
#[command(name = "notary", version, about)]
pub struct NotaryServerConfig {
    /// Host to bind on.
    #[arg(long, env = "NOTARY_HOST", default_value = "127.0.0.1")]
    pub host: String,

    /// TCP wire-protocol port for Rust backend provers. `0` binds an ephemeral
    /// port.
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

    /// Max concurrent browser ProxyMode sessions. A slot is taken when the
    /// browser sends its first relayed bytes, not when it upgrades, so an
    /// upgraded socket that says nothing costs no slot. Past the limit the
    /// upgrade is refused with 503 and the browser retries; nothing queues. A
    /// session is one relay task plus its transcript, bounded by
    /// `--proxy-max-bytes`, so this can stay large.
    /// `--connection-deadline-secs` bounds how long one slot stays taken.
    #[arg(long, env = "NOTARY_MAX_SESSIONS", default_value_t = 1024)]
    pub max_sessions: usize,

    /// Bytes one ProxyMode session may relay in total, both directions
    /// combined. The default is 10 MB, meaning 10,000,000 bytes. Counted on
    /// every read and write of the relayed TLS stream: the operation that
    /// crosses the cap fails, the session is aborted with WebSocket close code
    /// 1008 and reason `PROXY_DATA_CAP_EXCEEDED`, and nothing is attested. The
    /// stream is never truncated, because a shortened transcript would attest
    /// as a complete one. Per-session memory is bounded by this plus one I/O
    /// buffer. MPC-TLS has its own, far smaller limits, negotiated at session
    /// setup and logged at startup; this cap does not apply to it.
    #[arg(long, env = "NOTARY_PROXY_MAX_BYTES", default_value_t = 10_000_000)]
    pub proxy_max_bytes: usize,

    /// Concurrent MPC-TLS sessions on the TCP wire port: a count (`16`) or a
    /// multiple of the cores this process may use (`4x`, the default), which is
    /// resolved once at startup and logged. A slot is taken once the prover has
    /// sent its first byte, not on accept, so a connection that says nothing
    /// never holds one. A prover past the limit waits its turn rather than
    /// being refused, because it cannot cheaply retry once it has paid for MPC
    /// setup; `--connection-deadline-secs` caps the wait.
    #[arg(long, env = "NOTARY_MPC_MAX_SESSIONS", default_value_t = Concurrency::default())]
    pub mpc_max_sessions: Concurrency,

    /// Seconds one prover connection may live, on either transport, from the
    /// moment its session starts to the attestation being written; for MPC-TLS
    /// that includes time spent waiting for a session slot. Past it the
    /// connection is dropped and nothing is attested. A real session finishes
    /// in well under a minute even on a slow link, so the default is headroom,
    /// not a budget.
    #[arg(
        long,
        env = "NOTARY_CONNECTION_DEADLINE_SECS",
        default_value_t = 300,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub connection_deadline_secs: u64,

    /// Seconds a connection has to start its session: to send its first byte
    /// on the TCP port, or its first binary frame on the WebSocket. Until it
    /// does it holds no session slot, so this bounds only how long an idle
    /// socket may sit -- which is the point. A slot taken on accept would let
    /// anyone able to open a socket reserve the notary's scarcest resource
    /// without speaking the protocol, and hold it for the whole connection
    /// deadline. A real client sends immediately; the default is for a slow
    /// network, not for a slow client.
    #[arg(
        long,
        env = "NOTARY_SETUP_DEADLINE_SECS",
        default_value_t = 15,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub setup_deadline_secs: u64,
}

impl NotaryServerConfig {
    /// `--connection-deadline-secs` as a duration.
    pub fn connection_deadline(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.connection_deadline_secs)
    }

    /// `--setup-deadline-secs` as a duration.
    pub fn setup_deadline(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.setup_deadline_secs)
    }
}
