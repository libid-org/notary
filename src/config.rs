//! Runtime configuration (clap + environment).

use clap::{
    Parser,
    ValueEnum,
};
use tlsn::webpki::CertificateDer;

use crate::{
    limits::Concurrency,
    store::{
        redact,
        WindowLimits,
    },
};

/// Configuration for the notary server.
#[derive(Parser, Debug)]
#[command(name = "notary", version, about)]
pub struct NotaryServerConfig {
    /// Host to bind on.
    #[arg(long, env = "NOTARY_HOST", default_value = "127.0.0.1")]
    pub host: String,

    /// The internal MPC-TLS wire port, for Rust provers inside the cluster.
    /// Off unless set: this port has no per-client limits, because our own
    /// services are the protocol, not users of it, so it must never be
    /// reachable from outside. Publish it through the cluster Service only.
    /// The conventional value is 7047; `0` binds an ephemeral port.
    #[arg(long, env = "NOTARY_PORT")]
    pub port: Option<u16>,

    /// The public HTTP/WebSocket port: browser ProxyMode, behind the load
    /// balancer, with every per-client limit in force. `0` disables it.
    #[arg(long, env = "NOTARY_WS_PORT", default_value_t = 7048)]
    pub ws_port: u16,

    /// Mount `GET /internal/notarize-proxy` on the public port: ProxyMode for
    /// our own in-cluster services, with no per-client limits, its own
    /// session pool (`--internal-max-sessions`), and the limits store never
    /// consulted. Off unless set; without it the route does not exist (404).
    ///
    /// The route MUST be blocked at the load balancer -- a fixed-response 403
    /// for `/internal/*` -- because nothing on it limits a caller. As defence
    /// in depth the notary answers 403 itself whenever the request carries
    /// `X-Forwarded-For` or `CF-Connecting-IP`, since the balancer always adds
    /// one; that backstop is not the control.
    #[arg(long, env = "NOTARY_INTERNAL_PROXY_ROUTE")]
    pub internal_proxy_route: bool,

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

    /// Max concurrent ProxyMode sessions on the internal route. Its own
    /// pool, so public load can never queue our own services behind it.
    #[arg(long, env = "NOTARY_INTERNAL_MAX_SESSIONS", default_value_t = 1024)]
    pub internal_max_sessions: usize,

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

    /// Max concurrent public ProxyMode sessions from one client. `0` disables
    /// the per-client cap.
    ///
    /// Concurrency, not request rate, because that is what a session costs:
    /// one relay task, its transcript, and up to `--proxy-max-bytes`, held
    /// until it ends. One browser ceremony opens two sessions at once, so the
    /// default leaves a user one ceremony of headroom -- and a shared office
    /// address two users.
    ///
    /// The client is whoever `--client-ip-header` names; see there.
    #[arg(long, env = "NOTARY_MAX_SESSIONS_PER_IP", default_value_t = 4)]
    pub max_sessions_per_ip: usize,

    /// Sessions one client may START per window on the public port, as
    /// `<count>/<window>` entries: `10/1m,60/30m,100/1h`. Every window must
    /// have room. Empty disables it.
    ///
    /// The concurrency cap bounds what a client holds now; this bounds how
    /// much of the pool's time it consumes by finishing one session and
    /// starting the next. Counted at the upgrade, in the shared store, so it
    /// holds across replicas.
    #[arg(
        long,
        env = "NOTARY_PER_IP_UPGRADES",
        default_value = "10/1m,60/30m,100/1h"
    )]
    pub per_ip_upgrades: String,

    /// Bytes one client may relay per window on the public port, both
    /// directions, as `<size>/<window>` entries: `100MB/1m,600MB/30m,1GB/1h`.
    /// Charged when a session ends; a client whose windows are full is
    /// refused at its next upgrade. Empty disables it.
    #[arg(
        long,
        env = "NOTARY_PER_IP_BYTES",
        default_value = "100MB/1m,600MB/30m,1GB/1h"
    )]
    pub per_ip_bytes: String,

    /// Which header names the client on the public port. Every per-client
    /// limit counts against it, and a public upgrade without it is refused
    /// with 400: behind a load balancer the socket peer is the balancer, so
    /// there is nothing else to key on.
    ///
    /// `x-forwarded-for`: the client is the RIGHTMOST `X-Forwarded-For`
    /// entry -- the address that connected to the load balancer, which the
    /// balancer appends last. Set when the notary sits directly behind the
    /// ALB (Cloudflare DNS-only, grey cloud).
    ///
    /// `cf-connecting-ip`: the client is the `CF-Connecting-IP` value
    /// Cloudflare adds. Set ONLY when the Cloudflare DNS record is proxied
    /// (orange cloud); with it set while the record is grey, every public
    /// request is a 400, which is loud rather than wrong.
    ///
    /// The limitation: nothing verifies who wrote the header. Anything that
    /// can reach the public port directly can set it and choose its own
    /// key, so the public port must be reachable only through the load
    /// balancer. That is the deployment's job, not the notary's. The
    /// internal route keys on no header; a request there carrying one is
    /// refused.
    #[arg(
        long,
        env = "NOTARY_CLIENT_IP_HEADER",
        value_enum,
        default_value_t = ClientIpHeader::XForwardedFor
    )]
    pub client_ip_header: ClientIpHeader,

    /// Where the public port's per-client counts live: a Postgres URL
    /// (`postgres://user:pass@host/db`), or the literal `memory` for a
    /// single replica.
    ///
    /// The load balancer spreads one client's connections across every
    /// replica, so a count kept in one process is a limit multiplied by the
    /// replica count. `memory` says that is understood. With a per-client
    /// limit on a non-loopback address, an empty setting refuses to start.
    #[arg(long, env = "NOTARY_LIMITS_STORE", default_value = "")]
    pub limits_store: String,

    /// TEST HOOK. Where every ProxyMode session dials, as `<ip>:<port>`,
    /// instead of `<server name>:443`. It exists so a test suite can run the
    /// real binary against a local TLS fixture; the server name a session
    /// authenticates is unchanged, so the fixture has to hold a certificate
    /// for it. Refused on any non-loopback `--host`: a notary reachable
    /// from off the machine dials the server it authenticates and nothing
    /// else.
    #[arg(long, env = "NOTARY_PROXY_UPSTREAM")]
    pub proxy_upstream: Option<String>,

    /// TEST HOOK, with `--proxy-upstream`: a CA certificate file, DER or
    /// PEM, added to the roots the upstream's certificate is verified
    /// against, so a local fixture holding a certificate for the server
    /// name is accepted. Refused without `--proxy-upstream`, and with it
    /// on any non-loopback `--host`.
    #[arg(long, env = "NOTARY_PROXY_UPSTREAM_CA", requires = "proxy_upstream")]
    pub proxy_upstream_ca: Option<std::path::PathBuf>,
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

    /// `--per-ip-upgrades` parsed.
    pub fn per_ip_upgrades(&self) -> Result<WindowLimits, String> {
        WindowLimits::parse(&self.per_ip_upgrades)
            .map_err(|e| format!("--per-ip-upgrades {e}"))
    }

    /// `--per-ip-bytes` parsed.
    pub fn per_ip_bytes(&self) -> Result<WindowLimits, String> {
        WindowLimits::parse(&self.per_ip_bytes).map_err(|e| format!("--per-ip-bytes {e}"))
    }

    /// `--limits-store`, checked against the rest of the configuration.
    ///
    /// A limit counted in one process is silently multiplied by the replica
    /// count, so on a non-loopback bind the choice has to be explicit:
    /// `memory` for a single replica, or a Postgres URL.
    pub fn limits_store(&self) -> Result<LimitsStoreSpec, String> {
        let spec = self.limits_store.trim();
        if spec.is_empty() {
            if self.public_limits_in_force() && !self.bound_locally() {
                return Err(
                    "per-client limits are on but --limits-store is empty: counted in \
                     one process, every limit is multiplied by the replica count. Set \
                     a Postgres URL, or \"memory\" for a single replica"
                        .into(),
                );
            }
            return Ok(LimitsStoreSpec::Memory);
        }
        if spec == "memory" {
            return Ok(LimitsStoreSpec::Memory);
        }
        if spec.starts_with("postgres://") || spec.starts_with("postgresql://") {
            return Ok(LimitsStoreSpec::Postgres(spec.to_string()));
        }
        Err(format!(
            "--limits-store: expected \"memory\" or a postgres:// URL, got '{}'",
            redact(spec)
        ))
    }

    /// `--proxy-upstream` and `--proxy-upstream-ca`, checked against the
    /// bind address: the hook is for a test suite on this machine, so a
    /// non-loopback bind refuses to start rather than serve attestations
    /// of a fixture to the network. The CA file is read here.
    pub fn proxy_upstream(&self) -> Result<Option<ProxyUpstream>, String> {
        let Some(spec) = self
            .proxy_upstream
            .as_deref()
            .map(str::trim)
            .filter(|spec| !spec.is_empty())
        else {
            if self.proxy_upstream_ca.is_some() {
                return Err("--proxy-upstream-ca needs --proxy-upstream".into());
            }
            return Ok(None);
        };
        if !self.bound_locally() {
            return Err(format!(
                "--proxy-upstream is a test hook and needs a loopback --host, got '{}'",
                self.host
            ));
        }
        let addr = spec.parse().map_err(|e| {
            format!("--proxy-upstream: expected <ip>:<port>, got '{spec}': {e}")
        })?;
        let ca = match &self.proxy_upstream_ca {
            None => None,
            Some(path) => {
                let bytes = std::fs::read(path).map_err(|e| {
                    format!("--proxy-upstream-ca {}: {e}", path.display())
                })?;
                let der = if bytes.starts_with(b"-----BEGIN") {
                    CertificateDer::from_pem_slice(&bytes).map_err(|e| {
                        format!("--proxy-upstream-ca {}: {e}", path.display())
                    })?
                } else {
                    CertificateDer(bytes)
                };
                Some(der)
            }
        };
        Ok(Some(ProxyUpstream { addr, ca }))
    }

    /// Whether any per-client limit applies on the public port.
    fn public_limits_in_force(&self) -> bool {
        self.ws_port != 0
            && (self.max_sessions_per_ip > 0
                || !self.per_ip_upgrades.trim().is_empty()
                || !self.per_ip_bytes.trim().is_empty())
    }

    fn bound_locally(&self) -> bool {
        self.host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
    }
}

/// Which header names the client on the public port; `--client-ip-header`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum ClientIpHeader {
    /// The rightmost `X-Forwarded-For` entry: what the load balancer
    /// appended, which is the address that connected to it. For a notary
    /// directly behind the ALB (Cloudflare DNS-only, grey cloud).
    XForwardedFor,
    /// The `CF-Connecting-IP` value Cloudflare adds. Only for a proxied
    /// Cloudflare record (orange cloud); with a grey record nothing sets it
    /// and every public request is refused.
    CfConnectingIp,
}

impl std::fmt::Display for ClientIpHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::XForwardedFor => "x-forwarded-for",
            Self::CfConnectingIp => "cf-connecting-ip",
        };
        f.write_str(name)
    }
}

/// The test hook `--proxy-upstream` names: where every ProxyMode session
/// dials, and the root its certificate may chain to besides the public
/// ones.
#[derive(Clone, Debug)]
pub struct ProxyUpstream {
    /// Dialled instead of `<server name>:443`.
    pub addr: std::net::SocketAddr,
    /// `--proxy-upstream-ca`, read.
    pub ca: Option<CertificateDer>,
}

/// Where the shared counts live.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LimitsStoreSpec {
    /// In this process only. Correct for one replica; a multiplier otherwise.
    Memory,
    /// A Postgres URL.
    Postgres(String),
}

impl std::fmt::Display for LimitsStoreSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Memory => f.write_str("memory"),
            Self::Postgres(url) => write!(f, "postgres ({})", redact(url)),
        }
    }
}
