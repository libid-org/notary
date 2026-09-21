//! Runtime configuration (clap + environment).

use clap::{
    Parser,
    ValueEnum,
};

use crate::{
    limits::{
        Concurrency,
        DEFAULT_MAX_SESSIONS,
    },
    store::{
        LimitsStoreSpec,
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
    /// The route MUST be blocked at the load balancer -- a fixed response,
    /// 404, for `/internal/*` -- because nothing on it limits a caller. As defence
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
    #[arg(long, env = "NOTARY_MAX_SESSIONS", default_value_t = DEFAULT_MAX_SESSIONS)]
    pub max_sessions: usize,

    /// Max concurrent ProxyMode sessions on the internal route. Its own
    /// pool, so public load can never queue our own services behind it.
    #[arg(long, env = "NOTARY_INTERNAL_MAX_SESSIONS", default_value_t = DEFAULT_MAX_SESSIONS)]
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
    /// until it ends. One browser identity flow opens two sessions at once, so
    /// the default leaves a user one flow of headroom -- and a shared office
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
    pub per_ip_upgrades: WindowLimits,

    /// Bytes one client may relay per window on the public port, both
    /// directions, as `<size>/<window>` entries: `100MB/1m,600MB/30m,1GB/1h`.
    /// Charged when a session ends; a client whose windows are full is
    /// refused at its next upgrade. Empty disables it.
    #[arg(
        long,
        env = "NOTARY_PER_IP_BYTES",
        default_value = "100MB/1m,600MB/30m,1GB/1h"
    )]
    pub per_ip_bytes: WindowLimits,

    /// Who the client of a public request is, for every per-client limit.
    /// A public upgrade the mode cannot attribute is refused with 400,
    /// never keyed on something else.
    ///
    /// `peer`: the socket peer, for a notary that clients reach directly,
    /// local Docker included. A request that carries `X-Forwarded-For` or
    /// `CF-Connecting-IP` came through a proxy the configuration does not
    /// know about, and the peer would be that proxy: refused.
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
    /// In the header modes nothing verifies who wrote the header. Anything
    /// that can reach the public port directly can set it and choose its
    /// own key, so the public port must be reachable only through the load
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
    /// limit on a non-loopback address, leaving it unset refuses to start.
    #[arg(long, env = "NOTARY_LIMITS_STORE")]
    pub limits_store: Option<LimitsStoreSpec>,
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

    /// The store as configured, or `memory` when unset -- which is refused
    /// with per-client limits on a non-loopback bind, since counts kept in
    /// one process multiply every limit by the replica count.
    pub fn limits_store(&self) -> Result<LimitsStoreSpec, String> {
        match &self.limits_store {
            Some(spec) => Ok(spec.clone()),
            None if self.public_limits_in_force() && !self.bound_locally() => Err(
                "per-client limits are on but --limits-store is unset: counted in \
                 one process, every limit is multiplied by the replica count. Set \
                 a Postgres URL, or \"memory\" for a single replica"
                    .into(),
            ),
            None => Ok(LimitsStoreSpec::Memory),
        }
    }

    /// Whether any per-client limit applies on the public port.
    fn public_limits_in_force(&self) -> bool {
        self.ws_port != 0
            && (self.max_sessions_per_ip > 0
                || !self.per_ip_upgrades.is_empty()
                || !self.per_ip_bytes.is_empty())
    }

    fn bound_locally(&self) -> bool {
        self.host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
    }
}

/// Who the client of a public request is; `--client-ip-header`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum ClientIpHeader {
    /// The socket peer, for a notary that clients reach directly. A
    /// request carrying a proxy's header is refused: the peer would be
    /// the proxy.
    Peer,
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
            Self::Peer => "peer",
            Self::XForwardedFor => "x-forwarded-for",
            Self::CfConnectingIp => "cf-connecting-ip",
        };
        f.write_str(name)
    }
}
