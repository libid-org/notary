//! The notary under test. The production binary's configuration, plus the
//! one thing a release build must never carry: where every ProxyMode
//! session dials instead of `<server name>:443`, and the root that
//! fixture's certificate chains to. Built only with `--features e2e`;
//! `tests/e2e_limits.rs` spawns it.

use std::{
    net::{
        IpAddr,
        SocketAddr,
    },
    path::PathBuf,
};

use clap::Parser;
use notary::{
    cli,
    server::Upstream,
    NotaryServerConfig,
};
use tlsn::webpki::CertificateDer;

#[derive(Parser, Debug)]
#[command(
    name = "notary-e2e",
    about = "The libID notary, dialling a local fixture"
)]
struct E2eConfig {
    #[command(flatten)]
    notary: NotaryServerConfig,

    /// `<ip>:<port>` every ProxyMode session dials instead of
    /// `<server name>:443`. The server name a session authenticates is
    /// unchanged, so the fixture has to hold a certificate for it.
    #[arg(long, env = "NOTARY_E2E_UPSTREAM")]
    upstream: SocketAddr,

    /// A CA certificate file, DER or PEM, added to the roots the upstream's
    /// certificate is verified against.
    #[arg(long, env = "NOTARY_E2E_UPSTREAM_CA")]
    upstream_ca: Option<PathBuf>,
}

impl E2eConfig {
    /// The override, once the bind is one nothing off the machine can reach:
    /// a notary reachable from elsewhere dials the server it authenticates
    /// and nothing else.
    fn upstream(&self) -> anyhow::Result<Upstream> {
        let loopback = self
            .notary
            .host
            .parse::<IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false);
        anyhow::ensure!(
            loopback,
            "--upstream needs a loopback --host, got '{}'",
            self.notary.host
        );
        let ca = match &self.upstream_ca {
            None => None,
            Some(path) => {
                let bytes = std::fs::read(path).map_err(|e| {
                    anyhow::anyhow!("--upstream-ca {}: {e}", path.display())
                })?;
                Some(if bytes.starts_with(b"-----BEGIN") {
                    CertificateDer::from_pem_slice(&bytes).map_err(|e| {
                        anyhow::anyhow!("--upstream-ca {}: {e}", path.display())
                    })?
                } else {
                    CertificateDer(bytes)
                })
            }
        };
        Ok(Upstream {
            addr: self.upstream,
            ca,
        })
    }
}

fn main() -> anyhow::Result<()> {
    cli::init_tracing();
    let config = E2eConfig::parse();
    let upstream = config.upstream()?;
    cli::serve(config.notary, Some(upstream))
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::E2eConfig;

    fn parse(extra: &[&str]) -> E2eConfig {
        let mut args = vec![
            "notary-e2e",
            "--signing-key",
            "00",
            "--upstream",
            "127.0.0.1:4433",
        ];
        args.extend_from_slice(extra);
        E2eConfig::try_parse_from(args).unwrap()
    }

    #[test]
    fn the_override_only_starts_on_a_loopback_bind() {
        let upstream = parse(&[]).upstream().unwrap();
        assert_eq!(upstream.addr, "127.0.0.1:4433".parse().unwrap());
        assert!(upstream.ca.is_none());
        for host in ["0.0.0.0", "::", "10.0.0.5"] {
            let error = parse(&["--host", host]).upstream().unwrap_err().to_string();
            assert!(error.contains("loopback"), "{error}");
        }
    }
}
