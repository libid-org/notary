//! CLI entry point for the notary server.

use clap::Parser;
use notary::{
    server,
    NotaryServerConfig,
};
use tracing::info;

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".parse().expect("static filter parses")),
        )
        .init();
    let config = NotaryServerConfig::parse();

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let handle = server::run(config).await?;
            info!(
                mpc = ?handle.local_addr(),
                ws = ?handle.ws_local_addr(),
                "Notary server up"
            );
            let mut signals = StopSignals::new()?;
            let signal = signals.next().await;
            info!(signal, "stop requested; draining");
            // A second signal while draining is an operator who will not
            // wait: stop now, and still exit 0 -- nothing failed.
            tokio::select! {
                () = handle.drain() => {}
                signal = signals.next() => {
                    info!(signal, "second signal: exiting without waiting");
                }
            }
            Ok(())
        })
}

/// Ctrl-C and, on Unix, SIGTERM -- what the orchestrator sends a pod before
/// its grace period starts. One registration, kept for the life of the
/// process, so a second signal is heard while the first is being honoured.
struct StopSignals {
    #[cfg(unix)]
    sigint: tokio::signal::unix::Signal,
    #[cfg(unix)]
    sigterm: tokio::signal::unix::Signal,
}

impl StopSignals {
    fn new() -> std::io::Result<Self> {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{
                signal,
                SignalKind,
            };
            Ok(Self {
                sigint: signal(SignalKind::interrupt())?,
                sigterm: signal(SignalKind::terminate())?,
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Self {})
        }
    }

    /// The next stop signal, by name.
    async fn next(&mut self) -> &'static str {
        #[cfg(unix)]
        {
            tokio::select! {
                () = received(&mut self.sigint) => "SIGINT",
                () = received(&mut self.sigterm) => "SIGTERM",
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
            "ctrl-c"
        }
    }
}

/// One delivery of `signal`. A stream that can deliver no more is not a
/// signal: it pends, so the other stream still decides.
#[cfg(unix)]
async fn received(signal: &mut tokio::signal::unix::Signal) {
    match signal.recv().await {
        Some(()) => {}
        None => std::future::pending().await,
    }
}
