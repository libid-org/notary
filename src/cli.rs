//! What a notary binary does after parsing its configuration: log setup,
//! the runtime, the server, and the stop signals that drain it. Shared by
//! the release binary and the one the e2e suite runs, so a signal is handled
//! the same way in both.

use tracing::info;

use crate::{
    server::{
        self,
        Upstream,
    },
    NotaryServerConfig,
};

/// Log to stderr, filtered by `RUST_LOG`, `info` by default.
pub fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".parse().expect("static filter parses")),
        )
        .init();
}

/// Run the notary until the first stop signal, then drain; a second signal
/// while draining exits at once, still successfully -- nothing failed.
pub fn serve(
    config: NotaryServerConfig,
    upstream: Option<Upstream>,
) -> anyhow::Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let handle = server::run_with(config, upstream).await?;
            info!(
                mpc = ?handle.local_addr(),
                ws = ?handle.ws_local_addr(),
                "Notary server up"
            );
            let mut signals = StopSignals::new()?;
            let signal = signals.next().await;
            info!(signal, "stop requested; draining");
            tokio::select! {
                () = handle.drain() => {}
                signal = signals.next() => {
                    info!(signal, "second signal: exiting without waiting");
                }
            }
            Ok(())
        })
}

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
