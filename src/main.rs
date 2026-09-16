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
                internal_ws = ?handle.internal_ws_local_addr(),
                "Notary server up"
            );
            let signal = stop_signal().await?;
            info!(signal, "stop requested; draining");
            handle.drain().await;
            Ok(())
        })
}

/// Resolves on Ctrl-C or, on Unix, SIGTERM -- what the orchestrator sends a
/// pod before its grace period starts -- with the signal's name.
async fn stop_signal() -> std::io::Result<&'static str> {
    #[cfg(unix)]
    {
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.map(|()| "SIGINT"),
            _ = sigterm.recv() => Ok("SIGTERM"),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.map(|()| "ctrl-c")
    }
}
