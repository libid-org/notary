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
            tokio::signal::ctrl_c().await?;
            handle.shutdown();
            Ok(())
        })
}
