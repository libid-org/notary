//! CLI entry point for the notary server.

use clap::Parser;
use notary::{
    cli,
    NotaryServerConfig,
};

fn main() -> anyhow::Result<()> {
    cli::init_tracing();
    cli::serve(NotaryServerConfig::parse(), None)
}
