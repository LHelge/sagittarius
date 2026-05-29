//! Binary entry point for Sagittarius.
//!
//! This file is intentionally thin: it initialises the tokio runtime,
//! delegates all real work to [`sagittarius::app::App`], and maps library
//! errors into [`anyhow`] at the process boundary.
//!
//! `anyhow` is used *only* here — the library uses typed per-module errors
//! collected under [`sagittarius::error`].

use clap::Parser;
use sagittarius::{app::App, cli::Cli, config::Config, telemetry::Telemetry};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    Telemetry::init();
    let config = Config::try_from(cli)?;
    Telemetry::log_startup(&config);
    App::new(config).run().await?;
    Ok(())
}
