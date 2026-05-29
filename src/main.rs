//! Binary entry point for Sagittarius.
//!
//! This file is intentionally thin: it initialises the tokio runtime,
//! delegates all real work to [`sagittarius::app::App`], and maps library
//! errors into [`anyhow`] at the process boundary.
//!
//! `anyhow` is used *only* here — the library uses typed per-module errors
//! collected under [`sagittarius::error`].

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let app = sagittarius::app::App::new();
    app.run().await?;
    Ok(())
}
