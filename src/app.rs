//! Application runtime.
//!
//! Owns the shared state that all subsystems read and write, and is
//! responsible for wiring them together at startup:
//!
//! 1. Open the SQLite database and run migrations ([`storage`]).
//! 2. Load configuration into in-memory structures.
//! 3. Spawn the DNS listeners and query pipeline ([`resolver`]).
//! 4. Spawn the web administration server ([`web`]).
//! 5. Spawn background tasks (blocklist refresh scheduler, etc.).
//! 6. Await a shutdown signal (`SIGTERM` / `SIGINT`) and drain in-flight
//!    work via a [`tokio_util::sync::CancellationToken`] +
//!    [`tokio_util::task::TaskTracker`] before returning.
//!
//! See SPEC §3, §10 for the architecture overview and deployment model.

use crate::error::Result;

/// The top-level application handle.
///
/// Created once in `main`, holds all shared state, and drives the entire
/// service lifetime.
pub struct App;

impl App {
    /// Construct a new, uninitialised [`App`].
    ///
    /// Real initialisation (database open, migration, listener bind) will be
    /// added in subsequent tasks.
    pub fn new() -> Self {
        Self
    }

    /// Run the application to completion, returning when the process receives
    /// a shutdown signal or a fatal error occurs.
    pub async fn run(&self) -> Result<()> {
        Ok(())
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn app_run_returns_ok() {
        let app = App::new();
        assert!(app.run().await.is_ok());
    }
}
