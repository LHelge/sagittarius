//! Web administration interface.
//!
//! An [`axum`] HTTP server sharing the tokio runtime with the DNS engine.
//! Renders HTML with [`askama`] compile-time templates and drives
//! interactivity via [Datastar](https://data-star.dev/) (SSE-based fragments
//! and reactive signals) — no JavaScript build step.  Styling is
//! [Pico CSS](https://picocss.com/) plus a thin custom layer, both vendored
//! into the binary.
//!
//! All routes are authenticated; state-changing requests carry CSRF
//! protection.  See SPEC §9 for the full capability list and security model.

/// Errors that can occur in the web administration server.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The admin HTTP server failed to bind its listen address.
    #[error("failed to bind admin listener on {addr}: {source}")]
    Bind {
        addr: std::net::SocketAddr,
        #[source]
        source: std::io::Error,
    },

    /// An internal server error occurred while handling a request.
    #[error("internal error: {0}")]
    Internal(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_variants_display() {
        let e = Error::Internal("unexpected state".into());
        assert!(e.to_string().contains("unexpected state"));
    }
}
