//! Configuration module.
//!
//! Responsible for parsing CLI arguments and environment variables into a
//! typed configuration structure, and for exposing operational settings to
//! the rest of the application.
//!
//! CLI arguments are parsed by [`clap`] with environment-variable fallbacks.
//! Application-level settings (upstreams, blocklists, etc.) are stored in
//! SQLite and managed through the admin UI; only operational/startup parameters
//! live here.

/// Errors that can occur while loading or validating configuration.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A configured bind address is invalid.
    #[error("invalid bind address: {0}")]
    InvalidAddress(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_is_display() {
        let e = Error::InvalidAddress("not-an-address".into());
        assert!(e.to_string().contains("not-an-address"));
    }
}
