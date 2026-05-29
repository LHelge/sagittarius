//! Operational configuration — the domain types the runtime is built from.
//!
//! This module owns the resolved [`Config`] value and the shared config value
//! types it contains (e.g. [`SessionCookieSecurePolicy`]). Turning process
//! arguments / environment variables into a [`Config`] is the job of
//! [`crate::cli`], which depends on this module; the dependency points one way
//! (cli → config) so the rest of the app consumes configuration without
//! pulling in the argument-parsing surface.
//!
//! The one concession to that separation is that [`SessionCookieSecurePolicy`]
//! derives [`clap::ValueEnum`] so the CLI can render its accepted values in
//! `--help`; the type itself is a plain domain value (also consumed by the web
//! layer, SPEC §9).
//!
//! Application-level settings (upstreams, blocklists, local records, etc.) are
//! stored in SQLite and managed through the admin UI; only operational/startup
//! parameters live here.

use std::{net::SocketAddr, path::PathBuf, str::FromStr};

// ── Errors ────────────────────────────────────────────────────────────────────

/// Errors that can occur while loading or validating configuration.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A configured bind address is invalid.
    #[error("invalid bind address: {0}")]
    InvalidAddress(String),

    /// A configured session-cookie-secure policy is invalid.
    #[error("invalid session-cookie-secure policy: {0:?} (expected one of: auto, always, never)")]
    InvalidCookiePolicy(String),
}

// ── SessionCookieSecurePolicy ─────────────────────────────────────────────────

/// Controls whether the admin session cookie carries the `Secure` attribute.
///
/// See SPEC §9 and §10 for the rationale.
///
/// - `Auto` — set `Secure` only when the incoming request is HTTPS (directly or
///   via a trusted `X-Forwarded-Proto: https` header from a reverse proxy).
/// - `Always` — always set `Secure`; use this behind a correctly configured TLS
///   reverse proxy.
/// - `Never` — never set `Secure`; only appropriate for local/loopback testing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum SessionCookieSecurePolicy {
    #[default]
    Auto,
    Always,
    Never,
}

impl FromStr for SessionCookieSecurePolicy {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "always" => Ok(Self::Always),
            "never" => Ok(Self::Never),
            _ => Err(Error::InvalidCookiePolicy(s.to_owned())),
        }
    }
}

impl std::fmt::Display for SessionCookieSecurePolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auto => write!(f, "auto"),
            Self::Always => write!(f, "always"),
            Self::Never => write!(f, "never"),
        }
    }
}

// ── Config ────────────────────────────────────────────────────────────────────

/// Resolved, validated operational configuration for the Sagittarius runtime.
///
/// Constructed from the CLI via [`TryFrom<Cli>`](crate::cli::Cli); see
/// [`crate::cli`] for the flag → env → default precedence semantics.
#[derive(Debug, Clone)]
pub struct Config {
    /// One or more DNS listener addresses (at least one is always present).
    pub dns_addrs: Vec<SocketAddr>,

    /// Admin web interface bind address.
    pub admin_addr: SocketAddr,

    /// Path to the SQLite database file.
    pub db_path: PathBuf,

    /// Session-cookie `Secure` attribute policy.
    pub session_cookie_secure: SessionCookieSecurePolicy,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── SessionCookieSecurePolicy ─────────────────────────────────────────

    #[test]
    fn cookie_policy_default_is_auto() {
        assert_eq!(
            SessionCookieSecurePolicy::default(),
            SessionCookieSecurePolicy::Auto
        );
    }

    #[test]
    fn cookie_policy_from_str_auto() {
        assert_eq!(
            "auto".parse::<SessionCookieSecurePolicy>().unwrap(),
            SessionCookieSecurePolicy::Auto
        );
    }

    #[test]
    fn cookie_policy_from_str_always() {
        assert_eq!(
            "always".parse::<SessionCookieSecurePolicy>().unwrap(),
            SessionCookieSecurePolicy::Always
        );
    }

    #[test]
    fn cookie_policy_from_str_never() {
        assert_eq!(
            "never".parse::<SessionCookieSecurePolicy>().unwrap(),
            SessionCookieSecurePolicy::Never
        );
    }

    #[test]
    fn cookie_policy_from_str_case_insensitive() {
        assert_eq!(
            "AUTO".parse::<SessionCookieSecurePolicy>().unwrap(),
            SessionCookieSecurePolicy::Auto
        );
        assert_eq!(
            "Always".parse::<SessionCookieSecurePolicy>().unwrap(),
            SessionCookieSecurePolicy::Always
        );
    }

    #[test]
    fn cookie_policy_from_str_invalid() {
        let err = "invalid".parse::<SessionCookieSecurePolicy>().unwrap_err();
        assert!(matches!(err, Error::InvalidCookiePolicy(_)));
        assert!(err.to_string().contains("invalid"));
    }

    #[test]
    fn cookie_policy_display() {
        assert_eq!(SessionCookieSecurePolicy::Auto.to_string(), "auto");
        assert_eq!(SessionCookieSecurePolicy::Always.to_string(), "always");
        assert_eq!(SessionCookieSecurePolicy::Never.to_string(), "never");
    }

    // ── Error display ─────────────────────────────────────────────────────

    #[test]
    fn error_invalid_address_is_display() {
        let e = Error::InvalidAddress("not-an-address".into());
        assert!(e.to_string().contains("not-an-address"));
    }

    #[test]
    fn error_invalid_cookie_policy_is_display() {
        let e = Error::InvalidCookiePolicy("bogus".into());
        assert!(e.to_string().contains("bogus"));
    }
}
