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

    /// `--primary-url` was given without a matching `--primary-api-key`.
    #[error("secondary mode requires --primary-api-key (or SAGITTARIUS_PRIMARY_API_KEY)")]
    MissingApiKey,

    /// The `--primary-url` value is not an absolute `http(s)://` URL.
    #[error("invalid --primary-url: {0:?} (must start with http:// or https://)")]
    InvalidPrimaryUrl(String),
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

// ── InstanceMode ──────────────────────────────────────────────────────────────

/// The role this instance plays (SPEC §13).
///
/// Determined at startup from `--primary-url`: absent ⇒ [`Primary`](Self::Primary)
/// (today's standalone behaviour), present ⇒ [`Secondary`](Self::Secondary), a
/// read-only fallback that mirrors the primary's configuration.  The secondary's
/// API key is **not** carried here — it lives on [`Config::primary_api_key`] so
/// the secret never reaches the web state or a rendered page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstanceMode {
    /// Standalone / primary: configuration is edited locally.
    Primary,
    /// Read-only fallback mirroring `primary_url`'s configuration.
    Secondary {
        /// Base URL of the primary instance (no trailing slash), e.g.
        /// `https://sagittarius.home.lan`.
        primary_url: String,
    },
}

impl InstanceMode {
    /// Whether this instance is a read-only secondary.
    #[must_use]
    pub fn is_secondary(&self) -> bool {
        matches!(self, Self::Secondary { .. })
    }

    /// The primary base URL when secondary, otherwise `None`.
    #[must_use]
    pub fn primary_url(&self) -> Option<&str> {
        match self {
            Self::Secondary { primary_url } => Some(primary_url),
            Self::Primary => None,
        }
    }
}

// ── Secret ────────────────────────────────────────────────────────────────────

/// A sensitive string (e.g. the primary API key) that redacts itself in `Debug`
/// output, so it cannot leak into logs via a derived `Debug` on [`Config`].
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    /// Wrap a sensitive value.
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// Borrow the underlying value (only at the point it is actually used).
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret([redacted])")
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

    /// The instance role (primary or read-only secondary, SPEC §13).
    pub instance_mode: InstanceMode,

    /// API key used to authenticate to the primary in secondary mode; `None` in
    /// primary mode.  Held here (not on [`InstanceMode`]) and redacting in
    /// `Debug` so the secret stays out of the web state and logs.
    pub primary_api_key: Option<Secret>,
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

    // ── InstanceMode / Secret (E18.6) ─────────────────────────────────────

    #[test]
    fn instance_mode_primary_helpers() {
        let m = InstanceMode::Primary;
        assert!(!m.is_secondary());
        assert_eq!(m.primary_url(), None);
    }

    #[test]
    fn instance_mode_secondary_helpers() {
        let m = InstanceMode::Secondary {
            primary_url: "https://primary.home.lan".to_owned(),
        };
        assert!(m.is_secondary());
        assert_eq!(m.primary_url(), Some("https://primary.home.lan"));
    }

    #[test]
    fn secret_redacts_in_debug_but_exposes_value() {
        let s = Secret::new("super-secret-key".to_owned());
        assert_eq!(s.expose(), "super-secret-key");
        let debug = format!("{s:?}");
        assert!(
            !debug.contains("super-secret-key"),
            "debug must not leak: {debug}"
        );
        assert!(debug.contains("redacted"));
    }

    #[test]
    fn config_debug_does_not_leak_api_key() {
        let cfg = Config {
            dns_addrs: vec!["0.0.0.0:53".parse().unwrap()],
            admin_addr: "127.0.0.1:8080".parse().unwrap(),
            db_path: PathBuf::from("sagittarius.db"),
            session_cookie_secure: SessionCookieSecurePolicy::Auto,
            instance_mode: InstanceMode::Secondary {
                primary_url: "https://primary.home.lan".to_owned(),
            },
            primary_api_key: Some(Secret::new("leak-me-not".to_owned())),
        };
        let debug = format!("{cfg:?}");
        assert!(
            !debug.contains("leak-me-not"),
            "Config debug must not leak the key"
        );
    }
}
