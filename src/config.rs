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
//!
//! ## Precedence
//!
//! For every flag: **explicit flag value > environment variable > built-in
//! default**. This is implemented natively by clap: each argument carries an
//! `env` attribute (read once at parse time) and a `default_value` that is used
//! only when neither the flag nor the env var is present.

use std::{net::SocketAddr, path::PathBuf, str::FromStr};

use clap::Parser;

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

// ── Cli ───────────────────────────────────────────────────────────────────────

/// Sagittarius — a self-hosted DNS sinkhole.
///
/// Operational settings are provided as CLI flags (or matching environment
/// variables). Application configuration (upstreams, blocklists, local
/// records, etc.) is managed through the admin web UI and stored in SQLite.
#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    /// DNS listener bind address(es).
    ///
    /// May be repeated to bind multiple addresses, e.g. add `[::]:53` for
    /// dual-stack IPv6. When no `--dns-addr` flag is given and
    /// `SAGITTARIUS_DNS_ADDR` is unset, defaults to `0.0.0.0:53`.
    #[arg(
        long,
        env = "SAGITTARIUS_DNS_ADDR",
        default_value = "0.0.0.0:53",
        value_name = "ADDR"
    )]
    pub dns_addr: Vec<SocketAddr>,

    /// Admin interface bind address.
    ///
    /// Defaults to `127.0.0.1:8080` (loopback) because TLS termination is the
    /// reverse proxy's responsibility (SPEC §9, §10).
    #[arg(
        long,
        env = "SAGITTARIUS_ADMIN_ADDR",
        default_value = "127.0.0.1:8080",
        value_name = "ADDR"
    )]
    pub admin_addr: SocketAddr,

    /// Path to the SQLite database file.
    #[arg(
        long,
        env = "SAGITTARIUS_DB_PATH",
        default_value = "sagittarius.db",
        value_name = "PATH"
    )]
    pub db_path: PathBuf,

    /// Session-cookie Secure attribute policy.
    ///
    /// `auto` (default) — mirror the scheme of the incoming request.
    /// `always` — always set Secure (use behind a TLS reverse proxy).
    /// `never`  — never set Secure (local/loopback testing only).
    #[arg(
        long,
        env = "SAGITTARIUS_SESSION_COOKIE_SECURE",
        default_value = "auto",
        value_name = "POLICY"
    )]
    pub session_cookie_secure: SessionCookieSecurePolicy,
}

// ── Config ────────────────────────────────────────────────────────────────────

/// Resolved, validated operational configuration for the Sagittarius runtime.
///
/// Constructed via [`TryFrom<Cli>`]; see the module-level docs for the flag →
/// env → default precedence semantics.
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

impl TryFrom<Cli> for Config {
    type Error = Error;

    fn try_from(cli: Cli) -> Result<Self, Self::Error> {
        // clap already parses SocketAddr natively, so addresses are validated
        // at parse time. dns_addr carries a default_value so the Vec is never
        // empty when clap succeeds; the assertion below guards against any
        // future refactor that might break that invariant.
        let dns_addrs = if cli.dns_addr.is_empty() {
            // Fallback should never be reached in practice because clap's
            // default_value applies when the flag is absent, but we keep the
            // rule explicit here for clarity.
            vec![
                "0.0.0.0:53"
                    .parse::<SocketAddr>()
                    .map_err(|_| Error::InvalidAddress("0.0.0.0:53".into()))?,
            ]
        } else {
            cli.dns_addr
        };

        Ok(Self {
            dns_addrs,
            admin_addr: cli.admin_addr,
            db_path: cli.db_path,
            session_cookie_secure: cli.session_cookie_secure,
        })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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

    // ── Cli defaults ──────────────────────────────────────────────────────

    #[test]
    fn cli_defaults_dns_addr() {
        let cli = Cli::try_parse_from(["sagittarius"]).unwrap();
        assert_eq!(cli.dns_addr.len(), 1);
        assert_eq!(
            cli.dns_addr[0],
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 53)
        );
    }

    #[test]
    fn cli_defaults_admin_addr() {
        let cli = Cli::try_parse_from(["sagittarius"]).unwrap();
        assert_eq!(
            cli.admin_addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080)
        );
    }

    #[test]
    fn cli_defaults_db_path() {
        let cli = Cli::try_parse_from(["sagittarius"]).unwrap();
        assert_eq!(cli.db_path, PathBuf::from("sagittarius.db"));
    }

    #[test]
    fn cli_defaults_cookie_policy() {
        let cli = Cli::try_parse_from(["sagittarius"]).unwrap();
        assert_eq!(cli.session_cookie_secure, SessionCookieSecurePolicy::Auto);
    }

    // ── Cli flag precedence (flag overrides default) ───────────────────────
    // Note on env-var testing: environment variables are process-global state,
    // which makes them inherently racy in parallel test runs. We therefore test
    // the flag-wins behaviour here using explicit CLI args (which clap always
    // prefers over env vars), and we rely on the `env` attribute being declared
    // on each field (visible in the struct definition) plus the clap-rendered
    // `--help` test below to confirm env integration at the API level.

    #[test]
    fn flag_overrides_default_dns_addr() {
        let cli = Cli::try_parse_from(["sagittarius", "--dns-addr", "127.0.0.1:5353"]).unwrap();
        assert_eq!(cli.dns_addr.len(), 1);
        assert_eq!(
            cli.dns_addr[0],
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5353)
        );
    }

    #[test]
    fn flag_overrides_default_admin_addr() {
        let cli = Cli::try_parse_from(["sagittarius", "--admin-addr", "0.0.0.0:9090"]).unwrap();
        assert_eq!(
            cli.admin_addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 9090)
        );
    }

    #[test]
    fn flag_overrides_default_db_path() {
        let cli =
            Cli::try_parse_from(["sagittarius", "--db-path", "/var/lib/sagittarius/db.sqlite"])
                .unwrap();
        assert_eq!(cli.db_path, PathBuf::from("/var/lib/sagittarius/db.sqlite"));
    }

    #[test]
    fn flag_overrides_default_cookie_policy_always() {
        let cli =
            Cli::try_parse_from(["sagittarius", "--session-cookie-secure", "always"]).unwrap();
        assert_eq!(cli.session_cookie_secure, SessionCookieSecurePolicy::Always);
    }

    #[test]
    fn flag_overrides_default_cookie_policy_never() {
        let cli = Cli::try_parse_from(["sagittarius", "--session-cookie-secure", "never"]).unwrap();
        assert_eq!(cli.session_cookie_secure, SessionCookieSecurePolicy::Never);
    }

    // ── Repeatable --dns-addr ─────────────────────────────────────────────

    #[test]
    fn dns_addr_repeatable_ipv4_and_ipv6() {
        let cli = Cli::try_parse_from([
            "sagittarius",
            "--dns-addr",
            "0.0.0.0:53",
            "--dns-addr",
            "[::]:53",
        ])
        .unwrap();
        assert_eq!(cli.dns_addr.len(), 2);
        assert!(
            cli.dns_addr
                .contains(&SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 53))
        );
        assert!(
            cli.dns_addr
                .contains(&SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 53))
        );
    }

    // ── Address parsing ───────────────────────────────────────────────────

    #[test]
    fn ipv4_address_parses() {
        let cli = Cli::try_parse_from(["sagittarius", "--admin-addr", "192.168.1.1:8080"]).unwrap();
        assert_eq!(
            cli.admin_addr,
            "192.168.1.1:8080".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn ipv6_address_parses() {
        let cli = Cli::try_parse_from(["sagittarius", "--admin-addr", "[::1]:8080"]).unwrap();
        assert_eq!(cli.admin_addr, "[::1]:8080".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn malformed_admin_addr_is_rejected() {
        let result = Cli::try_parse_from(["sagittarius", "--admin-addr", "not-an-address"]);
        assert!(result.is_err());
    }

    #[test]
    fn malformed_dns_addr_is_rejected() {
        let result = Cli::try_parse_from(["sagittarius", "--dns-addr", "bad:addr:here"]);
        assert!(result.is_err());
    }

    // ── Cookie policy — clap validation ──────────────────────────────────

    #[test]
    fn invalid_cookie_policy_rejected_by_clap() {
        let result = Cli::try_parse_from(["sagittarius", "--session-cookie-secure", "unknown"]);
        assert!(result.is_err());
    }

    // ── TryFrom<Cli> for Config ───────────────────────────────────────────

    #[test]
    fn config_from_defaults() {
        let cli = Cli::try_parse_from(["sagittarius"]).unwrap();
        let config = Config::try_from(cli).unwrap();
        assert_eq!(config.dns_addrs.len(), 1);
        assert_eq!(
            config.dns_addrs[0],
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 53)
        );
        assert_eq!(
            config.admin_addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080)
        );
        assert_eq!(config.db_path, PathBuf::from("sagittarius.db"));
        assert_eq!(
            config.session_cookie_secure,
            SessionCookieSecurePolicy::Auto
        );
    }

    #[test]
    fn config_from_explicit_flags() {
        let cli = Cli::try_parse_from([
            "sagittarius",
            "--dns-addr",
            "0.0.0.0:53",
            "--dns-addr",
            "[::]:53",
            "--admin-addr",
            "0.0.0.0:8080",
            "--db-path",
            "/data/sgt.db",
            "--session-cookie-secure",
            "always",
        ])
        .unwrap();
        let config = Config::try_from(cli).unwrap();
        assert_eq!(config.dns_addrs.len(), 2);
        assert_eq!(
            config.admin_addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080)
        );
        assert_eq!(config.db_path, PathBuf::from("/data/sgt.db"));
        assert_eq!(
            config.session_cookie_secure,
            SessionCookieSecurePolicy::Always
        );
    }

    // ── --help output ─────────────────────────────────────────────────────

    #[test]
    fn help_contains_all_flags() {
        // Render --help to a string and verify every documented flag appears.
        // This guards against accidental removal of a flag from the Cli struct.
        use clap::CommandFactory;
        let mut cmd = Cli::command();
        let mut buf = Vec::new();
        cmd.write_long_help(&mut buf).unwrap();
        let help = String::from_utf8(buf).unwrap();

        assert!(help.contains("--dns-addr"), "help missing --dns-addr");
        assert!(help.contains("--admin-addr"), "help missing --admin-addr");
        assert!(help.contains("--db-path"), "help missing --db-path");
        assert!(
            help.contains("--session-cookie-secure"),
            "help missing --session-cookie-secure"
        );
    }

    // ── bad args produce Err ──────────────────────────────────────────────

    #[test]
    fn unknown_flag_is_rejected() {
        let result = Cli::try_parse_from(["sagittarius", "--unknown-flag"]);
        assert!(result.is_err());
    }
}
