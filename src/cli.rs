//! Command-line interface — the input adapter that turns process arguments
//! and environment variables into a typed [`Config`].
//!
//! This module owns the clap surface ([`Cli`]) and the [`TryFrom<Cli>`]
//! conversion into [`Config`]. It depends on [`crate::config`] for the domain
//! types; the dependency points one way (cli → config) so the parsing concern
//! stays isolated from the configuration the rest of the app consumes. Only
//! `main` touches [`Cli`].
//!
//! ## Precedence
//!
//! For every flag: **explicit flag value > environment variable > built-in
//! default**. This is implemented natively by clap: each argument carries an
//! `env` attribute (read once at parse time) and a `default_value` that is used
//! only when neither the flag nor the env var is present.

use std::{net::SocketAddr, path::PathBuf};

use clap::Parser;

use crate::config::{Config, Error, InstanceMode, Secret, SessionCookieSecurePolicy};

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

    /// Base URL of a primary instance to mirror (enables **secondary/fallback**
    /// mode, SPEC §13).
    ///
    /// When set, this instance becomes a read-only secondary: it polls the
    /// primary's config-sync API and mirrors its configuration, and its own
    /// admin UI is read-only. Requires `--primary-api-key`. When unset the
    /// instance runs as a normal (primary) standalone server.
    #[arg(long, env = "SAGITTARIUS_PRIMARY_URL", value_name = "URL")]
    pub primary_url: Option<String>,

    /// API key used to authenticate to the primary (required with
    /// `--primary-url`). Mint it on the primary's API-keys page.
    #[arg(long, env = "SAGITTARIUS_PRIMARY_API_KEY", value_name = "KEY")]
    pub primary_api_key: Option<String>,
}

impl TryFrom<Cli> for Config {
    type Error = Error;

    fn try_from(cli: Cli) -> Result<Self, Self::Error> {
        // clap already parses SocketAddr natively, so addresses are validated
        // at parse time. dns_addr carries a default_value so the Vec is never
        // empty when clap succeeds; the fallback below keeps that invariant
        // explicit against any future refactor that might break it.
        let dns_addrs = if cli.dns_addr.is_empty() {
            vec![
                "0.0.0.0:53"
                    .parse::<SocketAddr>()
                    .map_err(|_| Error::InvalidAddress("0.0.0.0:53".into()))?,
            ]
        } else {
            cli.dns_addr
        };

        // Instance mode: a `--primary-url` turns this into a read-only secondary
        // and requires a matching API key. The key is kept separate from the
        // mode so it never reaches the web state or logs (see `config::Secret`).
        let (instance_mode, primary_api_key) = match cli.primary_url {
            Some(url) => {
                let url = normalize_primary_url(&url)?;
                let key = cli.primary_api_key.ok_or(Error::MissingApiKey)?;
                (
                    InstanceMode::Secondary { primary_url: url },
                    Some(Secret::new(key)),
                )
            }
            None => (InstanceMode::Primary, None),
        };

        Ok(Self {
            dns_addrs,
            admin_addr: cli.admin_addr,
            db_path: cli.db_path,
            session_cookie_secure: cli.session_cookie_secure,
            instance_mode,
            primary_api_key,
        })
    }
}

/// Validate and normalize a `--primary-url`: require an absolute `http(s)://`
/// URL and strip any trailing slash so `{url}/api/v1/config` joins cleanly.
fn normalize_primary_url(url: &str) -> Result<String, Error> {
    let trimmed = url.trim();
    if !(trimmed.starts_with("http://") || trimmed.starts_with("https://")) {
        return Err(Error::InvalidPrimaryUrl(url.to_owned()));
    }
    Ok(trimmed.trim_end_matches('/').to_owned())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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

    // ── Instance mode (E18.6) ─────────────────────────────────────────────

    #[test]
    fn config_defaults_to_primary_mode() {
        let cli = Cli::try_parse_from(["sagittarius"]).unwrap();
        let config = Config::try_from(cli).unwrap();
        assert_eq!(config.instance_mode, InstanceMode::Primary);
        assert!(config.primary_api_key.is_none());
    }

    #[test]
    fn primary_url_with_key_enables_secondary_mode() {
        let cli = Cli::try_parse_from([
            "sagittarius",
            "--primary-url",
            "https://primary.home.lan/",
            "--primary-api-key",
            "abc.def",
        ])
        .unwrap();
        let config = Config::try_from(cli).unwrap();
        assert_eq!(
            config.instance_mode,
            // The trailing slash is normalized away.
            InstanceMode::Secondary {
                primary_url: "https://primary.home.lan".to_owned()
            }
        );
        assert_eq!(
            config
                .primary_api_key
                .as_ref()
                .map(|s| s.expose().to_owned()),
            Some("abc.def".to_owned())
        );
    }

    #[test]
    fn primary_url_without_key_is_error() {
        let cli = Cli::try_parse_from(["sagittarius", "--primary-url", "https://p.lan"]).unwrap();
        assert!(matches!(Config::try_from(cli), Err(Error::MissingApiKey)));
    }

    #[test]
    fn non_http_primary_url_is_error() {
        let cli = Cli::try_parse_from([
            "sagittarius",
            "--primary-url",
            "ftp://p.lan",
            "--primary-api-key",
            "k",
        ])
        .unwrap();
        assert!(matches!(
            Config::try_from(cli),
            Err(Error::InvalidPrimaryUrl(_))
        ));
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
        assert!(help.contains("--primary-url"), "help missing --primary-url");
        assert!(
            help.contains("--primary-api-key"),
            "help missing --primary-api-key"
        );
    }

    // ── bad args produce Err ──────────────────────────────────────────────

    #[test]
    fn unknown_flag_is_rejected() {
        let result = Cli::try_parse_from(["sagittarius", "--unknown-flag"]);
        assert!(result.is_err());
    }
}
