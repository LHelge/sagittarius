//! Repository for the singleton `settings` row.
//!
//! Provides the [`SettingsRepository`] trait and its [`SqliteSettingsRepo`]
//! implementation.  All DB interaction uses compile-time-checked `sqlx::query_as!`
//! / `sqlx::query!` macros against the `settings` table defined in migration
//! `0001_schema.sql`.

use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use sqlx::SqlitePool;

use super::Error;

// ── Result alias ────────────────────────────────────────────────────────────

pub type Result<T> = std::result::Result<T, Error>;

// ── BlockingMode ─────────────────────────────────────────────────────────────

/// How the DNS sinkhole responds to blocked domains.
///
/// Maps to/from the `blocking_mode` TEXT column values `'nxdomain'`,
/// `'null-ip'`, and `'custom'`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockingMode {
    /// Reply with `NXDOMAIN` (domain does not exist).
    NxDomain,
    /// Reply with `0.0.0.0` / `::` (null IP addresses).
    NullIp,
    /// Reply with the admin-configured custom IP addresses.
    Custom,
}

impl BlockingMode {
    /// Returns the canonical TEXT representation stored in the database.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NxDomain => "nxdomain",
            Self::NullIp => "null-ip",
            Self::Custom => "custom",
        }
    }
}

impl fmt::Display for BlockingMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for BlockingMode {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "nxdomain" => Ok(Self::NxDomain),
            "null-ip" => Ok(Self::NullIp),
            "custom" => Ok(Self::Custom),
            other => Err(Error::Decode(format!(
                "unknown blocking_mode value: {other:?}"
            ))),
        }
    }
}

// ── Settings ──────────────────────────────────────────────────────────────────

/// Typed representation of the singleton `settings` row (id = 1).
#[derive(Debug, Clone, PartialEq)]
pub struct Settings {
    /// Minimum TTL to serve from the cache, in seconds.
    pub cache_min_ttl: u32,
    /// Maximum TTL to serve from the cache, in seconds.
    pub cache_max_ttl: u32,
    /// Cap applied to NXDOMAIN/NODATA negative cache entries, in seconds.
    pub cache_negative_ttl_cap: u32,
    /// Maximum number of cache entries.
    pub cache_capacity: u64,
    /// How blocked domains are answered.
    pub blocking_mode: BlockingMode,
    /// Custom IPv4 address used when `blocking_mode` is `Custom`.
    pub custom_block_ipv4: Option<Ipv4Addr>,
    /// Custom IPv6 address used when `blocking_mode` is `Custom`.
    pub custom_block_ipv6: Option<Ipv6Addr>,
    /// How often blocklists are refreshed, in seconds.
    pub blocklist_refresh_interval: u32,
    /// UI colour-scheme preference (e.g. `"auto"`, `"light"`, `"dark"`).
    pub ui_theme: String,
}

// ── Private row struct ────────────────────────────────────────────────────────

/// Private projection returned by `query_as!` — all primitive SQLite types so
/// the macro can type-check the column names and types at compile time.
struct SettingsRow {
    cache_min_ttl: i64,
    cache_max_ttl: i64,
    cache_negative_ttl_cap: i64,
    cache_capacity: i64,
    blocking_mode: String,
    custom_block_ipv4: Option<String>,
    custom_block_ipv6: Option<String>,
    blocklist_refresh_interval: i64,
    ui_theme: String,
}

/// Narrow a non-negative `i64` DB value to `u32`, returning a decode error
/// when out of range.
fn narrow_u32(value: i64, column: &'static str) -> Result<u32> {
    u32::try_from(value)
        .map_err(|_| Error::Decode(format!("column {column} value {value} is out of u32 range")))
}

/// Narrow a non-negative `i64` DB value to `u64`.
fn narrow_u64(value: i64, column: &'static str) -> Result<u64> {
    u64::try_from(value)
        .map_err(|_| Error::Decode(format!("column {column} value {value} is out of u64 range")))
}

impl TryFrom<SettingsRow> for Settings {
    type Error = Error;

    fn try_from(row: SettingsRow) -> Result<Self> {
        let blocking_mode: BlockingMode = row.blocking_mode.parse()?;

        let custom_block_ipv4 = row
            .custom_block_ipv4
            .as_deref()
            .map(|s| {
                s.parse::<Ipv4Addr>()
                    .map_err(|e| Error::Decode(format!("invalid custom_block_ipv4 {s:?}: {e}")))
            })
            .transpose()?;

        let custom_block_ipv6 = row
            .custom_block_ipv6
            .as_deref()
            .map(|s| {
                s.parse::<Ipv6Addr>()
                    .map_err(|e| Error::Decode(format!("invalid custom_block_ipv6 {s:?}: {e}")))
            })
            .transpose()?;

        Ok(Settings {
            cache_min_ttl: narrow_u32(row.cache_min_ttl, "cache_min_ttl")?,
            cache_max_ttl: narrow_u32(row.cache_max_ttl, "cache_max_ttl")?,
            cache_negative_ttl_cap: narrow_u32(
                row.cache_negative_ttl_cap,
                "cache_negative_ttl_cap",
            )?,
            cache_capacity: narrow_u64(row.cache_capacity, "cache_capacity")?,
            blocking_mode,
            custom_block_ipv4,
            custom_block_ipv6,
            blocklist_refresh_interval: narrow_u32(
                row.blocklist_refresh_interval,
                "blocklist_refresh_interval",
            )?,
            ui_theme: row.ui_theme,
        })
    }
}

// ── SettingsRepository trait ─────────────────────────────────────────────────

/// Repository for reading and writing the singleton `settings` row.
///
/// # Note on `async_fn_in_trait`
///
/// We use `async fn` directly in the trait.  All implementations are in this
/// crate, so we control the full `impl` surface and have no need for
/// `Send`-bound flexibility across dynamic dispatch.  The lint is suppressed
/// here rather than desugaring to `impl Future`.
#[allow(async_fn_in_trait)]
pub trait SettingsRepository {
    /// Read the singleton settings row (id = 1).
    async fn get(&self) -> Result<Settings>;

    /// Persist all mutable fields of `settings` back to the database.
    async fn update(&self, settings: &Settings) -> Result<()>;
}

// ── SqliteSettingsRepo ────────────────────────────────────────────────────────

/// SQLite-backed [`SettingsRepository`].
pub struct SqliteSettingsRepo {
    pool: SqlitePool,
}

impl SqliteSettingsRepo {
    /// Construct a new repository from an open [`crate::storage::Db`].
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

impl SettingsRepository for SqliteSettingsRepo {
    async fn get(&self) -> Result<Settings> {
        let row = sqlx::query_as!(
            SettingsRow,
            r#"SELECT
                cache_min_ttl,
                cache_max_ttl,
                cache_negative_ttl_cap,
                cache_capacity,
                blocking_mode,
                custom_block_ipv4,
                custom_block_ipv6,
                blocklist_refresh_interval,
                ui_theme
            FROM settings
            WHERE id = 1"#
        )
        .fetch_one(&self.pool)
        .await?;

        Settings::try_from(row)
    }

    async fn update(&self, settings: &Settings) -> Result<()> {
        let blocking_mode = settings.blocking_mode.as_str();
        let custom_block_ipv4 = settings.custom_block_ipv4.map(|ip| ip.to_string());
        let custom_block_ipv6 = settings.custom_block_ipv6.map(|ip| ip.to_string());
        let cache_min_ttl = settings.cache_min_ttl as i64;
        let cache_max_ttl = settings.cache_max_ttl as i64;
        let cache_negative_ttl_cap = settings.cache_negative_ttl_cap as i64;
        let cache_capacity = settings.cache_capacity as i64;
        let blocklist_refresh_interval = settings.blocklist_refresh_interval as i64;

        sqlx::query!(
            r#"UPDATE settings SET
                cache_min_ttl               = ?,
                cache_max_ttl               = ?,
                cache_negative_ttl_cap      = ?,
                cache_capacity              = ?,
                blocking_mode               = ?,
                custom_block_ipv4           = ?,
                custom_block_ipv6           = ?,
                blocklist_refresh_interval  = ?,
                ui_theme                    = ?
            WHERE id = 1"#,
            cache_min_ttl,
            cache_max_ttl,
            cache_negative_ttl_cap,
            cache_capacity,
            blocking_mode,
            custom_block_ipv4,
            custom_block_ipv6,
            blocklist_refresh_interval,
            settings.ui_theme,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Db;
    use tempfile::TempDir;

    async fn open_repo() -> (TempDir, SqliteSettingsRepo) {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("test.db");
        let db = Db::connect(&path).await.expect("connect");
        let repo = SqliteSettingsRepo::new(db.pool().clone());
        (dir, repo)
    }

    // ── BlockingMode unit tests ───────────────────────────────────────────────

    #[test]
    fn blocking_mode_display() {
        assert_eq!(BlockingMode::NxDomain.to_string(), "nxdomain");
        assert_eq!(BlockingMode::NullIp.to_string(), "null-ip");
        assert_eq!(BlockingMode::Custom.to_string(), "custom");
    }

    #[test]
    fn blocking_mode_from_str_valid() {
        assert_eq!(
            "nxdomain".parse::<BlockingMode>().unwrap(),
            BlockingMode::NxDomain
        );
        assert_eq!(
            "null-ip".parse::<BlockingMode>().unwrap(),
            BlockingMode::NullIp
        );
        assert_eq!(
            "custom".parse::<BlockingMode>().unwrap(),
            BlockingMode::Custom
        );
    }

    #[test]
    fn blocking_mode_from_str_invalid() {
        let err = "unknown".parse::<BlockingMode>();
        assert!(err.is_err(), "invalid blocking mode must fail");
        let msg = err.unwrap_err().to_string();
        assert!(
            msg.contains("unknown"),
            "error message must mention the bad value: {msg}"
        );
    }

    // ── get() returns seeded defaults ────────────────────────────────────────

    #[tokio::test]
    async fn get_returns_seeded_defaults() {
        let (_dir, repo) = open_repo().await;
        let settings = repo.get().await.expect("get settings");

        assert_eq!(settings.cache_min_ttl, 1u32);
        assert_eq!(settings.cache_max_ttl, 86400u32);
        assert_eq!(settings.cache_negative_ttl_cap, 3600u32);
        assert_eq!(settings.cache_capacity, 100_000u64);
        assert_eq!(settings.blocking_mode, BlockingMode::NullIp);
        assert!(settings.custom_block_ipv4.is_none());
        assert!(settings.custom_block_ipv6.is_none());
        assert_eq!(settings.blocklist_refresh_interval, 86400u32);
        assert_eq!(settings.ui_theme, "auto");
    }

    // ── update() round-trips ──────────────────────────────────────────────────

    #[tokio::test]
    async fn update_round_trips() {
        let (_dir, repo) = open_repo().await;

        let mut settings = repo.get().await.expect("get");

        // Change several fields.
        settings.blocking_mode = BlockingMode::Custom;
        settings.custom_block_ipv4 = Some("203.0.113.1".parse().unwrap());
        settings.custom_block_ipv6 = Some("2001:db8::1".parse().unwrap());
        settings.cache_max_ttl = 43200;
        settings.ui_theme = "dark".to_owned();

        repo.update(&settings).await.expect("update");

        let fetched = repo.get().await.expect("re-get");
        assert_eq!(fetched.blocking_mode, BlockingMode::Custom);
        assert_eq!(
            fetched.custom_block_ipv4,
            Some("203.0.113.1".parse().unwrap())
        );
        assert_eq!(
            fetched.custom_block_ipv6,
            Some("2001:db8::1".parse().unwrap())
        );
        assert_eq!(fetched.cache_max_ttl, 43200u32);
        assert_eq!(fetched.ui_theme, "dark");
    }

    #[tokio::test]
    async fn update_clears_custom_ips() {
        let (_dir, repo) = open_repo().await;

        // Set custom IPs first.
        let mut settings = repo.get().await.expect("get");
        settings.custom_block_ipv4 = Some("10.0.0.1".parse().unwrap());
        repo.update(&settings).await.expect("update with IP");

        // Now clear them.
        settings.custom_block_ipv4 = None;
        repo.update(&settings).await.expect("update clearing IP");

        let fetched = repo.get().await.expect("re-get");
        assert!(fetched.custom_block_ipv4.is_none());
    }

    #[tokio::test]
    async fn update_blocking_mode_round_trips_all_variants() {
        let (_dir, repo) = open_repo().await;
        let mut settings = repo.get().await.expect("get");

        for mode in [
            BlockingMode::NxDomain,
            BlockingMode::NullIp,
            BlockingMode::Custom,
        ] {
            settings.blocking_mode = mode;
            repo.update(&settings).await.expect("update");
            let fetched = repo.get().await.expect("re-get");
            assert_eq!(fetched.blocking_mode, mode, "round-trip for {mode}");
        }
    }
}
