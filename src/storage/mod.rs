//! Persistent storage backed by SQLite.
//!
//! Acts as the durable system of record for configuration: upstreams, admin
//! credentials and sessions, blocklist source definitions, the admin
//! blacklist/allowlist, and local DNS records (see SPEC §4).
//!
//! Access is provided through [`sqlx`] with compile-time-checked queries
//! (`query!` / `query_as!`).  Embedded migrations are applied at startup via
//! `sqlx::migrate!` so the schema is always up-to-date.
//!
//! At startup the relevant tables are read into the in-memory data structures
//! held by the `app` module.  Subsequent writes go to SQLite first, then
//! refresh the live in-memory snapshot.
//!
//! # Sub-modules
//!
//! | Sub-module | Responsibility |
//! |---|---|
//! | [`admin_users`] | Web-admin credentials: [`admin_users::AdminUserRepository`] + [`admin_users::SqliteAdminUserRepo`] |
//! | [`api_keys`] | Config-sync bearer keys: [`api_keys::ApiKeyRepository`] + [`api_keys::SqliteApiKeyRepo`] |
//! | [`blocklists`] | Blocklist source + offline cache: [`blocklists::BlocklistRepository`] + [`blocklists::SqliteBlocklistRepo`] |
//! | [`forward_zones`] | Conditional-forward zone rows: [`forward_zones::ForwardZoneRepository`] + [`forward_zones::SqliteForwardZoneRepo`] |
//! | [`lists`] | Blacklist + allowlist repos: [`lists::BlacklistRepository`] + [`lists::AllowlistRepository`] |
//! | [`local_records`] | Local DNS record rows: [`local_records::LocalRecordRepository`] + [`local_records::SqliteLocalRecordRepo`] |
//! | [`query_log`] | Durable per-query history: [`query_log::QueryLogRepository`] + [`query_log::SqliteQueryLogRepo`] |
//! | [`settings`] | Singleton settings row: [`settings::SettingsRepository`] + [`settings::SqliteSettingsRepo`] |
//! | [`upstreams`] | Upstream resolver rows: [`upstreams::UpstreamRepository`] + [`upstreams::SqliteUpstreamRepo`] |

pub mod admin_users;
pub mod api_keys;
pub mod blocklists;
pub mod forward_zones;
pub mod lists;
pub mod local_records;
pub mod query_log;
pub mod sessions;
pub mod settings;
pub mod upstreams;

use std::{path::Path, time::Duration};

use sqlx::{
    SqlitePool,
    sqlite::{
        SqliteAutoVacuum, SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions,
        SqliteSynchronous,
    },
};

// ── Errors ─────────────────────────────────────────────────────────────────

/// Errors that can occur while opening, migrating, reading, or writing
/// the SQLite database.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A SQLite or pool-level error.
    #[error("database error: {0}")]
    Sqlx(#[from] sqlx::Error),

    /// A schema migration failed.
    #[error("migration failed: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),

    /// A value stored in the database could not be decoded into the expected
    /// domain type (e.g. an unrecognised enum discriminant or an invalid IP
    /// address string).
    #[error("decode error: {0}")]
    Decode(String),

    /// A domain name string supplied to a repository method could not be
    /// parsed as a valid DNS name (e.g. an empty label, a label longer than 63
    /// bytes, or a name exceeding 255 wire-format bytes).
    #[error("invalid domain name: {0}")]
    InvalidDomain(String),
}

// ── Db ─────────────────────────────────────────────────────────────────────

/// An open, migrated SQLite connection pool.
///
/// Constructed via [`Db::connect`]; exposes the underlying [`SqlitePool`]
/// through [`Db::pool`] for use by repository layers (E3.4+).
///
/// # Pool settings
///
/// - WAL journal mode (explicit — sqlx does not default to WAL).
/// - `synchronous = NORMAL` — safe crash consistency with WAL.
/// - 5-second busy timeout — appropriate for SQLite's single-writer model.
/// - Foreign key enforcement enabled.
/// - Incremental auto-vacuum so the query-log retention purge (E10.5) can
///   return freed pages to the OS via `PRAGMA incremental_vacuum`. This only
///   takes effect on a **freshly created** database; an existing DB keeps
///   whatever auto-vacuum mode it was created with (its space is reused but not
///   returned, which we accept rather than running a whole-DB `VACUUM`).
/// - Maximum 5 connections — modest, given SQLite is single-writer.
#[derive(Debug, Clone)]
pub struct Db {
    pool: SqlitePool,
}

impl Db {
    /// Open (or create) the SQLite database at `path`, apply any pending
    /// embedded migrations, and return a ready-to-use [`Db`].
    ///
    /// The file is created if it does not exist. All pragmas listed in the
    /// struct documentation are applied to every new connection.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Sqlx`] if the pool cannot be built, or
    /// [`Error::Migrate`] if a migration fails.
    pub async fn connect(path: impl AsRef<Path>) -> Result<Self, Error> {
        let connect_options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .busy_timeout(Duration::from_secs(5))
            .auto_vacuum(SqliteAutoVacuum::Incremental)
            .foreign_keys(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(connect_options)
            .await?;

        sqlx::migrate!("./migrations").run(&pool).await?;

        Ok(Self { pool })
    }

    /// Returns a reference to the underlying [`SqlitePool`].
    ///
    /// Repository layers (E3.4+) use this to execute queries against the pool.
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    // ── Repository accessors ──────────────────────────────────────────────────
    //
    // Convenience constructors so callers write `db.settings()` instead of
    // `SqliteSettingsRepo::new(db.pool().clone())`. Each repo is a cheap handle
    // over a cloned pool (the pool itself is an `Arc`), so constructing one per
    // call is free; this just centralizes the wiring.

    /// Repository for the singleton settings row.
    pub fn settings(&self) -> settings::SqliteSettingsRepo {
        settings::SqliteSettingsRepo::new(self.pool.clone())
    }

    /// Repository for upstream resolver rows.
    pub fn upstreams(&self) -> upstreams::SqliteUpstreamRepo {
        upstreams::SqliteUpstreamRepo::new(self.pool.clone())
    }

    /// Repository for conditional-forward zone rows.
    pub fn forward_zones(&self) -> forward_zones::SqliteForwardZoneRepo {
        forward_zones::SqliteForwardZoneRepo::new(self.pool.clone())
    }

    /// Repository for blocklist source rows + the offline content cache.
    pub fn blocklists(&self) -> blocklists::SqliteBlocklistRepo {
        blocklists::SqliteBlocklistRepo::new(self.pool.clone())
    }

    /// Repository for the admin blacklist.
    pub fn blacklist(&self) -> lists::SqliteBlacklistRepo {
        lists::SqliteBlacklistRepo::new(self.pool.clone())
    }

    /// Repository for the admin allowlist.
    pub fn allowlist(&self) -> lists::SqliteAllowlistRepo {
        lists::SqliteAllowlistRepo::new(self.pool.clone())
    }

    /// Repository for authoritative local DNS records.
    pub fn local_records(&self) -> local_records::SqliteLocalRecordRepo {
        local_records::SqliteLocalRecordRepo::new(self.pool.clone())
    }

    /// Repository for web-admin credentials.
    pub fn admin_users(&self) -> admin_users::SqliteAdminUserRepo {
        admin_users::SqliteAdminUserRepo::new(self.pool.clone())
    }

    /// Repository for admin sessions.
    pub fn sessions(&self) -> sessions::SqliteSessionRepo {
        sessions::SqliteSessionRepo::new(self.pool.clone())
    }

    /// Repository for config-sync API keys (SPEC §13).
    pub fn api_keys(&self) -> api_keys::SqliteApiKeyRepo {
        api_keys::SqliteApiKeyRepo::new(self.pool.clone())
    }

    /// Repository for the durable per-query log.
    pub fn query_log(&self) -> query_log::SqliteQueryLogRepo {
        query_log::SqliteQueryLogRepo::new(self.pool.clone())
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn connect_creates_db_file() {
        let dir = TempDir::new().expect("create temp dir");
        let path = dir.path().join("sagittarius.db");
        assert!(!path.exists(), "file must not exist before connect");
        let _db = Db::connect(&path).await.expect("connect");
        assert!(path.exists(), "DB file must exist after connect");
    }

    #[tokio::test]
    async fn connect_applies_migrations() {
        // Connecting to a fresh DB must run migrations without error.
        let (_dir, _db) = crate::test_support::temp_db().await;
    }

    // ── Schema presence ───────────────────────────────────────────────────────

    /// Assert that every v0.1 config table was created by the migration.
    #[tokio::test]
    async fn schema_all_tables_exist() {
        let (_dir, db) = crate::test_support::temp_db().await;

        let expected = [
            "settings",
            "upstreams",
            "admin_users",
            "sessions",
            "blocklists",
            "blocklist_cache",
            "blacklist",
            "allowlist",
            "local_records",
            "api_keys",
        ];

        for table in expected {
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?",
            )
            .bind(table)
            .fetch_one(db.pool())
            .await
            .unwrap_or_else(|e| panic!("sqlite_master query failed for {table}: {e}"));

            assert_eq!(count, 1, "table '{table}' must exist after migration");
        }
    }

    /// Spot-check key columns on representative tables via PRAGMA table_info.
    #[tokio::test]
    async fn schema_key_columns_exist() {
        let (_dir, db) = crate::test_support::temp_db().await;

        // (table, column_name) pairs that must exist.
        let expected_columns: &[(&str, &str)] = &[
            ("settings", "id"),
            ("settings", "cache_min_ttl"),
            ("settings", "cache_max_ttl"),
            ("settings", "cache_negative_ttl_cap"),
            ("settings", "cache_capacity"),
            ("settings", "blocking_mode"),
            ("settings", "custom_block_ipv4"),
            ("settings", "custom_block_ipv6"),
            ("settings", "blocklist_refresh_interval"),
            ("settings", "ui_theme"),
            ("upstreams", "id"),
            ("upstreams", "address"),
            ("upstreams", "transport"),
            ("upstreams", "tls_server_name"),
            ("upstreams", "enabled"),
            ("upstreams", "sort_order"),
            ("admin_users", "id"),
            ("admin_users", "username"),
            ("admin_users", "password_hash"),
            ("admin_users", "role"),
            ("admin_users", "created_at"),
            ("admin_users", "updated_at"),
            ("sessions", "id"),
            ("sessions", "token_hash"),
            ("sessions", "user_id"),
            ("sessions", "created_at"),
            ("sessions", "expires_at"),
            ("blocklists", "url"),
            ("blocklists", "format"),
            ("blocklists", "enabled"),
            ("blocklists", "entry_count"),
            ("blocklists", "last_updated"),
            ("blocklists", "etag"),
            ("blocklists", "last_modified"),
            ("blocklist_cache", "blocklist_id"),
            ("blocklist_cache", "content"),
            ("blocklist_cache", "fetched_at"),
            ("blacklist", "domain"),
            ("blacklist", "created_at"),
            ("allowlist", "domain"),
            ("allowlist", "created_at"),
            ("local_records", "name"),
            ("local_records", "record_type"),
            ("local_records", "value"),
            ("local_records", "ttl"),
        ];

        for (table, column) in expected_columns {
            // PRAGMA table_info returns one row per column; we count rows where
            // the name matches.
            let count: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?")
                    .bind(table)
                    .bind(column)
                    .fetch_one(db.pool())
                    .await
                    .unwrap_or_else(|e| {
                        panic!("pragma_table_info query failed for {table}.{column}: {e}")
                    });

            assert_eq!(count, 1, "column '{column}' must exist in table '{table}'");
        }
    }

    /// Verify that the expected indexes were created.
    #[tokio::test]
    async fn schema_indexes_exist() {
        let (_dir, db) = crate::test_support::temp_db().await;

        let expected_indexes: &[(&str, &str)] = &[
            ("upstreams", "idx_upstreams_enabled_sort"),
            ("sessions", "idx_sessions_user_id"),
            ("sessions", "idx_sessions_expires_at"),
        ];

        for (table, index) in expected_indexes {
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM sqlite_master \
                 WHERE type = 'index' AND tbl_name = ? AND name = ?",
            )
            .bind(table)
            .bind(index)
            .fetch_one(db.pool())
            .await
            .unwrap_or_else(|e| panic!("sqlite_master query failed for index {index}: {e}"));

            assert_eq!(
                count, 1,
                "index '{index}' on table '{table}' must exist after migration"
            );
        }
    }

    // ── Constraint enforcement ─────────────────────────────────────────────────

    /// The settings CHECK (id = 1) must reject a row with id <> 1.
    #[tokio::test]
    async fn settings_check_id_rejects_nonone() {
        let (_dir, db) = crate::test_support::temp_db().await;

        let result = sqlx::query(
            "INSERT INTO settings \
             (id, cache_min_ttl, cache_max_ttl, cache_negative_ttl_cap, cache_capacity, \
              blocking_mode, blocklist_refresh_interval) \
             VALUES (2, 60, 86400, 300, 10000, 'nxdomain', 3600)",
        )
        .execute(db.pool())
        .await;

        assert!(
            result.is_err(),
            "inserting settings row with id=2 must fail the CHECK (id=1)"
        );
    }

    /// A second settings row (even with id = 1) must be rejected by PRIMARY KEY.
    /// After the seed migration the row (id = 1) already exists, so a direct
    /// INSERT — without ON CONFLICT DO NOTHING — must fail.
    #[tokio::test]
    async fn settings_check_id_rejects_second_row() {
        let (_dir, db) = crate::test_support::temp_db().await;

        // The seed migration inserted id = 1; a plain INSERT must therefore
        // fail with a PRIMARY KEY (and CHECK) violation.
        let result = sqlx::query(
            "INSERT INTO settings \
             (id, cache_min_ttl, cache_max_ttl, cache_negative_ttl_cap, cache_capacity, \
              blocking_mode, blocklist_refresh_interval) \
             VALUES (1, 30, 3600, 60, 5000, 'null-ip', 7200)",
        )
        .execute(db.pool())
        .await;

        assert!(
            result.is_err(),
            "a second settings row must fail due to PRIMARY KEY uniqueness"
        );
    }

    /// A FK violation on blocklist_cache.blocklist_id must be rejected.
    #[tokio::test]
    async fn fk_blocklist_cache_rejects_missing_parent() {
        let (_dir, db) = crate::test_support::temp_db().await;

        // blocklist_id = 9999 does not exist in blocklists.
        let result = sqlx::query(
            "INSERT INTO blocklist_cache (blocklist_id, content) VALUES (9999, X'DEADBEEF')",
        )
        .execute(db.pool())
        .await;

        assert!(
            result.is_err(),
            "inserting blocklist_cache with non-existent blocklist_id must fail FK constraint"
        );
    }

    /// A FK violation on sessions.user_id must be rejected.
    #[tokio::test]
    async fn fk_sessions_rejects_missing_user() {
        let (_dir, db) = crate::test_support::temp_db().await;

        let result = sqlx::query(
            "INSERT INTO sessions (id, token_hash, user_id, expires_at) \
             VALUES ('sess-abc', 'hash123', 9999, 9999999999)",
        )
        .execute(db.pool())
        .await;

        assert!(
            result.is_err(),
            "inserting session with non-existent user_id must fail FK constraint"
        );
    }

    /// UNIQUE on blacklist.domain must reject a duplicate domain.
    #[tokio::test]
    async fn unique_blacklist_domain() {
        let (_dir, db) = crate::test_support::temp_db().await;

        sqlx::query("INSERT INTO blacklist (domain) VALUES ('ads.example.com')")
            .execute(db.pool())
            .await
            .expect("first blacklist insert must succeed");

        let result = sqlx::query("INSERT INTO blacklist (domain) VALUES ('ads.example.com')")
            .execute(db.pool())
            .await;

        assert!(
            result.is_err(),
            "duplicate blacklist domain must fail UNIQUE constraint"
        );
    }

    /// UNIQUE on allowlist.domain must reject a duplicate domain.
    #[tokio::test]
    async fn unique_allowlist_domain() {
        let (_dir, db) = crate::test_support::temp_db().await;

        sqlx::query("INSERT INTO allowlist (domain) VALUES ('safe.example.com')")
            .execute(db.pool())
            .await
            .expect("first allowlist insert must succeed");

        let result = sqlx::query("INSERT INTO allowlist (domain) VALUES ('safe.example.com')")
            .execute(db.pool())
            .await;

        assert!(
            result.is_err(),
            "duplicate allowlist domain must fail UNIQUE constraint"
        );
    }

    /// UNIQUE (name, record_type) on local_records: same name + same type must
    /// fail, but same name + different type must succeed.
    #[tokio::test]
    async fn unique_local_records_name_type() {
        let (_dir, db) = crate::test_support::temp_db().await;

        // First record: A record for router.home.lan.
        sqlx::query(
            "INSERT INTO local_records (name, record_type, value, ttl) \
             VALUES ('router.home.lan', 'A', '192.168.1.1', 300)",
        )
        .execute(db.pool())
        .await
        .expect("first local_records insert must succeed");

        // Duplicate (name, record_type) must fail.
        let dup_result = sqlx::query(
            "INSERT INTO local_records (name, record_type, value, ttl) \
             VALUES ('router.home.lan', 'A', '192.168.1.2', 300)",
        )
        .execute(db.pool())
        .await;

        assert!(
            dup_result.is_err(),
            "duplicate (name, record_type) in local_records must fail UNIQUE constraint"
        );

        // Same name but different type (AAAA) must succeed.
        sqlx::query(
            "INSERT INTO local_records (name, record_type, value, ttl) \
             VALUES ('router.home.lan', 'AAAA', 'fd00::1', 300)",
        )
        .execute(db.pool())
        .await
        .expect("AAAA record for same name must succeed (different record_type)");
    }

    /// Connecting to a DB that already has all migrations applied must be a
    /// no-op (idempotent).
    #[tokio::test]
    async fn migrate_twice_is_noop() {
        let dir = TempDir::new().expect("create temp dir");
        let path = dir.path().join("sagittarius.db");

        let db1 = Db::connect(&path).await.expect("first connect");
        // All tables must exist after the first connect.
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'settings'",
        )
        .fetch_one(db1.pool())
        .await
        .expect("sqlite_master query");
        assert_eq!(count, 1, "settings table must exist after first connect");

        // Second connect re-runs migrate! but must succeed (already applied).
        let db2 = Db::connect(&path).await.expect("second connect is a no-op");
        let count2: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'settings'",
        )
        .fetch_one(db2.pool())
        .await
        .expect("sqlite_master query on second connect");
        assert_eq!(
            count2, 1,
            "settings table must still exist after second connect"
        );
    }

    #[tokio::test]
    async fn wal_mode_is_active() {
        let (_dir, db) = crate::test_support::temp_db().await;
        let mode: String = sqlx::query_scalar("PRAGMA journal_mode;")
            .fetch_one(db.pool())
            .await
            .expect("query journal_mode");
        assert_eq!(mode, "wal", "journal_mode must be WAL");
    }

    #[tokio::test]
    async fn auto_vacuum_is_incremental_on_fresh_db() {
        let (_dir, db) = crate::test_support::temp_db().await;
        // 0 = NONE, 1 = FULL, 2 = INCREMENTAL.
        let mode: i64 = sqlx::query_scalar("PRAGMA auto_vacuum;")
            .fetch_one(db.pool())
            .await
            .expect("query auto_vacuum");
        assert_eq!(mode, 2, "auto_vacuum must be INCREMENTAL (2) on a fresh DB");
    }

    // ── query_log migration (E10.1) ───────────────────────────────────────────

    /// The query_log table and all its columns must exist after migration.
    #[tokio::test]
    async fn query_log_table_and_columns_exist() {
        let (_dir, db) = crate::test_support::temp_db().await;

        let table_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'query_log'",
        )
        .fetch_one(db.pool())
        .await
        .expect("sqlite_master query for query_log");
        assert_eq!(table_count, 1, "query_log table must exist");

        let columns = [
            "id",
            "ts",
            "client",
            "qname",
            "qtype",
            "outcome",
            "rcode",
            "upstream",
            "latency_ms",
        ];
        for column in columns {
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM pragma_table_info('query_log') WHERE name = ?",
            )
            .bind(column)
            .fetch_one(db.pool())
            .await
            .unwrap_or_else(|e| panic!("pragma_table_info for query_log.{column}: {e}"));
            assert_eq!(count, 1, "column '{column}' must exist in query_log");
        }
    }

    /// The retention-purge index on query_log.ts must exist.
    #[tokio::test]
    async fn query_log_ts_index_exists() {
        let (_dir, db) = crate::test_support::temp_db().await;
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master \
             WHERE type = 'index' AND tbl_name = 'query_log' AND name = 'idx_query_log_ts'",
        )
        .fetch_one(db.pool())
        .await
        .expect("sqlite_master query for idx_query_log_ts");
        assert_eq!(count, 1, "idx_query_log_ts must exist");
    }

    /// The new settings columns must exist with their seeded defaults (1 / 30).
    #[tokio::test]
    async fn query_log_settings_defaults() {
        let (_dir, db) = crate::test_support::temp_db().await;

        let enabled: i64 =
            sqlx::query_scalar("SELECT query_log_enabled FROM settings WHERE id = 1")
                .fetch_one(db.pool())
                .await
                .expect("query_log_enabled");
        assert_eq!(enabled, 1, "query_log_enabled must default to 1");

        let retention: i64 =
            sqlx::query_scalar("SELECT query_log_retention_days FROM settings WHERE id = 1")
                .fetch_one(db.pool())
                .await
                .expect("query_log_retention_days");
        assert_eq!(retention, 30, "query_log_retention_days must default to 30");
    }

    /// The down migration must cleanly drop the table, index, and both columns.
    #[tokio::test]
    async fn query_log_down_migration_is_clean_inverse() {
        let (_dir, db) = crate::test_support::temp_db().await;

        let down_sql = include_str!("../../migrations/20260529130933_query_log.down.sql");
        sqlx::raw_sql(down_sql)
            .execute(db.pool())
            .await
            .expect("apply query_log down migration");

        let table_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'query_log'",
        )
        .fetch_one(db.pool())
        .await
        .expect("sqlite_master query for query_log after down");
        assert_eq!(table_count, 0, "query_log table must be dropped");

        let index_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'idx_query_log_ts'",
        )
        .fetch_one(db.pool())
        .await
        .expect("sqlite_master query for idx after down");
        assert_eq!(index_count, 0, "idx_query_log_ts must be dropped");

        for column in ["query_log_enabled", "query_log_retention_days"] {
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM pragma_table_info('settings') WHERE name = ?",
            )
            .bind(column)
            .fetch_one(db.pool())
            .await
            .unwrap_or_else(|e| panic!("pragma_table_info for settings.{column}: {e}"));
            assert_eq!(
                count, 0,
                "settings.{column} must be dropped by down migration"
            );
        }
    }

    // ── query_log.blocklist_id migration (E11.2) ──────────────────────────────

    /// The blocklist_id attribution column must exist and be nullable.
    #[tokio::test]
    async fn query_log_blocklist_id_column_exists_and_nullable() {
        let (_dir, db) = crate::test_support::temp_db().await;

        let notnull: Option<i64> = sqlx::query_scalar(
            "SELECT \"notnull\" FROM pragma_table_info('query_log') WHERE name = 'blocklist_id'",
        )
        .fetch_optional(db.pool())
        .await
        .expect("pragma_table_info for query_log.blocklist_id");

        assert_eq!(
            notnull,
            Some(0),
            "query_log.blocklist_id must exist and be nullable"
        );
    }

    /// The down migration must drop only the blocklist_id column, leaving the
    /// rest of the query_log table intact.
    #[tokio::test]
    async fn query_log_blocklist_id_down_migration_is_clean_inverse() {
        let (_dir, db) = crate::test_support::temp_db().await;

        let down_sql =
            include_str!("../../migrations/20260529130934_query_log_blocklist_id.down.sql");
        sqlx::raw_sql(down_sql)
            .execute(db.pool())
            .await
            .expect("apply blocklist_id down migration");

        let col_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pragma_table_info('query_log') WHERE name = 'blocklist_id'",
        )
        .fetch_one(db.pool())
        .await
        .expect("pragma_table_info after down");
        assert_eq!(col_count, 0, "blocklist_id column must be dropped");

        // The table itself and its other columns must survive the down.
        let table_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'query_log'",
        )
        .fetch_one(db.pool())
        .await
        .expect("sqlite_master query for query_log after down");
        assert_eq!(table_count, 1, "query_log table must remain");

        let qname_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pragma_table_info('query_log') WHERE name = 'qname'",
        )
        .fetch_one(db.pool())
        .await
        .expect("pragma_table_info for query_log.qname after down");
        assert_eq!(qname_count, 1, "other query_log columns must remain");
    }

    // ── forward_zones migration (E13.3) ───────────────────────────────────────

    /// The forward_zones table, its columns, and its index must exist after
    /// migration, and the seed must install the 20 disabled, untargeted zones.
    #[tokio::test]
    async fn forward_zones_table_columns_index_and_seed() {
        let (_dir, db) = crate::test_support::temp_db().await;

        let table_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'forward_zones'",
        )
        .fetch_one(db.pool())
        .await
        .expect("sqlite_master query for forward_zones");
        assert_eq!(table_count, 1, "forward_zones table must exist");

        for column in ["id", "zone_suffix", "target", "enabled", "sort_order"] {
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM pragma_table_info('forward_zones') WHERE name = ?",
            )
            .bind(column)
            .fetch_one(db.pool())
            .await
            .unwrap_or_else(|e| panic!("pragma_table_info for forward_zones.{column}: {e}"));
            assert_eq!(count, 1, "column '{column}' must exist in forward_zones");
        }

        let index_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master \
             WHERE type = 'index' AND tbl_name = 'forward_zones' \
               AND name = 'idx_forward_zones_enabled_sort'",
        )
        .fetch_one(db.pool())
        .await
        .expect("sqlite_master query for forward_zones index");
        assert_eq!(index_count, 1, "idx_forward_zones_enabled_sort must exist");

        // Seed: 20 zones, all disabled with a NULL target.
        let seeded: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM forward_zones WHERE enabled = 0 AND target IS NULL",
        )
        .fetch_one(db.pool())
        .await
        .expect("count seeded forward zones");
        assert_eq!(
            seeded, 20,
            "all 20 reverse zones must be seeded disabled and untargeted"
        );
    }

    /// The down migration must cleanly drop the index and table.
    #[tokio::test]
    async fn forward_zones_down_migration_is_clean_inverse() {
        let (_dir, db) = crate::test_support::temp_db().await;

        let down_sql = include_str!("../../migrations/20260529130936_forward_zones.down.sql");
        sqlx::raw_sql(down_sql)
            .execute(db.pool())
            .await
            .expect("apply forward_zones down migration");

        let table_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'forward_zones'",
        )
        .fetch_one(db.pool())
        .await
        .expect("sqlite_master query for forward_zones after down");
        assert_eq!(table_count, 0, "forward_zones table must be dropped");

        let index_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master \
             WHERE type = 'index' AND name = 'idx_forward_zones_enabled_sort'",
        )
        .fetch_one(db.pool())
        .await
        .expect("sqlite_master query for forward_zones index after down");
        assert_eq!(index_count, 0, "forward_zones index must be dropped");
    }

    // ── api_keys migration (E18.1) ────────────────────────────────────────────

    /// The api_keys table, its columns, and the active-lookup index must exist.
    #[tokio::test]
    async fn api_keys_table_columns_and_index() {
        let (_dir, db) = crate::test_support::temp_db().await;

        for column in [
            "id",
            "token_hash",
            "label",
            "created_at",
            "last_used_at",
            "revoked_at",
        ] {
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM pragma_table_info('api_keys') WHERE name = ?",
            )
            .bind(column)
            .fetch_one(db.pool())
            .await
            .unwrap_or_else(|e| panic!("pragma_table_info for api_keys.{column}: {e}"));
            assert_eq!(count, 1, "column '{column}' must exist in api_keys");
        }

        let index_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master \
             WHERE type = 'index' AND tbl_name = 'api_keys' AND name = 'idx_api_keys_active'",
        )
        .fetch_one(db.pool())
        .await
        .expect("sqlite_master query for api_keys index");
        assert_eq!(index_count, 1, "idx_api_keys_active must exist");
    }

    /// The down migration must cleanly drop the index and table.
    #[tokio::test]
    async fn api_keys_down_migration_is_clean_inverse() {
        let (_dir, db) = crate::test_support::temp_db().await;

        let down_sql = include_str!("../../migrations/20260705123646_api_keys.down.sql");
        sqlx::raw_sql(down_sql)
            .execute(db.pool())
            .await
            .expect("apply api_keys down migration");

        let table_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'api_keys'",
        )
        .fetch_one(db.pool())
        .await
        .expect("sqlite_master query for api_keys after down");
        assert_eq!(table_count, 0, "api_keys table must be dropped");

        let index_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master \
             WHERE type = 'index' AND name = 'idx_api_keys_active'",
        )
        .fetch_one(db.pool())
        .await
        .expect("sqlite_master query for api_keys index after down");
        assert_eq!(index_count, 0, "api_keys index must be dropped");
    }

    #[tokio::test]
    async fn foreign_keys_are_enforced() {
        let (_dir, db) = crate::test_support::temp_db().await;
        let fk: i64 = sqlx::query_scalar("PRAGMA foreign_keys;")
            .fetch_one(db.pool())
            .await
            .expect("query foreign_keys");
        assert_eq!(fk, 1, "foreign_keys must be enabled");
    }

    #[tokio::test]
    async fn trivial_query_round_trips() {
        let (_dir, db) = crate::test_support::temp_db().await;
        let val: i64 = sqlx::query_scalar("SELECT 1;")
            .fetch_one(db.pool())
            .await
            .expect("SELECT 1");
        assert_eq!(val, 1);
    }

    #[tokio::test]
    async fn connect_twice_same_path_is_noop() {
        let dir = TempDir::new().expect("create temp dir");
        let path = dir.path().join("sagittarius.db");
        let _db1 = Db::connect(&path).await.expect("first connect");
        // Re-running migrations on an already-migrated DB must succeed.
        let _db2 = Db::connect(&path).await.expect("second connect");
    }

    #[tokio::test]
    async fn error_display_sqlx() {
        // Exercise the Display impl on Error::Sqlx via a deliberately bad
        // connect options path (directory as DB path).
        let dir = TempDir::new().expect("create temp dir");
        // A directory path is not a valid SQLite file — connect must fail.
        let result = Db::connect(dir.path()).await;
        assert!(
            result.is_err(),
            "opening a directory as DB must return an error"
        );
        let msg = result.unwrap_err().to_string();
        assert!(!msg.is_empty(), "error message must be non-empty: {msg:?}");
    }

    // ── Seed-defaults migration ───────────────────────────────────────────────

    /// After a fresh connect the upstreams table must contain exactly the two
    /// Cloudflare default resolvers seeded by the seed-defaults migration.
    #[tokio::test]
    async fn seed_upstreams_count_and_addresses() {
        let (_dir, db) = crate::test_support::temp_db().await;

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM upstreams")
            .fetch_one(db.pool())
            .await
            .expect("count upstreams");
        assert_eq!(count, 2, "exactly 2 default upstreams must be seeded");

        // Both Cloudflare addresses must be present.
        for addr in &["1.1.1.1", "1.0.0.1"] {
            let found: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM upstreams WHERE address = ?")
                .bind(addr)
                .fetch_one(db.pool())
                .await
                .unwrap_or_else(|e| panic!("query for upstream {addr}: {e}"));
            assert_eq!(found, 1, "upstream {addr} must exist");
        }
    }

    /// Both seeded upstreams must use UDP transport and be enabled.
    #[tokio::test]
    async fn seed_upstreams_transport_and_enabled() {
        let (_dir, db) = crate::test_support::temp_db().await;

        // Use runtime (non-macro) query to stay offline-compilable.
        let rows: Vec<(String, String, i64)> =
            sqlx::query_as("SELECT address, transport, enabled FROM upstreams ORDER BY sort_order")
                .fetch_all(db.pool())
                .await
                .expect("fetch upstreams");

        assert_eq!(rows.len(), 2, "must be exactly 2 seeded upstreams");
        for (address, transport, enabled) in &rows {
            assert_eq!(
                transport, "udp",
                "upstream {address} must use udp transport"
            );
            assert_eq!(enabled, &1i64, "upstream {address} must be enabled");
        }
    }

    /// After a fresh connect the settings table must contain exactly one row
    /// (id = 1) with all the pinned seed values.
    #[tokio::test]
    async fn seed_settings_defaults() {
        let (_dir, db) = crate::test_support::temp_db().await;

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM settings")
            .fetch_one(db.pool())
            .await
            .expect("count settings");
        assert_eq!(count, 1, "exactly one settings row must exist");

        // Verify each pinned default individually using runtime queries
        // (no compile-time query! macros so offline builds stay green).

        let cache_min_ttl: i64 =
            sqlx::query_scalar("SELECT cache_min_ttl FROM settings WHERE id = 1")
                .fetch_one(db.pool())
                .await
                .expect("cache_min_ttl");
        assert_eq!(cache_min_ttl, 1, "cache_min_ttl must be 1");

        let cache_max_ttl: i64 =
            sqlx::query_scalar("SELECT cache_max_ttl FROM settings WHERE id = 1")
                .fetch_one(db.pool())
                .await
                .expect("cache_max_ttl");
        assert_eq!(cache_max_ttl, 86400, "cache_max_ttl must be 86400");

        let cache_negative_ttl_cap: i64 =
            sqlx::query_scalar("SELECT cache_negative_ttl_cap FROM settings WHERE id = 1")
                .fetch_one(db.pool())
                .await
                .expect("cache_negative_ttl_cap");
        assert_eq!(
            cache_negative_ttl_cap, 3600,
            "cache_negative_ttl_cap must be 3600"
        );

        let cache_capacity: i64 =
            sqlx::query_scalar("SELECT cache_capacity FROM settings WHERE id = 1")
                .fetch_one(db.pool())
                .await
                .expect("cache_capacity");
        assert_eq!(cache_capacity, 100000, "cache_capacity must be 100000");

        let blocking_mode: String =
            sqlx::query_scalar("SELECT blocking_mode FROM settings WHERE id = 1")
                .fetch_one(db.pool())
                .await
                .expect("blocking_mode");
        assert_eq!(blocking_mode, "null-ip", "blocking_mode must be 'null-ip'");

        let custom_block_ipv4: Option<String> =
            sqlx::query_scalar("SELECT custom_block_ipv4 FROM settings WHERE id = 1")
                .fetch_one(db.pool())
                .await
                .expect("custom_block_ipv4");
        assert!(
            custom_block_ipv4.is_none(),
            "custom_block_ipv4 must be NULL by default"
        );

        let custom_block_ipv6: Option<String> =
            sqlx::query_scalar("SELECT custom_block_ipv6 FROM settings WHERE id = 1")
                .fetch_one(db.pool())
                .await
                .expect("custom_block_ipv6");
        assert!(
            custom_block_ipv6.is_none(),
            "custom_block_ipv6 must be NULL by default"
        );

        let blocklist_refresh_interval: i64 =
            sqlx::query_scalar("SELECT blocklist_refresh_interval FROM settings WHERE id = 1")
                .fetch_one(db.pool())
                .await
                .expect("blocklist_refresh_interval");
        assert_eq!(
            blocklist_refresh_interval, 86400,
            "blocklist_refresh_interval must be 86400"
        );
    }

    /// Re-applying the seed SQL directly must be a no-op: admin-changed values
    /// are preserved and no duplicate rows are created.
    #[tokio::test]
    async fn seed_idempotency_preserves_admin_edits() {
        let (_dir, db) = crate::test_support::temp_db().await;

        // Simulate admin changes: different cache_max_ttl and disable one upstream.
        sqlx::query("UPDATE settings SET cache_max_ttl = 7200 WHERE id = 1")
            .execute(db.pool())
            .await
            .expect("update settings");
        sqlx::query("UPDATE upstreams SET enabled = 0 WHERE address = '1.0.0.1'")
            .execute(db.pool())
            .await
            .expect("disable upstream");

        // Re-apply the seed SQL directly (as if the migration ran a second time).
        let seed_sql = include_str!("../../migrations/20260529130932_seed_defaults.up.sql");
        sqlx::raw_sql(seed_sql)
            .execute(db.pool())
            .await
            .expect("re-apply seed SQL");

        // The edited cache_max_ttl must be preserved (ON CONFLICT DO NOTHING held).
        let cache_max_ttl: i64 =
            sqlx::query_scalar("SELECT cache_max_ttl FROM settings WHERE id = 1")
                .fetch_one(db.pool())
                .await
                .expect("cache_max_ttl after re-seed");
        assert_eq!(
            cache_max_ttl, 7200,
            "admin-changed cache_max_ttl must not be overwritten by re-seeding"
        );

        // The disabled upstream must still be disabled.
        let enabled: i64 =
            sqlx::query_scalar("SELECT enabled FROM upstreams WHERE address = '1.0.0.1'")
                .fetch_one(db.pool())
                .await
                .expect("enabled flag after re-seed");
        assert_eq!(
            enabled, 0,
            "admin-disabled upstream must not be re-enabled by re-seeding"
        );

        // No duplicate rows must have been created.
        let settings_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM settings")
            .fetch_one(db.pool())
            .await
            .expect("count settings after re-seed");
        assert_eq!(
            settings_count, 1,
            "still exactly one settings row after re-seeding"
        );

        let upstream_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM upstreams")
            .fetch_one(db.pool())
            .await
            .expect("count upstreams after re-seed");
        assert_eq!(
            upstream_count, 2,
            "still exactly 2 upstream rows after re-seeding"
        );
    }
}
