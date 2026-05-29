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

use std::{path::Path, time::Duration};

use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
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
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Helper: create a temp dir and open a fresh DB inside it.
    async fn open_temp_db() -> (TempDir, Db) {
        let dir = TempDir::new().expect("create temp dir");
        let path = dir.path().join("test.db");
        let db = Db::connect(&path).await.expect("connect to fresh DB");
        (dir, db)
    }

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
        let (_dir, _db) = open_temp_db().await;
    }

    // ── Schema presence ───────────────────────────────────────────────────────

    /// Assert that every v0.1 config table was created by the migration.
    #[tokio::test]
    async fn schema_all_tables_exist() {
        let (_dir, db) = open_temp_db().await;

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
        let (_dir, db) = open_temp_db().await;

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
        let (_dir, db) = open_temp_db().await;

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
        let (_dir, db) = open_temp_db().await;

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
    #[tokio::test]
    async fn settings_check_id_rejects_second_row() {
        let (_dir, db) = open_temp_db().await;

        // Insert the first (valid) row.
        sqlx::query(
            "INSERT INTO settings \
             (id, cache_min_ttl, cache_max_ttl, cache_negative_ttl_cap, cache_capacity, \
              blocking_mode, blocklist_refresh_interval) \
             VALUES (1, 60, 86400, 300, 10000, 'nxdomain', 3600)",
        )
        .execute(db.pool())
        .await
        .expect("first settings row must insert");

        // A second attempt with id = 1 must fail (PRIMARY KEY violation).
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
        let (_dir, db) = open_temp_db().await;

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
        let (_dir, db) = open_temp_db().await;

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
        let (_dir, db) = open_temp_db().await;

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
        let (_dir, db) = open_temp_db().await;

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
        let (_dir, db) = open_temp_db().await;

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
        let (_dir, db) = open_temp_db().await;
        let mode: String = sqlx::query_scalar("PRAGMA journal_mode;")
            .fetch_one(db.pool())
            .await
            .expect("query journal_mode");
        assert_eq!(mode, "wal", "journal_mode must be WAL");
    }

    #[tokio::test]
    async fn foreign_keys_are_enforced() {
        let (_dir, db) = open_temp_db().await;
        let fk: i64 = sqlx::query_scalar("PRAGMA foreign_keys;")
            .fetch_one(db.pool())
            .await
            .expect("query foreign_keys");
        assert_eq!(fk, 1, "foreign_keys must be enabled");
    }

    #[tokio::test]
    async fn trivial_query_round_trips() {
        let (_dir, db) = open_temp_db().await;
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
}
