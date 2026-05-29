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
    async fn connect_applies_empty_migrations() {
        // A fresh DB with no .sql migration files must still connect without error.
        let (_dir, _db) = open_temp_db().await;
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
