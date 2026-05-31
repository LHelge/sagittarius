//! Shared test-only helpers.
//!
//! Centralizes the throwaway-database setup otherwise repeated across the
//! module test suites. Test code reaches repositories through the [`Db`]
//! accessors (e.g. `db.upstreams()`), so this only needs to hand back an open,
//! migrated database.

use tempfile::TempDir;

use crate::storage::Db;

/// Open a fresh, migrated SQLite database in a throwaway temp directory.
///
/// Returns the [`TempDir`] guard — keep it alive for the duration of the test,
/// since dropping it deletes the database file — and the open [`Db`].
pub(crate) async fn temp_db() -> (TempDir, Db) {
    let dir = TempDir::new().expect("create temp dir");
    let db = Db::connect(dir.path().join("test.db"))
        .await
        .expect("connect to a fresh test database");
    (dir, db)
}
