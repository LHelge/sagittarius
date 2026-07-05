//! Repository for the `api_keys` table — bearer keys for the config-sync API.
//!
//! A **secondary/fallback** instance authenticates to the **primary**'s
//! read-only config-sync API (SPEC §13) with a key minted in the primary admin
//! UI.  Modelled on [`sessions`](super::sessions): the wire key is
//! `{id}.{token}`, but only the **SHA-256 hash of the token** is stored, so a
//! database read alone cannot mint a usable key.  Key generation, hashing, and
//! parsing live in [`crate::web::auth`]; this module is storage only.
//!
//! Rows are kept after revocation (`revoked_at` set) for audit; the auth path
//! filters on `revoked_at IS NULL`.

use std::future::Future;

use sqlx::SqlitePool;

use super::Error;

// ── Result alias ────────────────────────────────────────────────────────────

pub type Result<T> = std::result::Result<T, Error>;

// ── Records ─────────────────────────────────────────────────────────────────

/// A row from `api_keys` as shown in the admin list (never exposes the hash).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiKeyRecord {
    /// Opaque random id (the key's public prefix).
    pub id: String,
    /// Operator-facing label, e.g. `"fallback-nas"`.
    pub label: String,
    /// Unix epoch seconds when the key was created.
    pub created_at: i64,
    /// Unix epoch seconds of the last successful authentication, or `None`.
    pub last_used_at: Option<i64>,
    /// Unix epoch seconds when the key was revoked, or `None` while active.
    pub revoked_at: Option<i64>,
}

/// The subset of an **active** key the auth path needs to verify a bearer token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveApiKey {
    /// Hex SHA-256 of the bearer token; compared constant-time against the
    /// presented token's hash.
    pub token_hash: String,
    /// Last-used timestamp, so the extractor can throttle `touch_last_used`.
    pub last_used_at: Option<i64>,
}

/// Fields needed to insert a freshly minted key.
#[derive(Debug, Clone)]
pub struct NewApiKey {
    /// Opaque random id.
    pub id: String,
    /// Hex SHA-256 of the bearer token.
    pub token_hash: String,
    /// Operator-facing label.
    pub label: String,
}

// ── ApiKeyRepository trait ──────────────────────────────────────────────────

/// Repository for reading and writing API keys.
///
/// See [`UpstreamRepository`](super::upstreams::UpstreamRepository) for why the
/// methods return `impl Future` rather than `async fn`.
pub trait ApiKeyRepository {
    /// Insert a newly minted key.  `created_at` is set by the DB default.
    fn insert(&self, key: &NewApiKey) -> impl Future<Output = Result<()>>;

    /// Look up an **active** (non-revoked) key by its opaque id.
    fn find_active(&self, id: &str) -> impl Future<Output = Result<Option<ActiveApiKey>>>;

    /// List every key (active and revoked), newest first, without the hash.
    fn list(&self) -> impl Future<Output = Result<Vec<ApiKeyRecord>>>;

    /// Revoke a key by id (no-op if already revoked or absent).
    fn revoke(&self, id: &str, now: i64) -> impl Future<Output = Result<()>>;

    /// Record `now` as the key's last-used time (throttled by the caller).
    fn touch_last_used(&self, id: &str, now: i64) -> impl Future<Output = Result<()>>;
}

// ── SqliteApiKeyRepo ────────────────────────────────────────────────────────

/// SQLite-backed [`ApiKeyRepository`].
pub struct SqliteApiKeyRepo {
    pool: SqlitePool,
}

impl SqliteApiKeyRepo {
    /// Construct a new repository from an open [`crate::storage::Db`] pool.
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

impl ApiKeyRepository for SqliteApiKeyRepo {
    async fn insert(&self, key: &NewApiKey) -> Result<()> {
        sqlx::query!(
            r#"INSERT INTO api_keys (id, token_hash, label) VALUES (?, ?, ?)"#,
            key.id,
            key.token_hash,
            key.label,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn find_active(&self, id: &str) -> Result<Option<ActiveApiKey>> {
        let row = sqlx::query_as!(
            ActiveApiKey,
            r#"SELECT
                token_hash   AS "token_hash!",
                last_used_at AS "last_used_at"
            FROM api_keys
            WHERE id = ? AND revoked_at IS NULL"#,
            id,
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    async fn list(&self) -> Result<Vec<ApiKeyRecord>> {
        let rows = sqlx::query_as!(
            ApiKeyRecord,
            r#"SELECT
                id           AS "id!",
                label        AS "label!",
                created_at   AS "created_at!",
                last_used_at AS "last_used_at",
                revoked_at   AS "revoked_at"
            FROM api_keys
            ORDER BY created_at DESC, id"#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    async fn revoke(&self, id: &str, now: i64) -> Result<()> {
        sqlx::query!(
            "UPDATE api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
            now,
            id,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn touch_last_used(&self, id: &str, now: i64) -> Result<()> {
        sqlx::query!("UPDATE api_keys SET last_used_at = ? WHERE id = ?", now, id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
impl SqliteApiKeyRepo {
    /// Borrow the pool for direct SQL in tests.
    fn pool_for_test(&self) -> &SqlitePool {
        &self.pool
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn open_repo() -> (TempDir, SqliteApiKeyRepo) {
        let (dir, db) = crate::test_support::temp_db().await;
        (dir, SqliteApiKeyRepo::new(db.pool().clone()))
    }

    fn new_key(id: &str, label: &str) -> NewApiKey {
        NewApiKey {
            id: id.to_owned(),
            token_hash: format!("hash-of-{id}"),
            label: label.to_owned(),
        }
    }

    #[tokio::test]
    async fn insert_then_find_active_round_trips() {
        let (_dir, repo) = open_repo().await;
        repo.insert(&new_key("k1", "fallback-nas"))
            .await
            .expect("insert");

        let found = repo
            .find_active("k1")
            .await
            .expect("find")
            .expect("present");
        assert_eq!(found.token_hash, "hash-of-k1");
        assert_eq!(found.last_used_at, None);
    }

    #[tokio::test]
    async fn find_active_missing_returns_none() {
        let (_dir, repo) = open_repo().await;
        assert!(repo.find_active("nope").await.expect("find").is_none());
    }

    #[tokio::test]
    async fn revoke_hides_key_from_auth_but_keeps_it_listed() {
        let (_dir, repo) = open_repo().await;
        repo.insert(&new_key("k1", "one")).await.expect("insert");

        repo.revoke("k1", 1_700_000_000).await.expect("revoke");

        // No longer authenticatable …
        assert!(
            repo.find_active("k1").await.expect("find").is_none(),
            "revoked key must not authenticate"
        );
        // … but still present in the audit list with revoked_at set.
        let list = repo.list().await.expect("list");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, "k1");
        assert_eq!(list[0].revoked_at, Some(1_700_000_000));
    }

    #[tokio::test]
    async fn revoke_is_idempotent_and_preserves_first_timestamp() {
        let (_dir, repo) = open_repo().await;
        repo.insert(&new_key("k1", "one")).await.expect("insert");
        repo.revoke("k1", 100).await.expect("first revoke");
        // A second revoke must not overwrite the original revoked_at.
        repo.revoke("k1", 200).await.expect("second revoke");
        let list = repo.list().await.expect("list");
        assert_eq!(list[0].revoked_at, Some(100));
    }

    #[tokio::test]
    async fn touch_last_used_updates_timestamp() {
        let (_dir, repo) = open_repo().await;
        repo.insert(&new_key("k1", "one")).await.expect("insert");
        repo.touch_last_used("k1", 4242).await.expect("touch");
        let found = repo
            .find_active("k1")
            .await
            .expect("find")
            .expect("present");
        assert_eq!(found.last_used_at, Some(4242));
    }

    #[tokio::test]
    async fn list_orders_newest_first() {
        let (_dir, repo) = open_repo().await;
        // Insert with explicit created_at so ordering is deterministic.
        for (id, ts) in [("old", 1_000), ("new", 2_000)] {
            sqlx::query(
                "INSERT INTO api_keys (id, token_hash, label, created_at) VALUES (?, ?, ?, ?)",
            )
            .bind(id)
            .bind(format!("h-{id}"))
            .bind(id)
            .bind(ts)
            .execute(repo.pool_for_test())
            .await
            .expect("seed");
        }
        let list = repo.list().await.expect("list");
        assert_eq!(list[0].id, "new", "newest key must sort first");
        assert_eq!(list[1].id, "old");
    }
}
