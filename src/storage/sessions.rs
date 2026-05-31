//! Repository for the `sessions` table — admin session storage.
//!
//! Sessions are deliberately lightweight and home-grown (SPEC §9: "no
//! third-party session framework").  A session row holds an **opaque random
//! id** (the primary key, carried in the cookie) and the **hash of the bearer
//! token** — never the raw token — so a database read alone cannot mint a
//! valid session.  Token generation, hashing, and cookie handling live in
//! [`crate::web::auth`]; this module is storage only.
//!
//! These queries are added in Epic E8 — after the E3 offline gate — so
//! `cargo sqlx prepare` must be re-run and the updated `.sqlx/` committed.

use sqlx::SqlitePool;

use super::Error;

// ── Result alias ────────────────────────────────────────────────────────────

pub type Result<T> = std::result::Result<T, Error>;

// ── SessionRecord ─────────────────────────────────────────────────────────────

/// A single row from the `sessions` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    /// Opaque random session identifier (also the cookie's id component).
    pub id: String,
    /// Hash (hex SHA-256) of the bearer token; never the raw token.
    pub token_hash: String,
    /// Owning admin user id.
    pub user_id: i64,
    /// Unix epoch seconds when the session was created (absolute-lifetime anchor).
    pub created_at: i64,
    /// Unix epoch seconds when the session goes idle-stale (rolling).
    pub expires_at: i64,
}

/// Fields needed to create a new session row.
#[derive(Debug, Clone)]
pub struct NewSession {
    /// Opaque random session id.
    pub id: String,
    /// Hex SHA-256 of the bearer token.
    pub token_hash: String,
    /// Owning admin user id.
    pub user_id: i64,
    /// Initial idle-expiry, unix epoch seconds.
    pub expires_at: i64,
}

// ── SessionRepository trait ─────────────────────────────────────────────────

/// Repository for reading and writing admin sessions.
#[allow(async_fn_in_trait)]
pub trait SessionRepository {
    /// Insert a new session row.  `created_at` is set to the current epoch by
    /// the database default.
    async fn insert(&self, session: &NewSession) -> Result<()>;

    /// Look up a session by its opaque id, or `None` if absent.
    async fn find(&self, id: &str) -> Result<Option<SessionRecord>>;

    /// Slide the idle-expiry of a session forward.
    async fn touch(&self, id: &str, expires_at: i64) -> Result<()>;

    /// Delete a single session (logout).
    async fn delete(&self, id: &str) -> Result<()>;

    /// Delete every session owned by a user (e.g. password change / lockout).
    async fn delete_for_user(&self, user_id: i64) -> Result<()>;

    /// Delete all sessions whose idle-expiry is at or before `now`.
    ///
    /// Returns the number of rows removed.  Housekeeping; callable on a timer.
    async fn delete_expired(&self, now: i64) -> Result<u64>;
}

// ── SqliteSessionRepo ───────────────────────────────────────────────────────

/// SQLite-backed [`SessionRepository`].
pub struct SqliteSessionRepo {
    pool: SqlitePool,
}

impl SqliteSessionRepo {
    /// Construct a new repository from an open [`crate::storage::Db`].
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

impl SessionRepository for SqliteSessionRepo {
    async fn insert(&self, session: &NewSession) -> Result<()> {
        sqlx::query!(
            r#"INSERT INTO sessions (id, token_hash, user_id, expires_at)
            VALUES (?, ?, ?, ?)"#,
            session.id,
            session.token_hash,
            session.user_id,
            session.expires_at,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn find(&self, id: &str) -> Result<Option<SessionRecord>> {
        let row = sqlx::query_as!(
            SessionRecord,
            r#"SELECT
                id          AS "id!",
                token_hash  AS "token_hash!",
                user_id     AS "user_id!",
                created_at  AS "created_at!",
                expires_at  AS "expires_at!"
            FROM sessions
            WHERE id = ?"#,
            id,
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    async fn touch(&self, id: &str, expires_at: i64) -> Result<()> {
        sqlx::query!(
            "UPDATE sessions SET expires_at = ? WHERE id = ?",
            expires_at,
            id,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn delete(&self, id: &str) -> Result<()> {
        sqlx::query!("DELETE FROM sessions WHERE id = ?", id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn delete_for_user(&self, user_id: i64) -> Result<()> {
        sqlx::query!("DELETE FROM sessions WHERE user_id = ?", user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn delete_expired(&self, now: i64) -> Result<u64> {
        let result = sqlx::query!("DELETE FROM sessions WHERE expires_at <= ?", now)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::admin_users::{AdminUserRepository, SqliteAdminUserRepo};
    use tempfile::TempDir;

    /// Open a DB and seed one admin user (sessions FK-reference admin_users).
    async fn open_repo() -> (TempDir, SqliteSessionRepo, i64) {
        let (dir, db) = crate::test_support::temp_db().await;
        let user = SqliteAdminUserRepo::new(db.pool().clone())
            .create("admin", "$argon2id$dummy")
            .await
            .expect("create user");
        (dir, SqliteSessionRepo::new(db.pool().clone()), user.id)
    }

    fn new_session(id: &str, user_id: i64, expires_at: i64) -> NewSession {
        NewSession {
            id: id.to_owned(),
            token_hash: format!("hash-of-{id}"),
            user_id,
            expires_at,
        }
    }

    #[tokio::test]
    async fn insert_then_find_round_trips() {
        let (_dir, repo, uid) = open_repo().await;
        repo.insert(&new_session("sess-a", uid, 2_000_000_000))
            .await
            .expect("insert");

        let found = repo.find("sess-a").await.expect("find").expect("present");
        assert_eq!(found.id, "sess-a");
        assert_eq!(found.token_hash, "hash-of-sess-a");
        assert_eq!(found.user_id, uid);
        assert_eq!(found.expires_at, 2_000_000_000);
        assert!(found.created_at > 0);
    }

    #[tokio::test]
    async fn find_missing_returns_none() {
        let (_dir, repo, _uid) = open_repo().await;
        assert!(repo.find("nope").await.expect("find").is_none());
    }

    #[tokio::test]
    async fn touch_slides_expiry() {
        let (_dir, repo, uid) = open_repo().await;
        repo.insert(&new_session("s", uid, 1000))
            .await
            .expect("ins");
        repo.touch("s", 5000).await.expect("touch");
        let found = repo.find("s").await.expect("find").expect("present");
        assert_eq!(found.expires_at, 5000);
    }

    #[tokio::test]
    async fn delete_removes_session() {
        let (_dir, repo, uid) = open_repo().await;
        repo.insert(&new_session("s", uid, 1000))
            .await
            .expect("ins");
        repo.delete("s").await.expect("delete");
        assert!(repo.find("s").await.expect("find").is_none());
    }

    #[tokio::test]
    async fn delete_for_user_removes_all() {
        let (_dir, repo, uid) = open_repo().await;
        repo.insert(&new_session("a", uid, 1000)).await.expect("a");
        repo.insert(&new_session("b", uid, 1000)).await.expect("b");
        repo.delete_for_user(uid).await.expect("delete_for_user");
        assert!(repo.find("a").await.expect("find").is_none());
        assert!(repo.find("b").await.expect("find").is_none());
    }

    #[tokio::test]
    async fn delete_expired_removes_only_stale() {
        let (_dir, repo, uid) = open_repo().await;
        repo.insert(&new_session("old", uid, 100))
            .await
            .expect("old");
        repo.insert(&new_session("new", uid, 10_000))
            .await
            .expect("new");
        let removed = repo.delete_expired(1000).await.expect("delete_expired");
        assert_eq!(removed, 1);
        assert!(repo.find("old").await.expect("find").is_none());
        assert!(repo.find("new").await.expect("find").is_some());
    }
}
