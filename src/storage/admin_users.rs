//! Repository for the `admin_users` table — web-admin credentials.
//!
//! Provides the [`AdminUserRepository`] trait and its [`SqliteAdminUserRepo`]
//! implementation.  Password **hashing** is the web layer's concern
//! ([`crate::web::auth`], Argon2id); this module only persists the already
//! hashed PHC string alongside the username and role.
//!
//! These queries are added in Epic E8 — after the E3 offline gate — so
//! `cargo sqlx prepare` must be re-run and the updated `.sqlx/` committed.

use sqlx::SqlitePool;

use super::Error;

// ── Result alias ────────────────────────────────────────────────────────────

pub type Result<T> = std::result::Result<T, Error>;

// ── AdminUser ─────────────────────────────────────────────────────────────────

/// A single row from the `admin_users` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminUser {
    /// Row primary key.
    pub id: i64,
    /// Unique login name.
    pub username: String,
    /// Argon2id PHC hash string of the password.
    pub password_hash: String,
    /// Role label (`"admin"` in v0.1).
    pub role: String,
    /// Unix epoch seconds of creation.
    pub created_at: i64,
    /// Unix epoch seconds of the last update.
    pub updated_at: i64,
}

// ── AdminUserRepository trait ─────────────────────────────────────────────────

/// Repository for reading and writing admin users.
///
/// # Note on `async_fn_in_trait`
///
/// We use `async fn` directly in the trait.  All implementations live in this
/// crate, so we control the full `impl` surface and have no need for
/// `Send`-bound flexibility across dynamic dispatch.
#[allow(async_fn_in_trait)]
pub trait AdminUserRepository {
    /// Count the admin users.  `0` means the first-run wizard should run
    /// (SPEC §10).
    async fn count(&self) -> Result<i64>;

    /// Look up a user by exact username, or `None` if no such user exists.
    async fn find_by_username(&self, username: &str) -> Result<Option<AdminUser>>;

    /// Create a new admin user with the given pre-hashed (Argon2id PHC)
    /// password and return the inserted row.
    ///
    /// # Errors
    ///
    /// The `username` column is UNIQUE; inserting a duplicate surfaces as
    /// [`Error::Sqlx`].
    async fn create(&self, username: &str, password_hash: &str) -> Result<AdminUser>;
}

// ── SqliteAdminUserRepo ─────────────────────────────────────────────────────

/// SQLite-backed [`AdminUserRepository`].
pub struct SqliteAdminUserRepo {
    pool: SqlitePool,
}

impl SqliteAdminUserRepo {
    /// Construct a new repository from an open [`crate::storage::Db`].
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

impl AdminUserRepository for SqliteAdminUserRepo {
    async fn count(&self) -> Result<i64> {
        let count = sqlx::query_scalar!(r#"SELECT COUNT(*) AS "count!" FROM admin_users"#)
            .fetch_one(&self.pool)
            .await?;
        Ok(count)
    }

    async fn find_by_username(&self, username: &str) -> Result<Option<AdminUser>> {
        let row = sqlx::query_as!(
            AdminUser,
            r#"SELECT
                id            AS "id!",
                username,
                password_hash,
                role,
                created_at    AS "created_at!",
                updated_at    AS "updated_at!"
            FROM admin_users
            WHERE username = ?"#,
            username,
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    async fn create(&self, username: &str, password_hash: &str) -> Result<AdminUser> {
        let row = sqlx::query!(
            r#"INSERT INTO admin_users (username, password_hash)
            VALUES (?, ?)
            RETURNING
                id            AS "id!",
                created_at    AS "created_at!",
                updated_at    AS "updated_at!""#,
            username,
            password_hash,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(AdminUser {
            id: row.id,
            username: username.to_owned(),
            password_hash: password_hash.to_owned(),
            role: "admin".to_owned(),
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Db;
    use tempfile::TempDir;

    async fn open_repo() -> (TempDir, SqliteAdminUserRepo) {
        let dir = TempDir::new().expect("temp dir");
        let db = Db::connect(dir.path().join("test.db"))
            .await
            .expect("connect");
        (dir, SqliteAdminUserRepo::new(db.pool().clone()))
    }

    #[tokio::test]
    async fn fresh_db_has_no_admin_users() {
        let (_dir, repo) = open_repo().await;
        assert_eq!(repo.count().await.expect("count"), 0);
    }

    #[tokio::test]
    async fn create_then_find_round_trips() {
        let (_dir, repo) = open_repo().await;
        let created = repo
            .create("admin", "$argon2id$dummy")
            .await
            .expect("create");
        assert!(created.id > 0);
        assert_eq!(created.username, "admin");
        assert_eq!(created.role, "admin");
        assert!(created.created_at > 0);

        assert_eq!(repo.count().await.expect("count"), 1);

        let found = repo
            .find_by_username("admin")
            .await
            .expect("find")
            .expect("present");
        assert_eq!(found, created);
    }

    #[tokio::test]
    async fn find_unknown_returns_none() {
        let (_dir, repo) = open_repo().await;
        assert!(
            repo.find_by_username("nobody")
                .await
                .expect("find")
                .is_none()
        );
    }

    #[tokio::test]
    async fn duplicate_username_errors() {
        let (_dir, repo) = open_repo().await;
        repo.create("admin", "$h1").await.expect("first");
        let err = repo.create("admin", "$h2").await;
        assert!(
            matches!(err, Err(Error::Sqlx(_))),
            "duplicate username must surface as Sqlx error, got {err:?}"
        );
    }
}
