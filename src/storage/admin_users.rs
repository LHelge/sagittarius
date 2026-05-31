//! Repository for the `admin_users` table — web-admin credentials.
//!
//! Provides the [`AdminUserRepository`] trait and its [`SqliteAdminUserRepo`]
//! implementation.  Password **hashing** is the web layer's concern
//! ([`crate::web::auth`], Argon2id); this module only persists the already
//! hashed PHC string alongside the username and role.
//!
//! These queries are added in Epic E8 — after the E3 offline gate — so
//! `cargo sqlx prepare` must be re-run and the updated `.sqlx/` committed.

use std::{fmt, str::FromStr};

use sqlx::SqlitePool;

use super::Error;

// ── Result alias ────────────────────────────────────────────────────────────

pub type Result<T> = std::result::Result<T, Error>;

// ── Role ──────────────────────────────────────────────────────────────────────

/// The privilege level of an admin user.
///
/// Maps to/from the `role` TEXT column.  v0.1 only defines `admin`; new roles
/// are added as variants here (with a `#[strum(serialize)]` token) and to
/// [`Role::from_str`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, strum::IntoStaticStr)]
pub enum Role {
    /// Full administrative access (the only role in v0.1).
    #[default]
    #[strum(serialize = "admin")]
    Admin,
}

impl Role {
    /// Returns the canonical TEXT representation stored in the database.
    ///
    /// Driven by `#[strum(serialize)]` ([`strum::IntoStaticStr`]); the
    /// value-carrying [`FromStr`] below is the inverse.
    pub fn as_str(&self) -> &'static str {
        self.into()
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Role {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "admin" => Ok(Self::Admin),
            other => Err(Error::Decode(format!("unknown role value: {other:?}"))),
        }
    }
}

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
    /// The user's privilege level.
    pub role: Role,
    /// Unix epoch seconds of creation.
    pub created_at: i64,
    /// Unix epoch seconds of the last update.
    pub updated_at: i64,
}

// ── Private row struct ────────────────────────────────────────────────────────

/// Private projection returned by `query_as!` — all primitive SQLite types so
/// the macro can type-check the column names and types at compile time.  The
/// `role` TEXT column is parsed into [`Role`] by [`AdminUser::try_from`].
struct AdminUserRow {
    id: i64,
    username: String,
    password_hash: String,
    role: String,
    created_at: i64,
    updated_at: i64,
}

impl TryFrom<AdminUserRow> for AdminUser {
    type Error = Error;

    fn try_from(row: AdminUserRow) -> Result<Self> {
        Ok(AdminUser {
            id: row.id,
            username: row.username,
            password_hash: row.password_hash,
            role: row.role.parse()?,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
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

    /// Create the initial admin user only if the table is still empty.
    ///
    /// Returns `Ok(None)` if another setup request created an admin first.
    async fn create_initial(
        &self,
        username: &str,
        password_hash: &str,
    ) -> Result<Option<AdminUser>>;
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
            AdminUserRow,
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
        row.map(AdminUser::try_from).transpose()
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
            role: Role::Admin,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    async fn create_initial(
        &self,
        username: &str,
        password_hash: &str,
    ) -> Result<Option<AdminUser>> {
        let row = sqlx::query_as!(
            AdminUserRow,
            r#"INSERT INTO admin_users (username, password_hash, role)
            SELECT ?, ?, 'admin'
            WHERE NOT EXISTS (SELECT 1 FROM admin_users)
            RETURNING
                id            AS "id!",
                username,
                password_hash,
                role,
                created_at    AS "created_at!",
                updated_at    AS "updated_at!""#,
            username,
            password_hash,
        )
        .fetch_optional(&self.pool)
        .await?;

        row.map(AdminUser::try_from).transpose()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn open_repo() -> (TempDir, SqliteAdminUserRepo) {
        let (dir, db) = crate::test_support::temp_db().await;
        (dir, SqliteAdminUserRepo::new(db.pool().clone()))
    }

    #[test]
    fn role_round_trips_through_text() {
        assert_eq!(Role::Admin.as_str(), "admin");
        assert_eq!("admin".parse::<Role>().expect("parse"), Role::Admin);
        assert!("root".parse::<Role>().is_err());
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
        assert_eq!(created.role, Role::Admin);
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

    #[tokio::test]
    async fn create_initial_only_inserts_when_table_is_empty() {
        let (_dir, repo) = open_repo().await;

        let first = repo
            .create_initial("admin", "$h1")
            .await
            .expect("create initial")
            .expect("first setup should insert");
        let second = repo
            .create_initial("other", "$h2")
            .await
            .expect("second create initial");

        assert_eq!(first.username, "admin");
        assert!(second.is_none(), "second setup must not insert");
        assert_eq!(repo.count().await.expect("count"), 1);
        assert!(
            repo.find_by_username("other")
                .await
                .expect("find")
                .is_none()
        );
    }
}
