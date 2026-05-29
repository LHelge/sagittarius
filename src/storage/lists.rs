//! Repositories for the `blacklist` and `allowlist` tables.
//!
//! Provides the [`BlacklistRepository`] / [`AllowlistRepository`] traits and
//! their [`SqliteBlacklistRepo`] / [`SqliteAllowlistRepo`] implementations.
//!
//! # Domain normalization
//!
//! All domain inputs go through [`crate::codec::name::Name`] before touching
//! the database.  `Name::from_str` lowercases and appends a trailing dot, so
//! `"Ads.Example.COM"` and `"ads.example.com."` are stored identically and
//! compare equal when loaded via `load_all`.  Invalid domains (empty labels,
//! labels > 63 bytes, etc.) produce [`Error::InvalidDomain`].

use std::str::FromStr;

use sqlx::SqlitePool;

use crate::codec::name::Name;

use super::Error;

// ── Result alias ────────────────────────────────────────────────────────────

pub type Result<T> = std::result::Result<T, Error>;

// ── ListEntry ────────────────────────────────────────────────────────────────

/// A single row returned by [`BlacklistRepository::list`] /
/// [`AllowlistRepository::list`] — suitable for the admin UI.
#[derive(Debug, Clone, PartialEq)]
pub struct ListEntry {
    /// Row primary key.
    pub id: i64,
    /// Normalized domain (lowercase, trailing dot), e.g. `"ads.example.com."`.
    pub domain: String,
    /// Unix epoch seconds of when the domain was added.
    pub created_at: i64,
}

// ── Private row struct ────────────────────────────────────────────────────────

/// Private projection for `query_as!` — primitive SQLite types only.
///
/// `id` and `created_at` use the non-null override `AS "col!"` because
/// sqlx-SQLite infers NOT NULL INTEGER columns as `Option<i64>` in some query
/// shapes.
struct ListRow {
    id: i64,
    domain: String,
    created_at: i64,
}

impl From<ListRow> for ListEntry {
    fn from(row: ListRow) -> Self {
        Self {
            id: row.id,
            domain: row.domain,
            created_at: row.created_at,
        }
    }
}

// ── Helper: normalize a domain through Name ──────────────────────────────────

/// Parse `domain` through [`Name`] and return the normalized string
/// (e.g. `"ads.example.com."`), or an [`Error::InvalidDomain`] if the input
/// is not a valid DNS name.
fn normalize(domain: &str) -> Result<String> {
    Name::from_str(domain)
        .map(|n| n.as_str().to_owned())
        .map_err(|e| Error::InvalidDomain(format!("{domain:?}: {e}")))
}

// ── BlacklistRepository trait ─────────────────────────────────────────────────

/// Repository for reading and writing admin-blacklisted domains.
///
/// # Note on `async_fn_in_trait`
///
/// We use `async fn` directly in the trait.  All implementations live in this
/// crate, so we control the full `impl` surface and have no need for
/// `Send`-bound flexibility across dynamic dispatch.  The lint is suppressed
/// here rather than desugaring to `impl Future`.
#[allow(async_fn_in_trait)]
pub trait BlacklistRepository {
    /// Add `domain` to the blacklist.
    ///
    /// The domain is first normalized through [`Name`] (lowercase + trailing
    /// dot).  If the normalized domain already exists in the table the call
    /// succeeds silently (idempotent — `INSERT … ON CONFLICT DO NOTHING`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidDomain`] if `domain` cannot be parsed as a
    /// valid DNS name.  Database errors surface as [`Error::Sqlx`].
    async fn add(&self, domain: &str) -> Result<()>;

    /// Remove `domain` from the blacklist.
    ///
    /// The domain is normalized before the delete.  If the domain is not
    /// present the call succeeds silently (no-op).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidDomain`] if `domain` cannot be parsed.
    async fn remove(&self, domain: &str) -> Result<()>;

    /// List all blacklisted domains ordered by domain name.
    ///
    /// Returns entries with `id`, normalized `domain`, and `created_at`
    /// (unix epoch seconds) — intended for the admin UI.
    async fn list(&self) -> Result<Vec<ListEntry>>;

    /// Load all blacklisted domain names as parsed [`Name`] values.
    ///
    /// This is the bulk-read entry point used by the resolver (E4) to
    /// hydrate its in-memory `HashSet<Name>`.
    async fn load_all(&self) -> Result<Vec<Name>>;
}

// ── AllowlistRepository trait ─────────────────────────────────────────────────

/// Repository for reading and writing admin-allowlisted domains.
///
/// Identical contract to [`BlacklistRepository`] but operates on the separate
/// `allowlist` table.
#[allow(async_fn_in_trait)]
pub trait AllowlistRepository {
    /// Add `domain` to the allowlist (idempotent).
    async fn add(&self, domain: &str) -> Result<()>;

    /// Remove `domain` from the allowlist (no-op if absent).
    async fn remove(&self, domain: &str) -> Result<()>;

    /// List all allowlisted domains ordered by domain name.
    async fn list(&self) -> Result<Vec<ListEntry>>;

    /// Load all allowlisted domain names as parsed [`Name`] values.
    async fn load_all(&self) -> Result<Vec<Name>>;
}

// ── SqliteBlacklistRepo ───────────────────────────────────────────────────────

/// SQLite-backed [`BlacklistRepository`].
pub struct SqliteBlacklistRepo {
    pool: SqlitePool,
}

impl SqliteBlacklistRepo {
    /// Construct a new repository from an open [`crate::storage::Db`].
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

impl BlacklistRepository for SqliteBlacklistRepo {
    async fn add(&self, domain: &str) -> Result<()> {
        let normalized = normalize(domain)?;
        sqlx::query!(
            "INSERT INTO blacklist (domain) VALUES (?) ON CONFLICT(domain) DO NOTHING",
            normalized,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn remove(&self, domain: &str) -> Result<()> {
        let normalized = normalize(domain)?;
        sqlx::query!("DELETE FROM blacklist WHERE domain = ?", normalized)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn list(&self) -> Result<Vec<ListEntry>> {
        let rows = sqlx::query_as!(
            ListRow,
            r#"SELECT
                id          AS "id!",
                domain,
                created_at  AS "created_at!"
            FROM blacklist
            ORDER BY domain"#
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(ListEntry::from).collect())
    }

    async fn load_all(&self) -> Result<Vec<Name>> {
        let rows = sqlx::query_as!(
            ListRow,
            r#"SELECT
                id          AS "id!",
                domain,
                created_at  AS "created_at!"
            FROM blacklist"#
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                Name::from_str(&row.domain)
                    .map_err(|e| Error::Decode(format!("stored domain {:?}: {e}", row.domain)))
            })
            .collect()
    }
}

// ── SqliteAllowlistRepo ───────────────────────────────────────────────────────

/// SQLite-backed [`AllowlistRepository`].
pub struct SqliteAllowlistRepo {
    pool: SqlitePool,
}

impl SqliteAllowlistRepo {
    /// Construct a new repository from an open [`crate::storage::Db`].
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

impl AllowlistRepository for SqliteAllowlistRepo {
    async fn add(&self, domain: &str) -> Result<()> {
        let normalized = normalize(domain)?;
        sqlx::query!(
            "INSERT INTO allowlist (domain) VALUES (?) ON CONFLICT(domain) DO NOTHING",
            normalized,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn remove(&self, domain: &str) -> Result<()> {
        let normalized = normalize(domain)?;
        sqlx::query!("DELETE FROM allowlist WHERE domain = ?", normalized)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn list(&self) -> Result<Vec<ListEntry>> {
        let rows = sqlx::query_as!(
            ListRow,
            r#"SELECT
                id          AS "id!",
                domain,
                created_at  AS "created_at!"
            FROM allowlist
            ORDER BY domain"#
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(ListEntry::from).collect())
    }

    async fn load_all(&self) -> Result<Vec<Name>> {
        let rows = sqlx::query_as!(
            ListRow,
            r#"SELECT
                id          AS "id!",
                domain,
                created_at  AS "created_at!"
            FROM allowlist"#
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                Name::from_str(&row.domain)
                    .map_err(|e| Error::Decode(format!("stored domain {:?}: {e}", row.domain)))
            })
            .collect()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::storage::Db;
    use tempfile::TempDir;

    // ── Helpers ───────────────────────────────────────────────────────────────

    async fn open_blacklist_repo() -> (TempDir, SqliteBlacklistRepo) {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("test.db");
        let db = Db::connect(&path).await.expect("connect");
        let repo = SqliteBlacklistRepo::new(db.pool().clone());
        (dir, repo)
    }

    async fn open_allowlist_repo() -> (TempDir, SqliteAllowlistRepo) {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("test.db");
        let db = Db::connect(&path).await.expect("connect");
        let repo = SqliteAllowlistRepo::new(db.pool().clone());
        (dir, repo)
    }

    // ── normalize helper ──────────────────────────────────────────────────────

    #[test]
    fn normalize_lowercases_and_adds_dot() {
        let result = normalize("Ads.Example.COM").unwrap();
        assert_eq!(result, "ads.example.com.");
    }

    #[test]
    fn normalize_already_normalized_is_idempotent() {
        let result = normalize("ads.example.com.").unwrap();
        assert_eq!(result, "ads.example.com.");
    }

    #[test]
    fn normalize_invalid_domain_returns_error() {
        let err = normalize("foo..bar").unwrap_err();
        assert!(
            matches!(err, Error::InvalidDomain(_)),
            "expected InvalidDomain, got {err:?}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("foo..bar"),
            "error must mention the bad input: {msg}"
        );
    }

    // ── BlacklistRepository ───────────────────────────────────────────────────

    #[tokio::test]
    async fn blacklist_add_then_list_round_trips() {
        let (_dir, repo) = open_blacklist_repo().await;
        repo.add("ads.example.com").await.expect("add");
        let entries = repo.list().await.expect("list");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].domain, "ads.example.com.");
        assert!(entries[0].id > 0);
        assert!(entries[0].created_at > 0);
    }

    #[tokio::test]
    async fn blacklist_add_then_load_all_round_trips() {
        let (_dir, repo) = open_blacklist_repo().await;
        repo.add("tracker.example.org").await.expect("add");
        let names = repo.load_all().await.expect("load_all");
        assert_eq!(names.len(), 1);
        assert_eq!(names[0].as_str(), "tracker.example.org.");
    }

    #[tokio::test]
    async fn blacklist_mixed_case_input_normalizes() {
        let (_dir, repo) = open_blacklist_repo().await;
        repo.add("Ads.Example.COM").await.expect("add mixed-case");

        let names = repo.load_all().await.expect("load_all");
        assert_eq!(names.len(), 1);
        // The stored Name must equal the normalized form regardless of casing.
        let expected: Name = "ads.example.com".parse().unwrap();
        assert_eq!(
            names[0], expected,
            "stored name must normalize to ads.example.com."
        );

        // A lookup with different casing must match.
        let lookup: Name = "ADS.EXAMPLE.COM".parse().unwrap();
        let set: HashSet<Name> = names.into_iter().collect();
        assert!(
            set.contains(&lookup),
            "case-insensitive HashSet lookup must find the stored name"
        );
    }

    #[tokio::test]
    async fn blacklist_duplicate_add_is_noop() {
        let (_dir, repo) = open_blacklist_repo().await;
        repo.add("ads.example.com").await.expect("first add");
        // Second add must not error and must not create a duplicate.
        repo.add("ads.example.com")
            .await
            .expect("duplicate add must not error");
        let entries = repo.list().await.expect("list");
        assert_eq!(entries.len(), 1, "exactly one row after duplicate add");
    }

    #[tokio::test]
    async fn blacklist_duplicate_add_different_case_is_noop() {
        let (_dir, repo) = open_blacklist_repo().await;
        repo.add("ads.example.com").await.expect("first add");
        // Mixed-case duplicate normalizes to the same domain → idempotent.
        repo.add("ADS.EXAMPLE.COM")
            .await
            .expect("mixed-case duplicate add must not error");
        let entries = repo.list().await.expect("list");
        assert_eq!(entries.len(), 1, "one row after mixed-case duplicate add");
    }

    #[tokio::test]
    async fn blacklist_remove_deletes_entry() {
        let (_dir, repo) = open_blacklist_repo().await;
        repo.add("ads.example.com").await.expect("add");
        repo.remove("ads.example.com").await.expect("remove");
        let entries = repo.list().await.expect("list");
        assert!(entries.is_empty(), "entry must be gone after remove");
    }

    #[tokio::test]
    async fn blacklist_remove_nonexistent_is_noop() {
        let (_dir, repo) = open_blacklist_repo().await;
        // Removing something that was never added must not error.
        repo.remove("nothere.example.com")
            .await
            .expect("remove non-existent must not error");
    }

    #[tokio::test]
    async fn blacklist_list_ordered_by_domain() {
        let (_dir, repo) = open_blacklist_repo().await;
        repo.add("zzz.example.com").await.expect("add zzz");
        repo.add("aaa.example.com").await.expect("add aaa");
        repo.add("mmm.example.com").await.expect("add mmm");

        let entries = repo.list().await.expect("list");
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].domain, "aaa.example.com.");
        assert_eq!(entries[1].domain, "mmm.example.com.");
        assert_eq!(entries[2].domain, "zzz.example.com.");
    }

    #[tokio::test]
    async fn blacklist_invalid_domain_returns_error() {
        let (_dir, repo) = open_blacklist_repo().await;
        let err = repo.add("foo..bar").await.unwrap_err();
        assert!(
            matches!(err, Error::InvalidDomain(_)),
            "invalid domain must produce InvalidDomain error, got {err:?}"
        );
    }

    // ── AllowlistRepository ───────────────────────────────────────────────────

    #[tokio::test]
    async fn allowlist_add_then_list_round_trips() {
        let (_dir, repo) = open_allowlist_repo().await;
        repo.add("safe.example.com").await.expect("add");
        let entries = repo.list().await.expect("list");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].domain, "safe.example.com.");
    }

    #[tokio::test]
    async fn allowlist_add_then_load_all_round_trips() {
        let (_dir, repo) = open_allowlist_repo().await;
        repo.add("allow.example.net").await.expect("add");
        let names = repo.load_all().await.expect("load_all");
        assert_eq!(names.len(), 1);
        assert_eq!(names[0].as_str(), "allow.example.net.");
    }

    #[tokio::test]
    async fn allowlist_mixed_case_input_normalizes() {
        let (_dir, repo) = open_allowlist_repo().await;
        repo.add("Safe.EXAMPLE.Net").await.expect("add");
        let names = repo.load_all().await.expect("load_all");
        assert_eq!(names.len(), 1);
        let expected: Name = "safe.example.net".parse().unwrap();
        assert_eq!(names[0], expected);
    }

    #[tokio::test]
    async fn allowlist_duplicate_add_is_noop() {
        let (_dir, repo) = open_allowlist_repo().await;
        repo.add("safe.example.com").await.expect("first add");
        repo.add("safe.example.com")
            .await
            .expect("duplicate add must not error");
        let entries = repo.list().await.expect("list");
        assert_eq!(entries.len(), 1, "exactly one row after duplicate add");
    }

    #[tokio::test]
    async fn allowlist_remove_deletes_entry() {
        let (_dir, repo) = open_allowlist_repo().await;
        repo.add("safe.example.com").await.expect("add");
        repo.remove("safe.example.com").await.expect("remove");
        let entries = repo.list().await.expect("list");
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn allowlist_remove_nonexistent_is_noop() {
        let (_dir, repo) = open_allowlist_repo().await;
        repo.remove("nothere.example.com")
            .await
            .expect("remove non-existent must not error");
    }

    #[tokio::test]
    async fn allowlist_invalid_domain_returns_error() {
        let (_dir, repo) = open_allowlist_repo().await;
        let err = repo.add("bad..domain").await.unwrap_err();
        assert!(
            matches!(err, Error::InvalidDomain(_)),
            "invalid domain must produce InvalidDomain error, got {err:?}"
        );
    }

    // ── Isolation: blacklist and allowlist are independent ────────────────────

    #[tokio::test]
    async fn blacklist_and_allowlist_are_independent() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("test.db");
        let db = Db::connect(&path).await.expect("connect");

        let bl = SqliteBlacklistRepo::new(db.pool().clone());
        let al = SqliteAllowlistRepo::new(db.pool().clone());

        bl.add("domain.example.com")
            .await
            .expect("add to blacklist");
        al.add("domain.example.com")
            .await
            .expect("add to allowlist");

        // Both tables contain one entry.
        assert_eq!(bl.list().await.expect("bl list").len(), 1);
        assert_eq!(al.list().await.expect("al list").len(), 1);

        // Removing from one does not affect the other.
        bl.remove("domain.example.com")
            .await
            .expect("remove from blacklist");
        assert!(bl.list().await.expect("bl list after remove").is_empty());
        assert_eq!(
            al.list().await.expect("al list after bl remove").len(),
            1,
            "allowlist must be unaffected by blacklist removal"
        );
    }
}
