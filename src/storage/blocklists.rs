//! Repository for the `blocklists` and `blocklist_cache` tables.
//!
//! Provides the [`BlocklistRepository`] trait and its [`SqliteBlocklistRepo`]
//! implementation.  All DB interaction uses compile-time-checked `sqlx` macros
//! against the tables defined in migration `0001_schema.sql`.
//!
//! # Responsibilities
//!
//! This module handles *storage only*: persisting blocklist source definitions
//! and their offline-cached raw content.  Fetching, parsing, and aggregating
//! blocklist entries is handled in Epic E7.

use std::{fmt, str::FromStr};

use sqlx::SqlitePool;

use super::Error;

// ── Result alias ────────────────────────────────────────────────────────────

pub type Result<T> = std::result::Result<T, Error>;

// ── BlocklistFormat ───────────────────────────────────────────────────────────

/// The file format of a subscribed blocklist source.
///
/// Maps to/from the `format` TEXT column values `'hosts'` and `'domain-list'`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlocklistFormat {
    /// A `hosts`-style file (`0.0.0.0 ads.example.com` or `127.0.0.1 …`).
    Hosts,
    /// A plain-text domain list — one domain per line.
    DomainList,
}

impl BlocklistFormat {
    /// Returns the canonical TEXT representation stored in the database.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Hosts => "hosts",
            Self::DomainList => "domain-list",
        }
    }
}

impl fmt::Display for BlocklistFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for BlocklistFormat {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "hosts" => Ok(Self::Hosts),
            "domain-list" => Ok(Self::DomainList),
            other => Err(Error::Decode(format!(
                "unknown blocklist format value: {other:?}"
            ))),
        }
    }
}

// ── Blocklist ─────────────────────────────────────────────────────────────────

/// A blocklist source row.
#[derive(Debug, Clone, PartialEq)]
pub struct Blocklist {
    /// Row primary key.
    pub id: i64,
    /// URL of the blocklist.
    pub url: String,
    /// File format.
    pub format: BlocklistFormat,
    /// Whether this source is included in the active set.
    pub enabled: bool,
    /// Number of domain entries from the last successful fetch.
    pub entry_count: u64,
    /// Unix epoch seconds of the last successful fetch; `None` until first fetch.
    pub last_updated: Option<i64>,
    /// HTTP ETag for conditional requests; `None` until first fetch.
    pub etag: Option<String>,
    /// HTTP Last-Modified for conditional requests; `None` until first fetch.
    pub last_modified: Option<String>,
}

/// Data required to insert a new blocklist source (no `id` — assigned by the DB).
#[derive(Debug, Clone)]
pub struct NewBlocklist {
    /// URL of the blocklist.
    pub url: String,
    /// File format.
    pub format: BlocklistFormat,
    /// Whether this source is enabled.  Typically `true` on creation.
    pub enabled: bool,
}

// ── CachedContent ─────────────────────────────────────────────────────────────

/// The offline-cached raw content for a blocklist source.
///
/// Returned by [`BlocklistRepository::load_cache`].
#[derive(Debug, Clone, PartialEq)]
pub struct CachedContent {
    /// The raw fetched content (e.g. a hosts file or domain-list).
    pub content: Vec<u8>,
    /// Unix epoch seconds of when the content was last saved.
    pub fetched_at: i64,
}

// ── RefreshMetadata ───────────────────────────────────────────────────────────

/// Metadata persisted after a successful blocklist fetch (Epic E7).
///
/// Passed to [`BlocklistRepository::update_refresh_metadata`] to update the
/// source row without a full re-read.
#[derive(Debug, Clone, PartialEq)]
pub struct RefreshMetadata {
    /// Number of domain entries parsed from the fetched content.
    pub entry_count: u64,
    /// Unix epoch seconds of the successful fetch.
    pub last_updated: i64,
    /// HTTP ETag for use in the next conditional request, if provided.
    pub etag: Option<String>,
    /// HTTP Last-Modified for use in the next conditional request, if provided.
    pub last_modified: Option<String>,
}

// ── Private row structs ───────────────────────────────────────────────────────

/// Private projection for `query_as!` on the `blocklists` table.
///
/// The `SELECT`s use sqlx's non-null override (`AS "col!"`) on the NOT NULL
/// INTEGER columns `id`, `entry_count`, and `enabled`.  Without the override,
/// sqlx-SQLite conservatively types them as `Option<i64>`.  `enabled` is
/// decoded straight to `bool` via `AS "enabled!: bool"`.  `last_updated`,
/// `etag`, and `last_modified` are nullable and require no override.
struct BlocklistRow {
    id: i64,
    url: String,
    format: String,
    enabled: bool,
    entry_count: i64,
    last_updated: Option<i64>,
    etag: Option<String>,
    last_modified: Option<String>,
}

impl TryFrom<BlocklistRow> for Blocklist {
    type Error = Error;

    fn try_from(row: BlocklistRow) -> Result<Self> {
        let format = row.format.parse::<BlocklistFormat>()?;
        let entry_count = u64::try_from(row.entry_count).map_err(|_| {
            Error::Decode(format!(
                "column entry_count value {} is out of u64 range",
                row.entry_count
            ))
        })?;

        Ok(Blocklist {
            id: row.id,
            url: row.url,
            format,
            enabled: row.enabled,
            entry_count,
            last_updated: row.last_updated,
            etag: row.etag,
            last_modified: row.last_modified,
        })
    }
}

/// Convert a `Vec<BlocklistRow>` into a `Vec<Blocklist>`, propagating any
/// decode error.
fn rows_to_blocklists(rows: Vec<BlocklistRow>) -> Result<Vec<Blocklist>> {
    rows.into_iter().map(Blocklist::try_from).collect()
}

/// Private projection for `query_as!` on the `blocklist_cache` table.
struct CacheRow {
    content: Vec<u8>,
    fetched_at: i64,
}

// ── BlocklistRepository trait ─────────────────────────────────────────────────

/// Repository for reading and writing blocklist source definitions and their
/// offline-cached content.
///
/// # Note on `async_fn_in_trait`
///
/// We use `async fn` directly in the trait.  All implementations are in this
/// crate, so we control the full `impl` surface and have no need for
/// `Send`-bound flexibility across dynamic dispatch.  The lint is suppressed
/// here rather than desugaring to `impl Future`.
#[allow(async_fn_in_trait)]
pub trait BlocklistRepository {
    /// Insert a new blocklist source and return the inserted row (incl. new `id`).
    ///
    /// The `url` column has a UNIQUE constraint; inserting a duplicate URL
    /// surfaces an [`Error::Sqlx`] so the caller can report it as a user error.
    async fn insert(&self, blocklist: NewBlocklist) -> Result<Blocklist>;

    /// List all blocklist sources ordered by `id`.
    ///
    /// Used by the admin UI and as the startup read for E7/E4.
    async fn list(&self) -> Result<Vec<Blocklist>>;

    /// List only enabled blocklist sources ordered by `id`.
    ///
    /// Used by the E7 refresh loop.
    async fn list_enabled(&self) -> Result<Vec<Blocklist>>;

    /// Delete the blocklist source with the given `id`.
    ///
    /// The corresponding `blocklist_cache` row is removed automatically via the
    /// `ON DELETE CASCADE` foreign key constraint.
    async fn remove(&self, id: i64) -> Result<()>;

    /// Set the `enabled` flag on the blocklist source with the given `id`.
    async fn set_enabled(&self, id: i64, enabled: bool) -> Result<()>;

    /// Persist post-fetch metadata on the source row after a successful fetch.
    ///
    /// Updates `entry_count`, `last_updated`, `etag`, and `last_modified`.
    async fn update_refresh_metadata(&self, id: i64, meta: &RefreshMetadata) -> Result<()>;

    /// Upsert the cached raw content for a blocklist source.
    ///
    /// If no cache row exists for `blocklist_id` it is inserted; if one already
    /// exists it is replaced.  `fetched_at` is set to the current unix epoch
    /// via SQLite's `unixepoch()`.
    async fn save_cache(&self, blocklist_id: i64, content: &[u8]) -> Result<()>;

    /// Load the offline-cached content for a blocklist source, or `None` if no
    /// cache row exists yet.
    async fn load_cache(&self, blocklist_id: i64) -> Result<Option<CachedContent>>;
}

// ── SqliteBlocklistRepo ───────────────────────────────────────────────────────

/// SQLite-backed [`BlocklistRepository`].
pub struct SqliteBlocklistRepo {
    pool: SqlitePool,
}

impl SqliteBlocklistRepo {
    /// Construct a new repository from an open [`crate::storage::Db`].
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

impl BlocklistRepository for SqliteBlocklistRepo {
    async fn insert(&self, blocklist: NewBlocklist) -> Result<Blocklist> {
        let format = blocklist.format.as_str();
        let enabled = blocklist.enabled as i64;

        let id = sqlx::query!(
            r#"INSERT INTO blocklists (url, format, enabled)
            VALUES (?, ?, ?)
            RETURNING id"#,
            blocklist.url,
            format,
            enabled,
        )
        .fetch_one(&self.pool)
        .await?
        .id;

        Ok(Blocklist {
            id,
            url: blocklist.url,
            format: blocklist.format,
            enabled: blocklist.enabled,
            entry_count: 0,
            last_updated: None,
            etag: None,
            last_modified: None,
        })
    }

    async fn list(&self) -> Result<Vec<Blocklist>> {
        let rows = sqlx::query_as!(
            BlocklistRow,
            r#"SELECT
                id              AS "id!",
                url,
                format,
                enabled         AS "enabled!: bool",
                entry_count     AS "entry_count!",
                last_updated,
                etag,
                last_modified
            FROM blocklists
            ORDER BY id"#
        )
        .fetch_all(&self.pool)
        .await?;

        rows_to_blocklists(rows)
    }

    async fn list_enabled(&self) -> Result<Vec<Blocklist>> {
        let rows = sqlx::query_as!(
            BlocklistRow,
            r#"SELECT
                id              AS "id!",
                url,
                format,
                enabled         AS "enabled!: bool",
                entry_count     AS "entry_count!",
                last_updated,
                etag,
                last_modified
            FROM blocklists
            WHERE enabled = 1
            ORDER BY id"#
        )
        .fetch_all(&self.pool)
        .await?;

        rows_to_blocklists(rows)
    }

    async fn remove(&self, id: i64) -> Result<()> {
        sqlx::query!("DELETE FROM blocklists WHERE id = ?", id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn set_enabled(&self, id: i64, enabled: bool) -> Result<()> {
        let enabled_int = enabled as i64;
        sqlx::query!(
            "UPDATE blocklists SET enabled = ? WHERE id = ?",
            enabled_int,
            id,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn update_refresh_metadata(&self, id: i64, meta: &RefreshMetadata) -> Result<()> {
        let entry_count = meta.entry_count as i64;
        sqlx::query!(
            r#"UPDATE blocklists SET
                entry_count   = ?,
                last_updated  = ?,
                etag          = ?,
                last_modified = ?
            WHERE id = ?"#,
            entry_count,
            meta.last_updated,
            meta.etag,
            meta.last_modified,
            id,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn save_cache(&self, blocklist_id: i64, content: &[u8]) -> Result<()> {
        sqlx::query!(
            r#"INSERT INTO blocklist_cache (blocklist_id, content, fetched_at)
            VALUES (?, ?, unixepoch())
            ON CONFLICT(blocklist_id) DO UPDATE SET
                content    = excluded.content,
                fetched_at = excluded.fetched_at"#,
            blocklist_id,
            content,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn load_cache(&self, blocklist_id: i64) -> Result<Option<CachedContent>> {
        let row = sqlx::query_as!(
            CacheRow,
            r#"SELECT
                content,
                fetched_at  AS "fetched_at!"
            FROM blocklist_cache
            WHERE blocklist_id = ?"#,
            blocklist_id,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| CachedContent {
            content: r.content,
            fetched_at: r.fetched_at,
        }))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Db;
    use tempfile::TempDir;

    // ── Helper ────────────────────────────────────────────────────────────────

    async fn open_repo() -> (TempDir, SqliteBlocklistRepo) {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("test.db");
        let db = Db::connect(&path).await.expect("connect");
        let repo = SqliteBlocklistRepo::new(db.pool().clone());
        (dir, repo)
    }

    fn hosts_source(url: &str) -> NewBlocklist {
        NewBlocklist {
            url: url.to_owned(),
            format: BlocklistFormat::Hosts,
            enabled: true,
        }
    }

    fn domain_list_source(url: &str) -> NewBlocklist {
        NewBlocklist {
            url: url.to_owned(),
            format: BlocklistFormat::DomainList,
            enabled: false,
        }
    }

    // ── BlocklistFormat unit tests ────────────────────────────────────────────

    #[test]
    fn format_display() {
        assert_eq!(BlocklistFormat::Hosts.to_string(), "hosts");
        assert_eq!(BlocklistFormat::DomainList.to_string(), "domain-list");
    }

    #[test]
    fn format_as_str() {
        assert_eq!(BlocklistFormat::Hosts.as_str(), "hosts");
        assert_eq!(BlocklistFormat::DomainList.as_str(), "domain-list");
    }

    #[test]
    fn format_from_str_valid() {
        assert_eq!(
            "hosts".parse::<BlocklistFormat>().unwrap(),
            BlocklistFormat::Hosts
        );
        assert_eq!(
            "domain-list".parse::<BlocklistFormat>().unwrap(),
            BlocklistFormat::DomainList
        );
    }

    #[test]
    fn format_from_str_invalid() {
        let err = "adblock".parse::<BlocklistFormat>();
        assert!(err.is_err(), "invalid format must fail");
        let msg = err.unwrap_err().to_string();
        assert!(
            msg.contains("adblock"),
            "error must mention the bad value: {msg}"
        );
    }

    #[test]
    fn format_domain_list_round_trips_hyphen() {
        // 'domain-list' contains a hyphen — ensure it survives the round-trip.
        let s = BlocklistFormat::DomainList.to_string();
        let parsed: BlocklistFormat = s.parse().expect("parse domain-list");
        assert_eq!(parsed, BlocklistFormat::DomainList);
    }

    // ── Fresh DB has no blocklists ────────────────────────────────────────────

    #[tokio::test]
    async fn fresh_db_has_no_blocklists() {
        let (_dir, repo) = open_repo().await;
        let all = repo.list().await.expect("list");
        assert!(all.is_empty(), "fresh DB must have no blocklist rows");
    }

    // ── insert / list / list_enabled round-trips ──────────────────────────────

    #[tokio::test]
    async fn insert_then_list_round_trips() {
        let (_dir, repo) = open_repo().await;

        let inserted = repo
            .insert(hosts_source("https://hosts.example.com/hosts.txt"))
            .await
            .expect("insert");

        assert!(inserted.id > 0, "inserted id must be positive");
        assert_eq!(inserted.url, "https://hosts.example.com/hosts.txt");
        assert_eq!(inserted.format, BlocklistFormat::Hosts);
        assert!(inserted.enabled);
        assert_eq!(inserted.entry_count, 0);
        assert!(inserted.last_updated.is_none());
        assert!(inserted.etag.is_none());
        assert!(inserted.last_modified.is_none());

        let all = repo.list().await.expect("list");
        assert_eq!(all.len(), 1);
        assert_eq!(all[0], inserted);
    }

    #[tokio::test]
    async fn list_ordered_by_id() {
        let (_dir, repo) = open_repo().await;

        let a = repo
            .insert(hosts_source("https://list-a.example.com/hosts"))
            .await
            .expect("insert a");
        let b = repo
            .insert(domain_list_source("https://list-b.example.com/domains"))
            .await
            .expect("insert b");

        let all = repo.list().await.expect("list");
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].id, a.id, "first row must have smaller id");
        assert_eq!(all[1].id, b.id, "second row must have larger id");
    }

    #[tokio::test]
    async fn list_enabled_returns_only_enabled() {
        let (_dir, repo) = open_repo().await;

        // Insert one enabled (hosts) and one disabled (domain-list).
        let enabled_src = repo
            .insert(hosts_source("https://enabled.example.com/hosts"))
            .await
            .expect("insert enabled");
        let _disabled_src = repo
            .insert(domain_list_source("https://disabled.example.com/domains"))
            .await
            .expect("insert disabled");

        let all = repo.list().await.expect("list");
        assert_eq!(all.len(), 2, "list() must return both sources");

        let enabled = repo.list_enabled().await.expect("list_enabled");
        assert_eq!(enabled.len(), 1, "list_enabled() must return only 1");
        assert_eq!(enabled[0].id, enabled_src.id);
        assert!(enabled[0].enabled);
    }

    // ── Duplicate URL surfaces error ──────────────────────────────────────────

    #[tokio::test]
    async fn duplicate_url_insert_surfaces_error() {
        let (_dir, repo) = open_repo().await;

        repo.insert(hosts_source("https://dup.example.com/hosts"))
            .await
            .expect("first insert");

        let err = repo
            .insert(hosts_source("https://dup.example.com/hosts"))
            .await;

        assert!(err.is_err(), "duplicate URL insert must fail");
        assert!(
            matches!(err.unwrap_err(), Error::Sqlx(_)),
            "duplicate URL must surface as Error::Sqlx"
        );
    }

    // ── set_enabled ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn set_enabled_flips_flag() {
        let (_dir, repo) = open_repo().await;

        let src = repo
            .insert(hosts_source("https://flip.example.com/hosts"))
            .await
            .expect("insert");
        assert!(src.enabled);

        // Disable.
        repo.set_enabled(src.id, false)
            .await
            .expect("set_enabled false");
        let after_disable = repo.list().await.expect("list");
        assert!(!after_disable[0].enabled, "must be disabled");

        // Re-enable.
        repo.set_enabled(src.id, true)
            .await
            .expect("set_enabled true");
        let after_enable = repo.list().await.expect("list");
        assert!(after_enable[0].enabled, "must be re-enabled");
    }

    // ── update_refresh_metadata ───────────────────────────────────────────────

    #[tokio::test]
    async fn update_refresh_metadata_persists_and_re_reads() {
        let (_dir, repo) = open_repo().await;

        let src = repo
            .insert(hosts_source("https://meta.example.com/hosts"))
            .await
            .expect("insert");

        let meta = RefreshMetadata {
            entry_count: 42_000,
            last_updated: 1_700_000_000,
            etag: Some(r#""abc123""#.to_owned()),
            last_modified: Some("Thu, 01 Jan 2026 00:00:00 GMT".to_owned()),
        };

        repo.update_refresh_metadata(src.id, &meta)
            .await
            .expect("update_refresh_metadata");

        let all = repo.list().await.expect("list after metadata update");
        assert_eq!(all.len(), 1);
        let row = &all[0];
        assert_eq!(row.entry_count, 42_000);
        assert_eq!(row.last_updated, Some(1_700_000_000));
        assert_eq!(row.etag.as_deref(), Some(r#""abc123""#));
        assert_eq!(
            row.last_modified.as_deref(),
            Some("Thu, 01 Jan 2026 00:00:00 GMT")
        );
    }

    #[tokio::test]
    async fn update_refresh_metadata_with_none_etag_and_last_modified() {
        let (_dir, repo) = open_repo().await;

        let src = repo
            .insert(hosts_source("https://noetag.example.com/hosts"))
            .await
            .expect("insert");

        let meta = RefreshMetadata {
            entry_count: 100,
            last_updated: 1_700_000_001,
            etag: None,
            last_modified: None,
        };

        repo.update_refresh_metadata(src.id, &meta)
            .await
            .expect("update_refresh_metadata with None values");

        let all = repo.list().await.expect("list");
        let row = &all[0];
        assert_eq!(row.entry_count, 100);
        assert_eq!(row.last_updated, Some(1_700_000_001));
        assert!(row.etag.is_none(), "etag must remain None");
        assert!(
            row.last_modified.is_none(),
            "last_modified must remain None"
        );
    }

    // ── save_cache / load_cache ───────────────────────────────────────────────

    #[tokio::test]
    async fn save_then_load_cache_round_trips_content() {
        let (_dir, repo) = open_repo().await;

        let src = repo
            .insert(hosts_source("https://cache.example.com/hosts"))
            .await
            .expect("insert");

        let content = b"0.0.0.0 ads.example.com\n0.0.0.0 tracker.example.org\n";
        repo.save_cache(src.id, content).await.expect("save_cache");

        let cached = repo
            .load_cache(src.id)
            .await
            .expect("load_cache")
            .expect("cache must be Some after save");

        assert_eq!(cached.content, content.as_slice());
        assert!(cached.fetched_at > 0, "fetched_at must be a positive epoch");
    }

    #[tokio::test]
    async fn save_cache_again_updates_not_duplicates() {
        let (_dir, repo) = open_repo().await;

        let src = repo
            .insert(hosts_source("https://upsert.example.com/hosts"))
            .await
            .expect("insert");

        let first_content = b"0.0.0.0 first.example.com\n";
        repo.save_cache(src.id, first_content)
            .await
            .expect("first save_cache");

        let second_content = b"0.0.0.0 second.example.com\n0.0.0.0 third.example.com\n";
        repo.save_cache(src.id, second_content)
            .await
            .expect("second save_cache");

        let cached = repo
            .load_cache(src.id)
            .await
            .expect("load_cache")
            .expect("cache must be Some");

        // Content must reflect the second save, not the first.
        assert_eq!(
            cached.content,
            second_content.as_slice(),
            "second save must replace first"
        );

        // Verify only one cache row exists (no duplicate).
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM blocklist_cache WHERE blocklist_id = ?")
                .bind(src.id)
                .fetch_one(&repo.pool)
                .await
                .expect("count cache rows");
        assert_eq!(count, 1, "upsert must not create duplicate cache rows");
    }

    #[tokio::test]
    async fn load_cache_returns_none_when_no_cache() {
        let (_dir, repo) = open_repo().await;

        let src = repo
            .insert(hosts_source("https://nocache.example.com/hosts"))
            .await
            .expect("insert");

        let cached = repo.load_cache(src.id).await.expect("load_cache");
        assert!(cached.is_none(), "load_cache must return None when no row");
    }

    // ── remove / FK cascade ───────────────────────────────────────────────────

    #[tokio::test]
    async fn remove_deletes_source_and_cascades_to_cache() {
        let (_dir, repo) = open_repo().await;

        let src = repo
            .insert(hosts_source("https://cascade.example.com/hosts"))
            .await
            .expect("insert");

        // Save a cache row so we can verify cascade.
        repo.save_cache(src.id, b"0.0.0.0 cascade.example.com\n")
            .await
            .expect("save_cache");

        // Verify the cache row exists before removal.
        let before = repo
            .load_cache(src.id)
            .await
            .expect("load_cache before remove")
            .expect("cache must exist before remove");
        assert!(!before.content.is_empty());

        // Remove the source.
        repo.remove(src.id).await.expect("remove");

        // Source must be gone.
        let all = repo.list().await.expect("list after remove");
        assert!(
            all.iter().all(|b| b.id != src.id),
            "removed source must not appear in list"
        );

        // Cache row must have cascaded away.
        let after = repo
            .load_cache(src.id)
            .await
            .expect("load_cache after remove");
        assert!(
            after.is_none(),
            "blocklist_cache row must be removed via ON DELETE CASCADE"
        );
    }
}
