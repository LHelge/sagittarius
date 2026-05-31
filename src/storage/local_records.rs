//! Repository for the `local_records` table — authoritative local DNS records.
//!
//! Provides the [`LocalRecordRepository`] trait and its
//! [`SqliteLocalRecordRepo`] implementation.  All DB interaction uses
//! compile-time-checked `sqlx` macros against the `local_records` table
//! defined in the schema migration.
//!
//! # Name normalization
//!
//! Local record names are stored in a normalized form: **lowercase** with a
//! **trailing dot**.  Wildcard names like `*.home.lan` are supported — the `*`
//! label is kept verbatim and only the remaining labels are lowercased.  The
//! trailing dot is appended if absent.
//!
//! This normalization is intentionally done without going through
//! [`crate::codec::name::Name`] because `Name` does not allow a leading `*`
//! label.  The logic is equivalent for non-wildcard names and guarantees
//! consistent comparison with the resolver's `HashSet<Name>` lookups for
//! normal labels.

use std::{fmt, str::FromStr};

use sqlx::SqlitePool;

use super::Error;

// ── Result alias ────────────────────────────────────────────────────────────

pub type Result<T> = std::result::Result<T, Error>;

// ── RecordType ────────────────────────────────────────────────────────────────

/// DNS record type for local records (v0.1: A and AAAA only).
///
/// Maps to/from the `record_type` TEXT column values `'A'` and `'AAAA'`.
/// This is a focused subset; it deliberately does not reuse
/// [`crate::codec::header::Qtype`], which allows arbitrary `Other` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::IntoStaticStr)]
pub enum RecordType {
    /// IPv4 address record.
    #[strum(serialize = "A")]
    A,
    /// IPv6 address record.
    #[strum(serialize = "AAAA")]
    Aaaa,
}

impl RecordType {
    /// Returns the canonical TEXT representation stored in the database.
    ///
    /// Driven by `#[strum(serialize)]` ([`strum::IntoStaticStr`]); the
    /// value-carrying [`FromStr`] below is the inverse.
    pub fn as_str(&self) -> &'static str {
        self.into()
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RecordType {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "A" => Ok(Self::A),
            "AAAA" => Ok(Self::Aaaa),
            other => Err(Error::Decode(format!(
                "unknown record_type value: {other:?}"
            ))),
        }
    }
}

// ── LocalRecord ──────────────────────────────────────────────────────────────

/// A single row from the `local_records` table.
#[derive(Debug, Clone, PartialEq)]
pub struct LocalRecord {
    /// Row primary key.
    pub id: i64,
    /// Normalized name (lowercase, trailing dot).  May be a wildcard like
    /// `*.home.lan.`.
    pub name: String,
    /// DNS record type (A or AAAA).
    pub record_type: RecordType,
    /// The IP address value for A/AAAA records.
    pub value: String,
    /// Time-to-live in seconds.
    pub ttl: u32,
}

/// Data required to insert a new local record (no `id` — assigned by the DB).
#[derive(Debug, Clone)]
pub struct NewLocalRecord {
    /// Domain name to add.  May be a wildcard like `*.home.lan`.
    /// Will be normalized to lowercase with a trailing dot before storage.
    pub name: String,
    /// DNS record type.
    pub record_type: RecordType,
    /// IP address value.
    pub value: String,
    /// Time-to-live in seconds.
    pub ttl: u32,
}

// ── Private row struct ────────────────────────────────────────────────────────

/// Private projection for `query_as!` — primitive SQLite types only.
///
/// `id` and `ttl` use the non-null override `AS "col!"` because sqlx-SQLite
/// infers NOT NULL INTEGER columns as `Option<i64>` in some query shapes.
struct LocalRecordRow {
    id: i64,
    name: String,
    record_type: String,
    value: String,
    ttl: i64,
}

impl TryFrom<LocalRecordRow> for LocalRecord {
    type Error = Error;

    fn try_from(row: LocalRecordRow) -> Result<Self> {
        let record_type: RecordType = row.record_type.parse()?;
        let ttl = u32::try_from(row.ttl).map_err(|_| {
            Error::Decode(format!(
                "ttl value {} is out of u32 range for record {:?}",
                row.ttl, row.name
            ))
        })?;

        Ok(LocalRecord {
            id: row.id,
            name: row.name,
            record_type,
            value: row.value,
            ttl,
        })
    }
}

// ── Name normalization ────────────────────────────────────────────────────────

/// Normalize a local-record name to lowercase with a trailing dot.
///
/// Wildcard names like `*.home.lan` are supported: the `*` first label is kept
/// verbatim; only the dot-separated labels after it are lowercased.  A trailing
/// dot is appended if absent.
///
/// This is intentionally a light manual normalization rather than routing
/// through [`crate::codec::name::Name`], which does not accept a leading `*`
/// label.  For non-wildcard names the result is equivalent to what `Name`
/// produces.
fn normalize_local_name(name: &str) -> String {
    let s = name.strip_suffix('.').unwrap_or(name);
    let lowered = s.to_ascii_lowercase();
    format!("{lowered}.")
}

// ── LocalRecordRepository trait ───────────────────────────────────────────────

/// Repository for reading and writing local DNS records.
///
/// # Note on `async_fn_in_trait`
///
/// We use `async fn` directly in the trait.  All implementations live in this
/// crate, so we control the full `impl` surface and have no need for
/// `Send`-bound flexibility across dynamic dispatch.  The lint is suppressed
/// here rather than desugaring to `impl Future`.
#[allow(async_fn_in_trait)]
pub trait LocalRecordRepository {
    /// Insert a new local record and return the full inserted row (including
    /// the auto-assigned `id`).
    ///
    /// The name is normalized (lowercase, trailing dot) before storage.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Sqlx`] wrapping the underlying
    /// `UNIQUE (name, record_type)` constraint violation if a record with the
    /// same normalized name **and** the same type already exists.  A record
    /// with the same name but a **different** type succeeds.
    async fn add(&self, record: NewLocalRecord) -> Result<LocalRecord>;

    /// Delete the local record with the given `id`.
    ///
    /// If no row with that `id` exists, the call succeeds silently (no-op).
    async fn remove(&self, id: i64) -> Result<()>;

    /// List all local records ordered by name, then record type.
    ///
    /// Intended for the admin UI.
    async fn list(&self) -> Result<Vec<LocalRecord>>;

    /// Load all local records (same as [`list`](Self::list)).
    ///
    /// This is the dedicated bulk-read entry point used by the resolver (E4)
    /// to hydrate its in-memory data structures.  Provided as a separate
    /// method to clearly signal the hydration intent and allow future
    /// specialization (e.g. a subset filter).
    async fn load_all(&self) -> Result<Vec<LocalRecord>>;
}

// ── SqliteLocalRecordRepo ─────────────────────────────────────────────────────

/// SQLite-backed [`LocalRecordRepository`].
pub struct SqliteLocalRecordRepo {
    pool: SqlitePool,
}

impl SqliteLocalRecordRepo {
    /// Construct a new repository from an open [`crate::storage::Db`].
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

impl LocalRecordRepository for SqliteLocalRecordRepo {
    async fn add(&self, record: NewLocalRecord) -> Result<LocalRecord> {
        let name = normalize_local_name(&record.name);
        let record_type = record.record_type.as_str();
        let ttl = record.ttl as i64;

        let id = sqlx::query!(
            r#"INSERT INTO local_records (name, record_type, value, ttl)
            VALUES (?, ?, ?, ?)
            RETURNING id"#,
            name,
            record_type,
            record.value,
            ttl,
        )
        .fetch_one(&self.pool)
        .await?
        .id;

        Ok(LocalRecord {
            id,
            name,
            record_type: record.record_type,
            value: record.value,
            ttl: record.ttl,
        })
    }

    async fn remove(&self, id: i64) -> Result<()> {
        sqlx::query!("DELETE FROM local_records WHERE id = ?", id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn list(&self) -> Result<Vec<LocalRecord>> {
        let rows = sqlx::query_as!(
            LocalRecordRow,
            r#"SELECT
                id          AS "id!",
                name,
                record_type,
                value,
                ttl         AS "ttl!"
            FROM local_records
            ORDER BY name, record_type"#
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(LocalRecord::try_from).collect()
    }

    async fn load_all(&self) -> Result<Vec<LocalRecord>> {
        // Identical to list() — provided as the dedicated hydration entry point.
        self.list().await
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Db;
    use tempfile::TempDir;

    // ── Helpers ───────────────────────────────────────────────────────────────

    async fn open_repo() -> (TempDir, SqliteLocalRecordRepo) {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("test.db");
        let db = Db::connect(&path).await.expect("connect");
        let repo = SqliteLocalRecordRepo::new(db.pool().clone());
        (dir, repo)
    }

    fn new_record(name: &str, record_type: RecordType, value: &str, ttl: u32) -> NewLocalRecord {
        NewLocalRecord {
            name: name.to_owned(),
            record_type,
            value: value.to_owned(),
            ttl,
        }
    }

    // ── RecordType unit tests ─────────────────────────────────────────────────

    #[test]
    fn record_type_display() {
        assert_eq!(RecordType::A.to_string(), "A");
        assert_eq!(RecordType::Aaaa.to_string(), "AAAA");
    }

    #[test]
    fn record_type_from_str_valid() {
        assert_eq!("A".parse::<RecordType>().unwrap(), RecordType::A);
        assert_eq!("AAAA".parse::<RecordType>().unwrap(), RecordType::Aaaa);
    }

    #[test]
    fn record_type_from_str_invalid() {
        let err = "CNAME".parse::<RecordType>();
        assert!(err.is_err(), "invalid record type must fail");
        let msg = err.unwrap_err().to_string();
        assert!(
            msg.contains("CNAME"),
            "error must mention the bad value: {msg}"
        );
    }

    #[test]
    fn record_type_from_str_case_sensitive() {
        // Only exact-case matches are accepted.
        assert!("a".parse::<RecordType>().is_err());
        assert!("aaaa".parse::<RecordType>().is_err());
        assert!("Aaaa".parse::<RecordType>().is_err());
    }

    // ── normalize_local_name ──────────────────────────────────────────────────

    #[test]
    fn normalize_plain_domain() {
        assert_eq!(normalize_local_name("Router.Home.LAN"), "router.home.lan.");
    }

    #[test]
    fn normalize_already_lowercase_with_dot() {
        assert_eq!(normalize_local_name("router.home.lan."), "router.home.lan.");
    }

    #[test]
    fn normalize_wildcard_name() {
        assert_eq!(normalize_local_name("*.Home.LAN"), "*.home.lan.");
    }

    #[test]
    fn normalize_wildcard_already_normalized() {
        assert_eq!(normalize_local_name("*.home.lan."), "*.home.lan.");
    }

    // ── add() + list()/load_all() round-trips ─────────────────────────────────

    #[tokio::test]
    async fn add_then_list_round_trips() {
        let (_dir, repo) = open_repo().await;

        let inserted = repo
            .add(new_record(
                "router.home.lan",
                RecordType::A,
                "192.168.1.1",
                300,
            ))
            .await
            .expect("add A record");

        assert!(inserted.id > 0);
        assert_eq!(inserted.name, "router.home.lan.");
        assert_eq!(inserted.record_type, RecordType::A);
        assert_eq!(inserted.value, "192.168.1.1");
        assert_eq!(inserted.ttl, 300);

        let records = repo.list().await.expect("list");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0], inserted);
    }

    #[tokio::test]
    async fn name_is_normalized_on_insert() {
        let (_dir, repo) = open_repo().await;

        let inserted = repo
            .add(new_record(
                "Router.Home.LAN",
                RecordType::A,
                "192.168.1.1",
                300,
            ))
            .await
            .expect("add");

        assert_eq!(inserted.name, "router.home.lan.", "name must be normalized");

        let records = repo.list().await.expect("list");
        assert_eq!(records[0].name, "router.home.lan.");
    }

    #[tokio::test]
    async fn same_wildcard_name_a_and_aaaa_both_succeed() {
        let (_dir, repo) = open_repo().await;

        let a_rec = repo
            .add(new_record(
                "*.home.lan",
                RecordType::A,
                "192.168.1.100",
                300,
            ))
            .await
            .expect("add A record");

        let aaaa_rec = repo
            .add(new_record("*.home.lan", RecordType::Aaaa, "fd00::1", 300))
            .await
            .expect("add AAAA record for same wildcard name");

        // Both have the same normalized name.
        assert_eq!(a_rec.name, "*.home.lan.");
        assert_eq!(aaaa_rec.name, "*.home.lan.");

        // They are distinct records with different IDs.
        assert_ne!(a_rec.id, aaaa_rec.id);
        assert_eq!(a_rec.record_type, RecordType::A);
        assert_eq!(aaaa_rec.record_type, RecordType::Aaaa);

        // Both round-trip through list().
        let records = repo.list().await.expect("list");
        assert_eq!(records.len(), 2);
        // Ordered by name then record_type: A < AAAA lexicographically.
        assert_eq!(records[0].record_type, RecordType::A);
        assert_eq!(records[1].record_type, RecordType::Aaaa);
    }

    #[tokio::test]
    async fn duplicate_name_type_insert_returns_error() {
        let (_dir, repo) = open_repo().await;

        repo.add(new_record("*.home.lan", RecordType::A, "192.168.1.1", 300))
            .await
            .expect("first add");

        let err = repo
            .add(new_record("*.home.lan", RecordType::A, "10.0.0.1", 300))
            .await
            .expect_err("duplicate (name, record_type) must error");

        // Must surface as a database (Sqlx) error wrapping the UNIQUE violation.
        assert!(
            matches!(err, Error::Sqlx(_)),
            "expected Sqlx error for UNIQUE violation, got {err:?}"
        );
    }

    #[tokio::test]
    async fn remove_deletes_record() {
        let (_dir, repo) = open_repo().await;

        let inserted = repo
            .add(new_record(
                "router.home.lan",
                RecordType::A,
                "192.168.1.1",
                300,
            ))
            .await
            .expect("add");

        repo.remove(inserted.id).await.expect("remove");

        let records = repo.list().await.expect("list after remove");
        assert!(records.is_empty(), "record must be gone after remove");
    }

    #[tokio::test]
    async fn remove_nonexistent_is_noop() {
        let (_dir, repo) = open_repo().await;
        repo.remove(9999)
            .await
            .expect("remove non-existent must not error");
    }

    #[tokio::test]
    async fn load_all_returns_all_records() {
        let (_dir, repo) = open_repo().await;

        repo.add(new_record(
            "router.home.lan",
            RecordType::A,
            "192.168.1.1",
            300,
        ))
        .await
        .expect("add A");
        repo.add(new_record(
            "router.home.lan",
            RecordType::Aaaa,
            "fd00::1",
            300,
        ))
        .await
        .expect("add AAAA");
        repo.add(new_record(
            "nas.home.lan",
            RecordType::A,
            "192.168.1.2",
            600,
        ))
        .await
        .expect("add nas");

        let all = repo.load_all().await.expect("load_all");
        assert_eq!(all.len(), 3);
    }

    #[tokio::test]
    async fn wildcard_name_round_trips_faithfully() {
        let (_dir, repo) = open_repo().await;

        let inserted = repo
            .add(new_record(
                "*.WILD.example.COM",
                RecordType::A,
                "1.2.3.4",
                120,
            ))
            .await
            .expect("add wildcard");

        assert_eq!(
            inserted.name, "*.wild.example.com.",
            "wildcard name must normalize to lowercase with trailing dot"
        );
        assert_eq!(inserted.value, "1.2.3.4");
        assert_eq!(inserted.ttl, 120);

        let records = repo.list().await.expect("list");
        assert_eq!(records[0].name, "*.wild.example.com.");
    }

    #[tokio::test]
    async fn type_value_ttl_are_stored_faithfully() {
        let (_dir, repo) = open_repo().await;

        let inserted = repo
            .add(new_record(
                "host.local",
                RecordType::Aaaa,
                "2001:db8::1",
                7200,
            ))
            .await
            .expect("add AAAA");

        assert_eq!(inserted.record_type, RecordType::Aaaa);
        assert_eq!(inserted.value, "2001:db8::1");
        assert_eq!(inserted.ttl, 7200);
    }
}
