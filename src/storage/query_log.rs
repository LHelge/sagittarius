//! Repository for the `query_log` table — durable per-query history (Epic E10).
//!
//! Provides the [`QueryLogRepository`] trait and its [`SqliteQueryLogRepo`]
//! implementation, mirroring the other repository modules (trait + `Sqlite*Repo`
//! over compile-time-checked `sqlx` macros).
//!
//! Rows originate from [`QueryEvent`]s emitted on the DNS pipeline's log step.
//! The hot path never writes here directly: a dedicated batching writer task
//! (E10.4) drains a channel and calls [`QueryLogRepository::insert_batch`] so
//! the response path is never blocked on SQLite.
//!
//! The persisted `outcome` column uses the stable [`Outcome::as_str`] tokens
//! (E10.2); reads decode them back via [`Outcome`]'s [`FromStr`](std::str::FromStr).

use std::future::Future;

use sqlx::SqlitePool;

use super::Error;
use crate::{resolver::pipeline::Outcome, telemetry::QueryEvent};

// ── Result alias ────────────────────────────────────────────────────────────

pub type Result<T> = std::result::Result<T, Error>;

// ── QueryLogRecord ──────────────────────────────────────────────────────────

/// One persisted query-log row.
///
/// Built from a [`QueryEvent`] via [`From<&QueryEvent>`](QueryLogRecord) for
/// insertion (where `id` is ignored — the DB assigns it) and reconstructed from
/// the database by the read methods (where `id` is the real primary key).
#[derive(Debug, Clone, PartialEq)]
pub struct QueryLogRecord {
    /// Row primary key / pagination cursor. Ignored on insert (DB-assigned).
    pub id: i64,
    /// Receipt time, epoch milliseconds.
    pub ts: i64,
    /// Client IP (no port).
    pub client: String,
    /// Queried name (canonical form, with trailing dot).
    pub qname: String,
    /// Query type rendered as text — an IANA mnemonic (`A`, `AAAA`, `HTTPS`, …)
    /// or the RFC 3597 `TYPE<n>` form for unrecognized types.
    pub qtype: String,
    /// How the query was resolved.
    pub outcome: Outcome,
    /// DNS response code as an integer, when known.
    pub rcode: Option<i64>,
    /// Answering upstream (`ip:port`), when the query was forwarded.
    pub upstream: Option<String>,
    /// Measured query latency in milliseconds.
    pub latency_ms: i64,
    /// Primary blocklist source (`blocklist_id`) responsible for the block, when
    /// `outcome` is [`Outcome::BlockedByBlocklist`] and the name was still
    /// attributed in the live snapshot (E11).
    ///
    /// `None` for every other outcome. A plain integer, not an FK: it preserves
    /// historical attribution after a list is deleted (the read path LEFT JOINs
    /// `blocklists` and renders unknown ids as "removed list").
    pub blocklist_id: Option<i64>,
}

impl From<&QueryEvent> for QueryLogRecord {
    /// Build a record from an event. `blocklist_id` is left `None` here; the
    /// query-log writer (E11.3) resolves it from the live blocklist snapshot for
    /// `BlockedByBlocklist` events, since the event itself carries no source.
    fn from(ev: &QueryEvent) -> Self {
        Self {
            id: 0, // ignored on insert — the DB assigns the real id.
            ts: ev.ts,
            client: ev.client.ip().to_string(),
            qname: ev.qname.to_string(),
            // `Qtype`'s Display is the single canonical rendering (mnemonic or
            // RFC 3597 `TYPE<n>`), shared with the live log row.
            qtype: ev.qtype.to_string(),
            outcome: ev.outcome,
            rcode: ev.rcode.map(|rc| i64::from(u8::from(rc))),
            upstream: ev.upstream.map(|u| u.to_string()),
            latency_ms: ev.latency.as_millis() as i64,
            blocklist_id: None,
        }
    }
}

// ── Private row projection ──────────────────────────────────────────────────

/// Primitive projection for `query_as!` (SQLite types only).
///
/// NOT NULL columns get sqlx's non-null override (`AS "col!"`) because
/// sqlx-SQLite's nullability inference is conservative; the nullable columns
/// (`rcode`, `upstream`) stay `Option`.
struct QueryLogRow {
    id: i64,
    ts: i64,
    client: String,
    qname: String,
    qtype: String,
    outcome: String,
    rcode: Option<i64>,
    upstream: Option<String>,
    latency_ms: i64,
    blocklist_id: Option<i64>,
}

impl TryFrom<QueryLogRow> for QueryLogRecord {
    type Error = Error;

    fn try_from(row: QueryLogRow) -> Result<Self> {
        Ok(QueryLogRecord {
            id: row.id,
            ts: row.ts,
            client: row.client,
            qname: row.qname,
            qtype: row.qtype,
            outcome: row
                .outcome
                .parse::<Outcome>()
                .map_err(|_| Error::Decode(format!("unknown outcome token: {:?}", row.outcome)))?,
            rcode: row.rcode,
            upstream: row.upstream,
            latency_ms: row.latency_ms,
            blocklist_id: row.blocklist_id,
        })
    }
}

/// Convert a `Vec<QueryLogRow>` into a `Vec<QueryLogRecord>`, propagating any
/// decode error.
fn rows_to_records(rows: Vec<QueryLogRow>) -> Result<Vec<QueryLogRecord>> {
    rows.into_iter().map(QueryLogRecord::try_from).collect()
}

// ── Aggregates ──────────────────────────────────────────────────────────────

/// Windowed outcome counts for the dashboard (see
/// [`QueryLogRepository::counts_since`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QueryLogCounts {
    /// Total queries in the window.
    pub total: i64,
    /// Queries blocked (admin blacklist or aggregated blocklist).
    pub blocked: i64,
    /// Queries served from the cache.
    pub cached: i64,
    /// Queries forwarded to an upstream.
    pub forwarded: i64,
}

// ── QueryLogRepository trait ────────────────────────────────────────────────

/// Repository for reading and writing query-log rows.
///
/// See [`SettingsRepository`](super::settings::SettingsRepository) for why the
/// methods return `impl Future` rather than `async fn`.
pub trait QueryLogRepository {
    /// Insert a batch of records in a single transaction.
    ///
    /// An empty batch is a no-op. The records' `id` fields are ignored; the DB
    /// assigns the real primary keys.
    fn insert_batch(&self, records: &[QueryLogRecord]) -> impl Future<Output = Result<()>>;

    /// Fetch one page of history, newest-first (keyset pagination on `id`).
    ///
    /// `before = None` returns the newest page; `before = Some(cursor)` returns
    /// the next-older slice with `id < cursor` (no overlap, no gap).
    fn page(
        &self,
        before: Option<i64>,
        limit: i64,
    ) -> impl Future<Output = Result<Vec<QueryLogRecord>>>;

    /// Delete up to `batch_limit` rows older than `cutoff_ts_ms`, returning the
    /// number removed. The caller loops until it returns 0 to bound the work
    /// per statement (and the WAL growth).
    fn purge_older_than(
        &self,
        cutoff_ts_ms: i64,
        batch_limit: i64,
    ) -> impl Future<Output = Result<u64>>;

    /// Return freed pages to the OS via `PRAGMA incremental_vacuum`.
    fn incremental_vacuum(&self) -> impl Future<Output = Result<()>>;

    /// Delete every row (the "Clear query log now" admin action).
    fn clear_all(&self) -> impl Future<Output = Result<()>>;

    /// Windowed outcome counts for rows with `ts >= since_ms`.
    fn counts_since(&self, since_ms: i64) -> impl Future<Output = Result<QueryLogCounts>>;

    /// Top `n` queried names (by count) for rows with `ts >= since_ms`.
    fn top_domains_since(
        &self,
        since_ms: i64,
        n: i64,
    ) -> impl Future<Output = Result<Vec<(String, i64)>>>;

    /// Top `n` clients (by count) for rows with `ts >= since_ms`.
    fn top_clients_since(
        &self,
        since_ms: i64,
        n: i64,
    ) -> impl Future<Output = Result<Vec<(String, i64)>>>;

    /// Count of `BlockedByBlocklist` rows grouped by `blocklist_id` for rows
    /// with `ts >= since_ms` (E11.4 per-list effectiveness).
    ///
    /// The `blocklist_id` is the bare stored value, so callers must LEFT JOIN
    /// the live `blocklists` themselves: an id that no longer matches a source
    /// (or a `None`, written when attribution was unknown) is a "removed list".
    fn block_counts_by_source_since(
        &self,
        since_ms: i64,
    ) -> impl Future<Output = Result<Vec<(Option<i64>, i64)>>>;
}

// ── SqliteQueryLogRepo ──────────────────────────────────────────────────────

/// SQLite-backed [`QueryLogRepository`].
pub struct SqliteQueryLogRepo {
    pool: SqlitePool,
}

impl SqliteQueryLogRepo {
    /// Construct a new repository from an open pool.
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

impl QueryLogRepository for SqliteQueryLogRepo {
    async fn insert_batch(&self, records: &[QueryLogRecord]) -> Result<()> {
        if records.is_empty() {
            return Ok(());
        }

        let mut tx = self.pool.begin().await?;
        for record in records {
            let outcome = record.outcome.as_str();
            sqlx::query!(
                r#"INSERT INTO query_log
                    (ts, client, qname, qtype, outcome, rcode, upstream, latency_ms, blocklist_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
                record.ts,
                record.client,
                record.qname,
                record.qtype,
                outcome,
                record.rcode,
                record.upstream,
                record.latency_ms,
                record.blocklist_id,
            )
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn page(&self, before: Option<i64>, limit: i64) -> Result<Vec<QueryLogRecord>> {
        // `before` is bound twice: once for the NULL guard (newest page) and
        // once for the keyset comparison. When NULL the guard short-circuits to
        // every row; otherwise it restricts to id < before.
        let rows = sqlx::query_as!(
            QueryLogRow,
            r#"SELECT
                id          AS "id!",
                ts          AS "ts!",
                client,
                qname,
                qtype,
                outcome,
                rcode,
                upstream,
                latency_ms  AS "latency_ms!",
                blocklist_id
            FROM query_log
            WHERE (? IS NULL OR id < ?)
            ORDER BY id DESC
            LIMIT ?"#,
            before,
            before,
            limit,
        )
        .fetch_all(&self.pool)
        .await?;

        rows_to_records(rows)
    }

    async fn purge_older_than(&self, cutoff_ts_ms: i64, batch_limit: i64) -> Result<u64> {
        let affected = sqlx::query!(
            r#"DELETE FROM query_log
            WHERE id IN (
                SELECT id FROM query_log WHERE ts < ? ORDER BY id LIMIT ?
            )"#,
            cutoff_ts_ms,
            batch_limit,
        )
        .execute(&self.pool)
        .await?
        .rows_affected();

        Ok(affected)
    }

    async fn incremental_vacuum(&self) -> Result<()> {
        // PRAGMA is not supported by the compile-time query macros.
        sqlx::query("PRAGMA incremental_vacuum;")
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn clear_all(&self) -> Result<()> {
        sqlx::query!("DELETE FROM query_log")
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn counts_since(&self, since_ms: i64) -> Result<QueryLogCounts> {
        let row = sqlx::query!(
            r#"SELECT
                COUNT(*) AS "total!: i64",
                COALESCE(SUM(
                    CASE WHEN outcome IN ('blocked-admin', 'blocked-blocklist')
                         THEN 1 ELSE 0 END), 0) AS "blocked!: i64",
                COALESCE(SUM(
                    CASE WHEN outcome = 'cached' THEN 1 ELSE 0 END), 0) AS "cached!: i64",
                COALESCE(SUM(
                    CASE WHEN outcome = 'forwarded' THEN 1 ELSE 0 END), 0) AS "forwarded!: i64"
            FROM query_log
            WHERE ts >= ?"#,
            since_ms,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(QueryLogCounts {
            total: row.total,
            blocked: row.blocked,
            cached: row.cached,
            forwarded: row.forwarded,
        })
    }

    async fn top_domains_since(&self, since_ms: i64, n: i64) -> Result<Vec<(String, i64)>> {
        let rows = sqlx::query!(
            r#"SELECT qname, COUNT(*) AS "n!: i64"
            FROM query_log
            WHERE ts >= ?
            GROUP BY qname
            ORDER BY COUNT(*) DESC, qname ASC
            LIMIT ?"#,
            since_ms,
            n,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| (r.qname, r.n)).collect())
    }

    async fn top_clients_since(&self, since_ms: i64, n: i64) -> Result<Vec<(String, i64)>> {
        let rows = sqlx::query!(
            r#"SELECT client, COUNT(*) AS "n!: i64"
            FROM query_log
            WHERE ts >= ?
            GROUP BY client
            ORDER BY COUNT(*) DESC, client ASC
            LIMIT ?"#,
            since_ms,
            n,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| (r.client, r.n)).collect())
    }

    async fn block_counts_by_source_since(&self, since_ms: i64) -> Result<Vec<(Option<i64>, i64)>> {
        // 'blocked-blocklist' is Outcome::BlockedByBlocklist.as_str(); kept in
        // sync with the enum by the same guard test as counts_since.
        let rows = sqlx::query!(
            r#"SELECT blocklist_id, COUNT(*) AS "n!: i64"
            FROM query_log
            WHERE ts >= ? AND outcome = 'blocked-blocklist'
            GROUP BY blocklist_id"#,
            since_ms,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| (r.blocklist_id, r.n)).collect())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Db;
    use tempfile::TempDir;

    async fn open_repo() -> (TempDir, SqliteQueryLogRepo) {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("test.db");
        let db = Db::connect(&path).await.expect("connect");
        let repo = SqliteQueryLogRepo::new(db.pool().clone());
        (dir, repo)
    }

    /// Build a record with the given id/ts/client/outcome and sensible defaults.
    fn rec(ts: i64, client: &str, qname: &str, outcome: Outcome) -> QueryLogRecord {
        QueryLogRecord {
            id: 0,
            ts,
            client: client.to_owned(),
            qname: qname.to_owned(),
            qtype: "A".to_owned(),
            outcome,
            rcode: Some(0),
            upstream: None,
            latency_ms: 5,
            blocklist_id: None,
        }
    }

    // ── From<&QueryEvent> mapping ─────────────────────────────────────────────

    #[test]
    fn record_from_event_maps_fields() {
        use crate::codec::{header::Rcode, message::Qtype, name::Name};
        use std::time::Duration;

        let client: std::net::SocketAddr = "203.0.113.7:5353".parse().unwrap();
        let qname: Name = "ads.example.com".parse().unwrap();
        let ev = QueryEvent::new(client, qname, Qtype::Aaaa, Outcome::Forwarded)
            .with_ts(1_234_567_890_123)
            .with_rcode(Rcode::NoError)
            .with_upstream("9.9.9.9:53".parse().unwrap())
            .with_latency(Duration::from_millis(17));

        let record = QueryLogRecord::from(&ev);
        assert_eq!(record.ts, 1_234_567_890_123);
        assert_eq!(record.client, "203.0.113.7", "client must drop the port");
        assert_eq!(record.qname, "ads.example.com.");
        assert_eq!(record.qtype, "AAAA");
        assert_eq!(record.outcome, Outcome::Forwarded);
        assert_eq!(record.rcode, Some(0));
        assert_eq!(record.upstream.as_deref(), Some("9.9.9.9:53"));
        assert_eq!(record.latency_ms, 17);
    }

    // ── insert_batch + page ───────────────────────────────────────────────────

    #[tokio::test]
    async fn insert_batch_empty_is_noop() {
        let (_dir, repo) = open_repo().await;
        repo.insert_batch(&[]).await.expect("empty batch is ok");
        assert!(repo.page(None, 10).await.expect("page").is_empty());
    }

    #[tokio::test]
    async fn page_returns_newest_first_with_keyset_pagination() {
        let (_dir, repo) = open_repo().await;

        // Insert 5 rows with increasing ts. id follows insertion order.
        let batch: Vec<_> = (0..5)
            .map(|i| rec(1_000 + i, "10.0.0.1", "example.com.", Outcome::Forwarded))
            .collect();
        repo.insert_batch(&batch).await.expect("insert");

        // Newest page (limit 2) → the two highest ids, descending.
        let page1 = repo.page(None, 2).await.expect("page1");
        assert_eq!(page1.len(), 2);
        assert!(page1[0].id > page1[1].id, "newest-first by id");
        assert_eq!(page1[0].ts, 1_004);
        assert_eq!(page1[1].ts, 1_003);

        // Next page using the last id as the cursor → older slice, no overlap.
        let cursor = page1[1].id;
        let page2 = repo.page(Some(cursor), 2).await.expect("page2");
        assert_eq!(page2.len(), 2);
        assert!(page2[0].id < cursor, "strictly older than the cursor");
        assert_eq!(page2[0].ts, 1_002);
        assert_eq!(page2[1].ts, 1_001);

        // Final page has the single remaining oldest row.
        let cursor2 = page2[1].id;
        let page3 = repo.page(Some(cursor2), 2).await.expect("page3");
        assert_eq!(page3.len(), 1);
        assert_eq!(page3[0].ts, 1_000);

        // Past the end → empty.
        let cursor3 = page3[0].id;
        assert!(repo.page(Some(cursor3), 2).await.expect("page4").is_empty());
    }

    #[tokio::test]
    async fn page_decodes_outcome_token_back_to_enum() {
        let (_dir, repo) = open_repo().await;
        repo.insert_batch(&[rec(1, "10.0.0.1", "a.test.", Outcome::BlockedByBlocklist)])
            .await
            .expect("insert");
        let page = repo.page(None, 10).await.expect("page");
        assert_eq!(page[0].outcome, Outcome::BlockedByBlocklist);
    }

    // ── purge_older_than ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn purge_removes_only_older_rows_and_counts() {
        let (_dir, repo) = open_repo().await;

        let batch: Vec<_> = [100, 200, 300, 400]
            .iter()
            .map(|&ts| rec(ts, "10.0.0.1", "x.test.", Outcome::Cached))
            .collect();
        repo.insert_batch(&batch).await.expect("insert");

        // Cutoff 300 → rows with ts < 300 (ts 100 and 200) are removed.
        let removed = repo.purge_older_than(300, 100).await.expect("purge");
        assert_eq!(removed, 2, "exactly the two rows older than 300");

        let remaining = repo.page(None, 10).await.expect("page");
        assert_eq!(remaining.len(), 2);
        assert!(
            remaining.iter().all(|r| r.ts >= 300),
            "only rows at/after the cutoff survive"
        );

        // Idempotent once drained.
        let again = repo.purge_older_than(300, 100).await.expect("purge again");
        assert_eq!(again, 0, "nothing left older than the cutoff");
    }

    #[tokio::test]
    async fn purge_respects_batch_limit() {
        let (_dir, repo) = open_repo().await;
        let batch: Vec<_> = (0..5)
            .map(|i| rec(i, "10.0.0.1", "x.test.", Outcome::Cached))
            .collect();
        repo.insert_batch(&batch).await.expect("insert");

        // All 5 are older than the cutoff, but the batch limit caps each call.
        let first = repo.purge_older_than(1_000, 2).await.expect("purge");
        assert_eq!(first, 2, "batch limit caps the delete count");
        let second = repo.purge_older_than(1_000, 2).await.expect("purge");
        assert_eq!(second, 2);
        let third = repo.purge_older_than(1_000, 2).await.expect("purge");
        assert_eq!(third, 1, "remaining row");
        let fourth = repo.purge_older_than(1_000, 2).await.expect("purge");
        assert_eq!(fourth, 0);
    }

    #[tokio::test]
    async fn incremental_vacuum_runs() {
        let (_dir, repo) = open_repo().await;
        repo.insert_batch(&[rec(1, "10.0.0.1", "x.test.", Outcome::Cached)])
            .await
            .expect("insert");
        repo.purge_older_than(1_000, 100).await.expect("purge");
        repo.incremental_vacuum()
            .await
            .expect("vacuum must succeed");
    }

    // ── clear_all ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn clear_all_empties_table() {
        let (_dir, repo) = open_repo().await;
        let batch: Vec<_> = (0..3)
            .map(|i| rec(i, "10.0.0.1", "x.test.", Outcome::Cached))
            .collect();
        repo.insert_batch(&batch).await.expect("insert");
        repo.clear_all().await.expect("clear");
        assert!(repo.page(None, 10).await.expect("page").is_empty());
    }

    // ── aggregates ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn counts_since_categorizes_and_windows() {
        let (_dir, repo) = open_repo().await;

        // Old rows (ts 10) must be excluded by the window.
        repo.insert_batch(&[
            rec(10, "10.0.0.1", "old.test.", Outcome::Forwarded),
            rec(10, "10.0.0.1", "old.test.", Outcome::Cached),
        ])
        .await
        .expect("insert old");

        // In-window rows (ts 1000+).
        repo.insert_batch(&[
            rec(1000, "10.0.0.1", "a.test.", Outcome::Forwarded),
            rec(1001, "10.0.0.1", "b.test.", Outcome::Cached),
            rec(1002, "10.0.0.1", "c.test.", Outcome::BlockedByAdmin),
            rec(1003, "10.0.0.1", "d.test.", Outcome::BlockedByBlocklist),
            rec(1004, "10.0.0.1", "e.test.", Outcome::Local),
        ])
        .await
        .expect("insert new");

        let counts = repo.counts_since(1000).await.expect("counts");
        assert_eq!(counts.total, 5, "only the 5 in-window rows");
        assert_eq!(counts.blocked, 2, "admin + blocklist");
        assert_eq!(counts.cached, 1);
        assert_eq!(counts.forwarded, 1);
    }

    #[tokio::test]
    async fn counts_since_empty_window_is_zero() {
        let (_dir, repo) = open_repo().await;
        let counts = repo.counts_since(0).await.expect("counts");
        assert_eq!(counts, QueryLogCounts::default());
    }

    /// `counts_since` hardcodes the outcome tokens it buckets as blocked / cached
    /// / forwarded directly in SQL. This guards that those literals stay in sync
    /// with `Outcome`'s `#[strum(serialize)]` tokens — rename a token and this
    /// fails, pointing here instead of silently miscounting the dashboard.
    #[test]
    fn counts_since_sql_tokens_match_outcome_mapping() {
        use std::collections::BTreeSet;
        use strum::IntoEnumIterator as _;

        // The SQL's `outcome IN ('blocked-admin', 'blocked-blocklist')` must be
        // exactly the variants whose category() is "blocked".
        let blocked: BTreeSet<&str> = Outcome::iter()
            .filter(|o| o.category() == "blocked")
            .map(|o| o.as_str())
            .collect();
        assert_eq!(
            blocked,
            BTreeSet::from(["blocked-admin", "blocked-blocklist"]),
            "blocked-bucket tokens drifted from counts_since SQL"
        );
        assert_eq!(Outcome::Cached.as_str(), "cached");
        assert_eq!(Outcome::Forwarded.as_str(), "forwarded");
    }

    /// Build a record with an explicit blocklist_id attribution.
    fn rec_attributed(ts: i64, qname: &str, blocklist_id: Option<i64>) -> QueryLogRecord {
        QueryLogRecord {
            blocklist_id,
            ..rec(ts, "10.0.0.1", qname, Outcome::BlockedByBlocklist)
        }
    }

    #[tokio::test]
    async fn block_counts_by_source_groups_and_windows() {
        let (_dir, repo) = open_repo().await;

        // Old blocked row (ts 10) must be excluded by the window.
        repo.insert_batch(&[rec_attributed(10, "old.test.", Some(1))])
            .await
            .expect("insert old");

        repo.insert_batch(&[
            rec_attributed(1000, "a.test.", Some(1)),
            rec_attributed(1001, "b.test.", Some(1)),
            rec_attributed(1002, "c.test.", Some(2)),
            rec_attributed(1003, "d.test.", None), // unknown / removed at write time
            // A non-blocklist outcome must not be counted even if attributed.
            rec(1004, "10.0.0.1", "e.test.", Outcome::Forwarded),
        ])
        .await
        .expect("insert new");

        let mut counts = repo
            .block_counts_by_source_since(1000)
            .await
            .expect("counts");
        counts.sort_by_key(|(id, _)| *id); // None sorts first

        assert_eq!(
            counts,
            vec![(None, 1), (Some(1), 2), (Some(2), 1)],
            "grouped by blocklist_id, blocklist-only, windowed"
        );
    }

    #[tokio::test]
    async fn block_counts_by_source_empty_window_is_empty() {
        let (_dir, repo) = open_repo().await;
        let counts = repo.block_counts_by_source_since(0).await.expect("counts");
        assert!(counts.is_empty(), "no rows → no groups");
    }

    #[tokio::test]
    async fn top_domains_and_clients_rank_within_window() {
        let (_dir, repo) = open_repo().await;

        // Old row excluded by window.
        repo.insert_batch(&[rec(1, "9.9.9.9", "old.test.", Outcome::Forwarded)])
            .await
            .expect("insert old");

        let mut batch = Vec::new();
        // a.test ×3, b.test ×2, c.test ×1 from two clients.
        for _ in 0..3 {
            batch.push(rec(1000, "10.0.0.1", "a.test.", Outcome::Forwarded));
        }
        for _ in 0..2 {
            batch.push(rec(1000, "10.0.0.2", "b.test.", Outcome::Forwarded));
        }
        batch.push(rec(1000, "10.0.0.2", "c.test.", Outcome::Forwarded));
        repo.insert_batch(&batch).await.expect("insert");

        let domains = repo.top_domains_since(1000, 2).await.expect("top domains");
        assert_eq!(
            domains,
            vec![("a.test.".to_owned(), 3), ("b.test.".to_owned(), 2)],
            "top-N domains ranked by count, old row excluded"
        );

        let clients = repo.top_clients_since(1000, 10).await.expect("top clients");
        assert_eq!(
            clients,
            vec![("10.0.0.1".to_owned(), 3), ("10.0.0.2".to_owned(), 3)],
            "both clients have count 3; ascending-ip tie-break orders .1 before .2"
        );
    }
}
