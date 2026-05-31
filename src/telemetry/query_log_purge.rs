//! Background task that enforces the query-log retention window (E10.5).
//!
//! Once an hour (and once shortly after startup) the [`QueryLogPurger`] deletes
//! rows older than `query_log_retention_days` and returns the freed pages to the
//! OS via `PRAGMA incremental_vacuum`. Deletes are batched so the single SQLite
//! writer lock is never held for long.
//!
//! The retention window is read from the live [`RuntimeSettings`] snapshot on
//! every cycle, so an operator's change takes effect at the next cycle without a
//! restart.

use std::{sync::Arc, time::Duration};

use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::{
    resolver::state::ResolverState,
    storage::{Error, query_log::QueryLogRepository},
    time::{self, Clock},
};

/// How often a purge cycle runs.
const PURGE_INTERVAL: Duration = Duration::from_secs(3_600);

/// Maximum rows deleted per statement, looped until the window is clear. Bounds
/// how long the write lock is held by any single delete.
const PURGE_BATCH: i64 = 1_000;

/// Deletes query-log rows that have aged out of the retention window.
pub struct QueryLogPurger<R> {
    repo: R,
    state: Arc<ResolverState>,
}

impl<R> QueryLogPurger<R>
where
    R: QueryLogRepository,
{
    /// Create a purger over the query-log `repo`, reading retention from `state`.
    pub fn new(repo: R, state: Arc<ResolverState>) -> Self {
        Self { repo, state }
    }

    /// Run one purge cycle, returning the number of rows removed.
    ///
    /// Reads the retention window from the live snapshot, deletes everything
    /// older than the cutoff in bounded batches, then runs an incremental
    /// vacuum to return freed pages.
    pub async fn purge_once(&self) -> Result<u64, Error> {
        let retention_days = u64::from(self.state.settings().query_log_retention_days);
        let cutoff_ms = Clock::millis_ago(time::days(retention_days));

        let mut removed = 0u64;
        loop {
            let n = self.repo.purge_older_than(cutoff_ms, PURGE_BATCH).await?;
            removed += n;
            if n == 0 {
                break;
            }
        }

        // Return freed pages to the OS (effective on fresh DBs; see E10.1).
        self.repo.incremental_vacuum().await?;
        Ok(removed)
    }

    /// Run until cancelled: purge shortly after startup, then every
    /// [`PURGE_INTERVAL`].
    pub async fn run(self, token: CancellationToken) {
        // `interval` fires its first tick immediately, giving the
        // "run once shortly after startup" behaviour for free.
        let mut ticker = tokio::time::interval(PURGE_INTERVAL);
        loop {
            tokio::select! {
                biased;
                _ = token.cancelled() => break,
                _ = ticker.tick() => match self.purge_once().await {
                    Ok(removed) => info!(removed, "query-log purge cycle complete"),
                    Err(e) => warn!(error = %e, "query-log purge cycle failed"),
                },
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;
    use crate::{
        resolver::pipeline::Outcome,
        resolver::state::RuntimeSettings,
        storage::{Db, query_log::QueryLogRecord},
    };

    async fn setup() -> (TempDir, Db, Arc<ResolverState>) {
        let dir = TempDir::new().expect("temp dir");
        let db = Db::connect(dir.path().join("t.db")).await.expect("connect");
        let state = ResolverState::hydrate(&db).await.expect("hydrate");
        (dir, db, state)
    }

    fn record(ts: i64) -> QueryLogRecord {
        QueryLogRecord {
            id: 0,
            ts,
            client: "10.0.0.1".to_owned(),
            qname: "x.test.".to_owned(),
            qtype: "A".to_owned(),
            outcome: Outcome::Forwarded,
            rcode: Some(0),
            upstream: None,
            latency_ms: 1,
        }
    }

    fn set_retention(state: &ResolverState, days: u32) {
        state.store_settings(RuntimeSettings {
            query_log_retention_days: days,
            ..(*state.settings_full()).clone()
        });
    }

    #[tokio::test]
    async fn removes_old_rows_keeps_recent() {
        let (_dir, db, state) = setup().await;
        let repo = db.query_log();

        let now = Clock::now_millis();
        // Default retention is 30 days; one row 40 days old, one fresh.
        let forty_days = time::days(40).as_millis() as i64;
        repo.insert_batch(&[record(now - forty_days), record(now - 1_000)])
            .await
            .expect("insert");

        let purger = QueryLogPurger::new(db.query_log(), state);
        let removed = purger.purge_once().await.expect("purge");
        assert_eq!(removed, 1, "only the aged-out row is removed");

        let rows = repo.page(None, 10).await.expect("page");
        assert_eq!(rows.len(), 1);
        assert!(rows[0].ts >= now - 1_000, "the recent row survives");
    }

    #[tokio::test]
    async fn empty_table_purges_nothing() {
        let (_dir, db, state) = setup().await;
        let purger = QueryLogPurger::new(db.query_log(), state);
        let removed = purger.purge_once().await.expect("purge empty");
        assert_eq!(removed, 0);
    }

    #[tokio::test]
    async fn honors_changed_retention_from_snapshot() {
        let (_dir, db, state) = setup().await;
        let repo = db.query_log();

        // A row two days old survives the default 30-day window …
        let now = Clock::now_millis();
        let two_days = time::days(2).as_millis() as i64;
        repo.insert_batch(&[record(now - two_days)])
            .await
            .expect("insert");

        let purger = QueryLogPurger::new(db.query_log(), Arc::clone(&state));
        assert_eq!(purger.purge_once().await.expect("purge 30d"), 0);

        // … but is removed once retention is tightened to 1 day.
        set_retention(&state, 1);
        assert_eq!(purger.purge_once().await.expect("purge 1d"), 1);
        assert!(repo.page(None, 10).await.expect("page").is_empty());
    }

    #[tokio::test]
    async fn run_exits_promptly_on_cancel() {
        let (_dir, db, state) = setup().await;
        let purger = QueryLogPurger::new(db.query_log(), state);
        let token = CancellationToken::new();
        let t2 = token.clone();
        let handle = tokio::spawn(async move { purger.run(t2).await });

        token.cancel();
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("run must exit promptly after cancel")
            .expect("task join");
    }
}
