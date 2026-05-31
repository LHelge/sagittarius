//! Background task that persists query events off the DNS hot path (E10.4).
//!
//! The [`TelemetrySink`](super::TelemetrySink) `try_send`s each [`QueryEvent`]
//! onto a bounded channel; this task drains that channel, batches events, and
//! writes them to SQLite in a single transaction per batch via
//! [`QueryLogRepository::insert_batch`]. Decoupling the write this way keeps the
//! response path free of any database latency.
//!
//! On shutdown (cancellation) the task makes a **final drain**: it flushes every
//! event still buffered in the channel before returning, so a graceful stop
//! never loses the tail of the log.

use std::sync::Arc;

use tokio::sync::mpsc::Receiver;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::{
    resolver::{pipeline::Outcome, state::ResolverState},
    storage::query_log::{QueryLogRecord, QueryLogRepository},
    telemetry::QueryEvent,
};

/// Maximum number of events written in a single `insert_batch` transaction.
const BATCH_CAPACITY: usize = 256;

/// Maximum time to keep coalescing a partial batch before flushing it, so
/// events are never held back more than ~1s under light load.
const FLUSH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// Drains the query-log channel and writes batches to the durable store.
pub struct QueryLogWriter<R> {
    rx: Receiver<QueryEvent>,
    repo: R,
    /// Shared resolver state, read off the hot path to attribute blocklist
    /// blocks to their primary source (E11.3).
    state: Arc<ResolverState>,
}

impl<R> QueryLogWriter<R>
where
    R: QueryLogRepository,
{
    /// Create a writer over `rx` (the channel held by the telemetry sink), the
    /// query-log `repo`, and the shared `state` (used to resolve the primary
    /// blocklist source of `BlockedByBlocklist` events).
    pub fn new(rx: Receiver<QueryEvent>, repo: R, state: Arc<ResolverState>) -> Self {
        Self { rx, repo, state }
    }

    /// Build the persisted record for `event`, attributing the primary blocklist
    /// source for `BlockedByBlocklist` events.
    ///
    /// **Eventual consistency:** the attribution is resolved against the *live*
    /// blocklist snapshot (read here ~1s after the block, off the hot path), not
    /// the snapshot in force at block time. A refresh in that window could shift
    /// or drop the attribution. A name that was blocked-by-blocklist is normally
    /// still present unless a refresh removed it in the gap — in which case
    /// `primary_source` returns `None` and the row stores `NULL`, which is fine
    /// for effectiveness telemetry.
    fn record_for(&self, event: &QueryEvent) -> QueryLogRecord {
        let mut record = QueryLogRecord::from(event);
        if event.outcome == Outcome::BlockedByBlocklist {
            record.blocklist_id = self.state.blocklist().primary_source(&event.qname);
        }
        record
    }

    /// Run until cancelled or every sender is dropped, then make a final drain.
    pub async fn run(mut self, token: CancellationToken) {
        loop {
            let mut batch = Vec::with_capacity(BATCH_CAPACITY);

            // Block for the first event of the next batch, honoring cancellation
            // and channel closure.
            tokio::select! {
                biased;
                _ = token.cancelled() => break,
                received = self.rx.recv_many(&mut batch, BATCH_CAPACITY) => {
                    if received == 0 {
                        // All senders dropped — nothing more will ever arrive.
                        return;
                    }
                }
            }

            // Coalesce more events into the batch until it fills or the flush
            // interval elapses, so steady traffic amortises into fewer txns.
            if batch.len() < BATCH_CAPACITY {
                let flush_at = tokio::time::sleep(FLUSH_INTERVAL);
                tokio::pin!(flush_at);
                loop {
                    let remaining = BATCH_CAPACITY - batch.len();
                    if remaining == 0 {
                        break;
                    }
                    tokio::select! {
                        biased;
                        _ = token.cancelled() => break,
                        _ = &mut flush_at => break,
                        received = self.rx.recv_many(&mut batch, remaining) => {
                            if received == 0 {
                                break; // channel closed; flush what we have
                            }
                        }
                    }
                }
            }

            self.flush(batch).await;

            if token.is_cancelled() {
                break;
            }
        }

        self.final_drain().await;
    }

    /// Flush all events still buffered in the channel without awaiting new ones.
    ///
    /// Called once after cancellation so the tail of the log is not lost. Uses
    /// `try_recv` (never blocks) so it cannot hang if a sender is still alive.
    async fn final_drain(&mut self) {
        // `try_recv` never blocks, so this terminates whether the channel is
        // empty or disconnected — it cannot hang if a sender is still alive.
        let mut batch = Vec::with_capacity(BATCH_CAPACITY);
        while let Ok(event) = self.rx.try_recv() {
            batch.push(event);
            if batch.len() >= BATCH_CAPACITY {
                self.flush(std::mem::take(&mut batch)).await;
                batch.reserve(BATCH_CAPACITY);
            }
        }
        self.flush(batch).await;
    }

    /// Map a batch of events to records and persist them in one transaction.
    async fn flush(&self, batch: Vec<QueryEvent>) {
        if batch.is_empty() {
            return;
        }
        let records: Vec<QueryLogRecord> =
            batch.iter().map(|event| self.record_for(event)).collect();
        if let Err(e) = self.repo.insert_batch(&records).await {
            warn!(
                error = %e,
                count = records.len(),
                "failed to persist query-log batch"
            );
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use tempfile::TempDir;
    use tokio::sync::mpsc;

    use super::*;
    use crate::{
        codec::{message::Qtype, name::Name},
        storage::{Db, query_log::SqliteQueryLogRepo},
    };

    async fn open_repo() -> (TempDir, SqliteQueryLogRepo, Db, Arc<ResolverState>) {
        let (dir, db) = crate::test_support::temp_db().await;
        let repo = db.query_log();
        let state = ResolverState::hydrate(&db).await.expect("hydrate");
        (dir, repo, db, state)
    }

    fn event(name: &str) -> QueryEvent {
        event_with(name, Outcome::Forwarded)
    }

    fn event_with(name: &str, outcome: Outcome) -> QueryEvent {
        QueryEvent::new(
            "10.0.0.1:1000".parse().unwrap(),
            name.parse::<Name>().unwrap(),
            Qtype::A,
            outcome,
        )
        .with_ts(1_000)
    }

    /// Install a blocklist snapshot mapping each `(name, id)` into the state.
    fn install_blocklist(state: &ResolverState, entries: &[(&str, i64)]) {
        let map = entries
            .iter()
            .map(|(n, id)| (n.parse::<Name>().unwrap(), *id))
            .collect();
        state.blocklist().store(map);
    }

    #[tokio::test]
    async fn writes_enqueued_events_to_db() {
        let (_dir, repo, db, state) = open_repo().await;
        let (tx, rx) = mpsc::channel(64);
        let writer = QueryLogWriter::new(rx, repo, state);
        let token = CancellationToken::new();
        let t2 = token.clone();
        let handle = tokio::spawn(async move { writer.run(t2).await });

        tx.send(event("a.test.")).await.unwrap();
        tx.send(event("b.test.")).await.unwrap();

        // Cancel to force a deterministic final flush, then join.
        token.cancel();
        drop(tx);
        handle.await.unwrap();

        let rows = db.query_log().page(None, 10).await.unwrap();
        assert_eq!(rows.len(), 2, "both enqueued events must be persisted");
    }

    #[tokio::test]
    async fn final_drain_flushes_buffered_events_on_cancel() {
        let (_dir, repo, db, state) = open_repo().await;
        let (tx, rx) = mpsc::channel(64);

        // Buffer several events before the writer ever runs.
        for i in 0..5 {
            tx.try_send(event(&format!("d{i}.test."))).unwrap();
        }

        // Start with an already-cancelled token: the main loop exits at once and
        // the final drain must still flush the buffered tail.
        let token = CancellationToken::new();
        token.cancel();
        let writer = QueryLogWriter::new(rx, repo, state);
        writer.run(token).await;

        let rows = db.query_log().page(None, 10).await.unwrap();
        assert_eq!(rows.len(), 5, "cancellation must drain the buffer");
    }

    #[tokio::test]
    async fn closed_channel_ends_the_run() {
        let (_dir, repo, _db, state) = open_repo().await;
        let (tx, rx) = mpsc::channel(64);
        let writer = QueryLogWriter::new(rx, repo, state);

        // Drop every sender; run must return promptly without cancellation.
        drop(tx);
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            writer.run(CancellationToken::new()),
        )
        .await
        .expect("run must end when the channel closes");
    }

    // ── Blocklist attribution (E11.3) ─────────────────────────────────────────

    /// A `BlockedByBlocklist` event for a domain in source S persists
    /// `blocklist_id = S`.
    #[tokio::test]
    async fn blocked_by_blocklist_persists_primary_source() {
        let (_dir, repo, db, state) = open_repo().await;
        install_blocklist(&state, &[("ads.example.com", 7)]);

        let (tx, rx) = mpsc::channel(64);
        let token = CancellationToken::new();
        let t2 = token.clone();
        let writer = QueryLogWriter::new(rx, repo, state);
        let handle = tokio::spawn(async move { writer.run(t2).await });

        tx.send(event_with("ads.example.com", Outcome::BlockedByBlocklist))
            .await
            .unwrap();
        token.cancel();
        drop(tx);
        handle.await.unwrap();

        let rows = db.query_log().page(None, 10).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].blocklist_id,
            Some(7),
            "block must be attributed to its primary source"
        );
    }

    /// Non-blocklist outcomes persist `NULL`, even if the name happens to be in
    /// the blocklist snapshot.
    #[tokio::test]
    async fn non_blocklist_outcomes_persist_null() {
        let (_dir, repo, db, state) = open_repo().await;
        install_blocklist(&state, &[("ads.example.com", 7)]);

        let (tx, rx) = mpsc::channel(64);
        let token = CancellationToken::new();
        let t2 = token.clone();
        let writer = QueryLogWriter::new(rx, repo, state);
        let handle = tokio::spawn(async move { writer.run(t2).await });

        // Admin block and a plain forward — neither must carry a blocklist_id.
        tx.send(event_with("ads.example.com", Outcome::BlockedByAdmin))
            .await
            .unwrap();
        tx.send(event_with("safe.example.com", Outcome::Forwarded))
            .await
            .unwrap();
        token.cancel();
        drop(tx);
        handle.await.unwrap();

        let rows = db.query_log().page(None, 10).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert!(
            rows.iter().all(|r| r.blocklist_id.is_none()),
            "only BlockedByBlocklist rows may carry a blocklist_id"
        );
    }

    /// A blocked domain that is absent from the current snapshot (e.g. a refresh
    /// dropped it in the ~1s gap) persists `NULL` without error.
    #[tokio::test]
    async fn blocked_domain_absent_from_snapshot_persists_null() {
        let (_dir, repo, db, state) = open_repo().await;
        // Blocklist is empty — the name is not attributed in the live snapshot.

        let (tx, rx) = mpsc::channel(64);
        let token = CancellationToken::new();
        let t2 = token.clone();
        let writer = QueryLogWriter::new(rx, repo, state);
        let handle = tokio::spawn(async move { writer.run(t2).await });

        tx.send(event_with("gone.example.com", Outcome::BlockedByBlocklist))
            .await
            .unwrap();
        token.cancel();
        drop(tx);
        handle.await.unwrap();

        let rows = db.query_log().page(None, 10).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].blocklist_id, None,
            "absent attribution must store NULL, not error"
        );
    }
}
