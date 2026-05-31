//! Per-query structured event type.
//!
//! [`QueryEvent`] is the canonical record emitted at the pipeline's log step
//! (E6.7).  It carries every piece of information relevant for telemetry and
//! the admin UI: client address, query name/type, resolution outcome, optional
//! RCODE and upstream address, and the measured query latency.
//!
//! The type is `Clone` so that the broadcast channel in [`super::live_log`] can
//! deliver it to multiple subscribers without requiring ownership transfer.

use std::{net::SocketAddr, time::Duration};

use crate::{
    codec::{header::Rcode, message::Qtype, name::Name},
    resolver::pipeline::Outcome,
    time::Clock,
};

// ── QueryEvent ────────────────────────────────────────────────────────────────

/// A record of a single resolved DNS query.
///
/// Constructed by the pipeline's log step (E6.7) and forwarded to
/// [`super::live_log::LiveLog`] and [`super::stats::Stats`] via
/// [`TelemetrySink::record`].
#[derive(Debug, Clone)]
pub struct QueryEvent {
    /// Receipt time as epoch milliseconds (see [`Clock::now_millis`]).
    ///
    /// Captured when the query arrives, so the persisted query log (E10)
    /// orders rows by arrival rather than by when the response completed.
    pub ts: i64,
    /// The client that sent the query.
    pub client: SocketAddr,
    /// The queried domain name.
    pub qname: Name,
    /// The query type (A, AAAA, …).
    pub qtype: Qtype,
    /// How the query was resolved.
    pub outcome: Outcome,
    /// The DNS response code, when known.
    pub rcode: Option<Rcode>,
    /// The upstream resolver that served the answer, when applicable.
    ///
    /// In v0.1 this is almost always `None` (the forwarding layer does not yet
    /// surface which upstream was used).
    pub upstream: Option<SocketAddr>,
    /// Wall-clock time from receipt to response.
    pub latency: Duration,
}

impl QueryEvent {
    /// Create a new [`QueryEvent`] with the mandatory fields.
    ///
    /// `ts` defaults to the current wall-clock time ([`Clock::now_millis`]); the
    /// pipeline overrides it with the receipt timestamp via [`QueryEvent::with_ts`]
    /// so the recorded time reflects arrival rather than construction. The other
    /// optional fields default to `None` / `Duration::ZERO`; use the `with_*`
    /// builder methods to populate them.
    pub fn new(client: SocketAddr, qname: Name, qtype: Qtype, outcome: Outcome) -> Self {
        Self {
            ts: Clock::now_millis(),
            client,
            qname,
            qtype,
            outcome,
            rcode: None,
            upstream: None,
            latency: Duration::ZERO,
        }
    }

    /// Set the receipt timestamp (epoch milliseconds).
    ///
    /// Captured at request start so the persisted log orders by arrival time.
    #[must_use]
    pub fn with_ts(mut self, ts: i64) -> Self {
        self.ts = ts;
        self
    }

    /// Set the DNS response code.
    #[must_use]
    pub fn with_rcode(mut self, rcode: Rcode) -> Self {
        self.rcode = Some(rcode);
        self
    }

    /// Set which upstream resolver served the answer.
    #[must_use]
    pub fn with_upstream(mut self, upstream: SocketAddr) -> Self {
        self.upstream = Some(upstream);
        self
    }

    /// Set the measured query latency.
    #[must_use]
    pub fn with_latency(mut self, latency: Duration) -> Self {
        self.latency = latency;
        self
    }

    /// Emit a structured [`tracing`] event at `info` level.
    ///
    /// Uses the `sagittarius::query` target so that callers can filter query
    /// logs independently of other log output (e.g. `RUST_LOG=sagittarius::query=info`).
    pub fn emit(&self) {
        tracing::info!(
            target: "sagittarius::query",
            client = %self.client,
            qname = %self.qname,
            qtype = ?self.qtype,
            outcome = %self.outcome,
            rcode = ?self.rcode,
            latency_ms = self.latency.as_millis() as u64,
            "query processed",
        );
    }
}

// ── TelemetrySink ─────────────────────────────────────────────────────────────

/// Bounded capacity of the query-log channel between the hot path and the
/// writer task (E10.4). Large enough to absorb bursts; on overflow events are
/// dropped (and counted) rather than blocking the DNS response path.
pub const QUERY_LOG_CHANNEL_CAPACITY: usize = 4096;

/// The hot-path → writer-task channel for persisting query events, plus the
/// gate and drop counter. Held by [`TelemetrySink`] only when persistence is
/// wired (it is absent in lightweight test sinks).
#[derive(Clone)]
struct QueryLogChannel {
    /// Bounded sender drained by the writer task ([`super::query_log_writer`]).
    sender: tokio::sync::mpsc::Sender<QueryEvent>,
    /// Shared resolver state, read to gate on `query_log_enabled` per query.
    state: std::sync::Arc<crate::resolver::state::ResolverState>,
    /// Count of events dropped because the channel was full.
    dropped: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

/// A thin bundle that wires together the [`super::live_log::LiveLog`] and
/// [`super::stats::Stats`] sinks, and (optionally) the persistent query-log
/// channel.
///
/// This is the single seam called by the pipeline's log step (E6.7).  One call
/// to [`TelemetrySink::record`] emits the structured log event, updates the
/// runtime counters, pushes the event to the live-log ring/broadcast, and —
/// when query logging is enabled — enqueues it for durable persistence
/// **without ever awaiting** (a full channel drops + counts instead).
///
/// Cheap to clone — every field is reference-counted.
#[derive(Clone)]
pub struct TelemetrySink {
    /// The live-log ring buffer and broadcast channel.
    pub live_log: std::sync::Arc<super::live_log::LiveLog>,
    /// The runtime counters and top-N accumulators.
    pub stats: std::sync::Arc<super::stats::Stats>,
    /// Persistence channel + gate; `None` in test sinks that don't persist.
    query_log: Option<QueryLogChannel>,
}

impl TelemetrySink {
    /// Create a new [`TelemetrySink`] without query-log persistence.
    ///
    /// Use [`TelemetrySink::with_query_log`] to attach the writer channel.
    pub fn new(
        live_log: std::sync::Arc<super::live_log::LiveLog>,
        stats: std::sync::Arc<super::stats::Stats>,
    ) -> Self {
        Self {
            live_log,
            stats,
            query_log: None,
        }
    }

    /// Attach the persistent query-log channel.
    ///
    /// `sender` is the bounded channel drained by the writer task; `state`
    /// supplies the `query_log_enabled` gate read per query on the hot path.
    #[must_use]
    pub fn with_query_log(
        mut self,
        sender: tokio::sync::mpsc::Sender<QueryEvent>,
        state: std::sync::Arc<crate::resolver::state::ResolverState>,
    ) -> Self {
        self.query_log = Some(QueryLogChannel {
            sender,
            state,
            dropped: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        });
        self
    }

    /// Number of query events dropped so far because the channel was full.
    ///
    /// Returns `0` when no query-log channel is attached.
    #[must_use]
    pub fn dropped_query_events(&self) -> u64 {
        self.query_log
            .as_ref()
            .map(|ch| ch.dropped.load(std::sync::atomic::Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Record a query event: emit the log line, update stats, enqueue for
    /// persistence (if enabled), and publish to the live-log ring/broadcast.
    ///
    /// Never blocks or awaits: the persistence enqueue is a non-blocking
    /// `try_send`; a full channel drops the event and bumps the drop counter.
    pub fn record(&self, event: QueryEvent) {
        event.emit();
        self.stats.record(&event);
        self.enqueue_for_persistence(&event);
        self.live_log.publish(event);
    }

    /// Enqueue `event` onto the query-log channel when logging is enabled.
    ///
    /// A clone is taken only when there is a channel and the gate is open, so
    /// the common (persisting) path costs one clone and the disabled/test paths
    /// cost nothing.
    fn enqueue_for_persistence(&self, event: &QueryEvent) {
        use std::sync::atomic::Ordering;
        use tokio::sync::mpsc::error::TrySendError;

        let Some(channel) = &self.query_log else {
            return;
        };
        if !channel.state.settings().query_log_enabled {
            return;
        }

        match channel.sender.try_send(event.clone()) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                // Rate-limit the warning: first drop, then every 1000th, so a
                // sustained overload doesn't flood the log.
                let dropped = channel.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                if dropped == 1 || dropped % 1000 == 0 {
                    tracing::warn!(
                        dropped,
                        "query-log channel full; dropping events (writer task is behind)"
                    );
                }
            }
            Err(TrySendError::Closed(_)) => {
                // The writer task has exited (e.g. during shutdown). Nothing to
                // do — the live log and stats already captured the event.
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        codec::{header::Rcode, message::Qtype, name::Name},
        resolver::pipeline::Outcome,
        telemetry::{Telemetry, live_log::LiveLog, stats::Stats},
    };
    use std::{net::SocketAddr, sync::Arc, time::Duration};

    fn make_event(outcome: Outcome) -> QueryEvent {
        let client: SocketAddr = "203.0.113.5:1234".parse().unwrap();
        let qname: Name = "example.com".parse().unwrap();
        QueryEvent::new(client, qname, Qtype::A, outcome)
    }

    // ── emit smoke test ───────────────────────────────────────────────────────

    #[test]
    fn emit_does_not_panic() {
        // Install a subscriber (idempotent across tests).
        let _ = Telemetry::init();

        let event = make_event(Outcome::Forwarded)
            .with_rcode(Rcode::NoError)
            .with_upstream("9.9.9.9:53".parse().unwrap())
            .with_latency(Duration::from_millis(12));

        // Must not panic.
        event.emit();
    }

    // ── builder setters ───────────────────────────────────────────────────────

    #[test]
    fn with_rcode_sets_rcode() {
        let event = make_event(Outcome::Forwarded).with_rcode(Rcode::NoError);
        assert_eq!(event.rcode, Some(Rcode::NoError));
    }

    #[test]
    fn with_upstream_sets_upstream() {
        let upstream: SocketAddr = "1.1.1.1:53".parse().unwrap();
        let event = make_event(Outcome::Forwarded).with_upstream(upstream);
        assert_eq!(event.upstream, Some(upstream));
    }

    #[test]
    fn with_latency_sets_latency() {
        let event = make_event(Outcome::Forwarded).with_latency(Duration::from_millis(42));
        assert_eq!(event.latency, Duration::from_millis(42));
    }

    #[test]
    fn defaults_are_none_and_zero() {
        let event = make_event(Outcome::Cached);
        assert!(event.rcode.is_none());
        assert!(event.upstream.is_none());
        assert_eq!(event.latency, Duration::ZERO);
    }

    #[test]
    fn new_carries_nonzero_ts() {
        // The pipeline relies on every event arriving with a real receipt time.
        let event = make_event(Outcome::Cached);
        assert!(
            event.ts > 1_700_000_000_000,
            "ts must default to a real epoch-ms timestamp: {}",
            event.ts
        );
    }

    #[test]
    fn with_ts_overrides_ts() {
        let event = make_event(Outcome::Cached).with_ts(42);
        assert_eq!(event.ts, 42);
    }

    // ── TelemetrySink.record ──────────────────────────────────────────────────

    #[tokio::test]
    async fn telemetry_sink_record_updates_all() {
        let _ = Telemetry::init();

        let live_log = Arc::new(LiveLog::default());
        let stats = Arc::new(Stats::default());
        let sink = TelemetrySink::new(Arc::clone(&live_log), Arc::clone(&stats));

        let mut rx = live_log.subscribe();

        let event = make_event(Outcome::Forwarded);
        sink.record(event);

        // Stats were updated.
        let snap = stats.snapshot(10);
        assert_eq!(snap.total, 1);
        assert_eq!(snap.forwarded, 1);

        // Live-log received the event.
        let received = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .expect("timeout waiting for broadcast")
            .expect("broadcast channel closed");

        assert_eq!(received.qname.to_string(), "example.com.");
    }

    // ── Query-log channel gating (E10.4) ──────────────────────────────────────

    /// Hydrate a fresh resolver state (query logging enabled by the seed
    /// defaults) for the gating tests.
    async fn hydrate_state() -> (
        tempfile::TempDir,
        Arc<crate::resolver::state::ResolverState>,
    ) {
        let (dir, db) = crate::test_support::temp_db().await;
        let state = crate::resolver::state::ResolverState::hydrate(&db)
            .await
            .expect("hydrate");
        (dir, state)
    }

    #[tokio::test]
    async fn record_enqueues_when_enabled() {
        let (_dir, state) = hydrate_state().await;
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let sink = TelemetrySink::new(Arc::new(LiveLog::default()), Arc::new(Stats::default()))
            .with_query_log(tx, Arc::clone(&state));

        sink.record(make_event(Outcome::Forwarded));

        let queued = rx.try_recv().expect("event must be enqueued when enabled");
        assert_eq!(queued.qname.to_string(), "example.com.");
        assert_eq!(sink.dropped_query_events(), 0);
    }

    #[tokio::test]
    async fn record_full_channel_drops_and_counts_without_blocking() {
        let (_dir, state) = hydrate_state().await;
        // Capacity 1, and we never drain it: the first record fills it, the rest
        // overflow and must be dropped (and counted) rather than blocking.
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let sink = TelemetrySink::new(Arc::new(LiveLog::default()), Arc::new(Stats::default()))
            .with_query_log(tx, Arc::clone(&state));

        for _ in 0..4 {
            // record() is synchronous and must return immediately even though
            // the channel is full — no await, no deadlock.
            sink.record(make_event(Outcome::Forwarded));
        }

        assert_eq!(
            sink.dropped_query_events(),
            3,
            "1 enqueued, 3 dropped on the full channel"
        );
        // Stats still counted every event.
        assert_eq!(sink.stats.snapshot(10).total, 4);
    }

    #[tokio::test]
    async fn record_skips_enqueue_when_disabled_but_stats_and_broadcast_fire() {
        use crate::resolver::state::RuntimeSettings;

        let (_dir, state) = hydrate_state().await;
        // Disable query logging on the live snapshot.
        state.store_settings(RuntimeSettings {
            query_log_enabled: false,
            ..(*state.settings_full()).clone()
        });

        let live_log = Arc::new(LiveLog::default());
        let stats = Arc::new(Stats::default());
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let sink = TelemetrySink::new(Arc::clone(&live_log), Arc::clone(&stats))
            .with_query_log(tx, Arc::clone(&state));

        let mut broadcast = live_log.subscribe();
        sink.record(make_event(Outcome::Cached));

        // Nothing was enqueued for persistence …
        assert!(
            matches!(
                rx.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            ),
            "disabled logging must not enqueue"
        );
        // … but stats and the live broadcast still fired.
        assert_eq!(stats.snapshot(10).total, 1);
        let got = tokio::time::timeout(std::time::Duration::from_secs(1), broadcast.recv())
            .await
            .expect("broadcast timeout")
            .expect("broadcast closed");
        assert_eq!(got.qname.to_string(), "example.com.");
    }
}
