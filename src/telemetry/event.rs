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

/// A thin bundle that wires together the [`super::live_log::LiveLog`] and
/// [`super::stats::Stats`] sinks.
///
/// This is the single seam called by the pipeline's log step (E6.7).  One call
/// to [`TelemetrySink::record`] emits the structured log event, updates the
/// runtime counters, and pushes the event to the live-log ring and broadcast
/// channel.
///
/// Cheap to clone — both inner `Arc`s are reference-counted.
#[derive(Clone)]
pub struct TelemetrySink {
    /// The live-log ring buffer and broadcast channel.
    pub live_log: std::sync::Arc<super::live_log::LiveLog>,
    /// The runtime counters and top-N accumulators.
    pub stats: std::sync::Arc<super::stats::Stats>,
}

impl TelemetrySink {
    /// Create a new [`TelemetrySink`].
    pub fn new(
        live_log: std::sync::Arc<super::live_log::LiveLog>,
        stats: std::sync::Arc<super::stats::Stats>,
    ) -> Self {
        Self { live_log, stats }
    }

    /// Record a query event: emit the log line, update stats, publish to the
    /// live-log ring.
    pub fn record(&self, event: QueryEvent) {
        event.emit();
        self.stats.record(&event);
        self.live_log.publish(event);
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
}
