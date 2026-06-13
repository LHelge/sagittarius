//! Per-upstream health & latency tracking (E15.2, SPEC §7).
//!
//! [`UpstreamHealth`] aggregates, in memory, how each upstream resolver is
//! performing: success/failure counts, an exponentially-weighted moving average
//! (EWMA) of successful-exchange latency, and the most recent error string.
//! It is updated on **every** forward attempt inside
//! [`UpstreamPool::forward`](super::pool::UpstreamPool::forward) using the
//! per-attempt measurements surfaced in E15.1.
//!
//! # Lifetime & sharing
//!
//! The tracker lives on the long-lived [`SharedUpstreamPool`](super::pool::SharedUpstreamPool),
//! **outside** the [`UpstreamPool`](super::pool::UpstreamPool) snapshot that is
//! hot-swapped when the operator edits upstreams — so health history survives a
//! pool rebuild and is only lost on process restart (like
//! [`Stats`](crate::telemetry::Stats)).
//!
//! # Concurrency
//!
//! A single `Mutex<HashMap<…>>` guards the per-upstream rows. The forward path
//! already awaits the network on every query, so this brief, uncontended lock
//! is negligible against that cost; sharding would be premature.

use std::{collections::HashMap, net::SocketAddr, sync::Mutex, time::Duration};

/// Smoothing factor for the latency EWMA: `ewma = α·sample + (1−α)·ewma`.
///
/// `0.2` weights recent samples enough to track a shifting upstream without
/// overreacting to a single slow exchange.
const EWMA_ALPHA: f64 = 0.2;

// ── Per-upstream accumulator ────────────────────────────────────────────────

/// Live counters for one upstream. Internal; [`UpstreamHealthRow`] is the
/// snapshot view exposed to readers.
#[derive(Debug, Default, Clone)]
struct UpstreamStat {
    /// Count of successful exchanges.
    successes: u64,
    /// Count of failed attempts (timeout or transport error).
    failures: u64,
    /// EWMA of successful-exchange latency in milliseconds; `None` until the
    /// first success. Failures never update it (a timeout is not a latency).
    ewma_latency_ms: Option<f64>,
    /// The most recent failure's error string, for operator diagnosis.
    last_error: Option<String>,
}

impl UpstreamStat {
    fn record_success(&mut self, latency: Duration) {
        self.successes += 1;
        let sample = latency.as_secs_f64() * 1000.0;
        self.ewma_latency_ms = Some(match self.ewma_latency_ms {
            Some(prev) => EWMA_ALPHA * sample + (1.0 - EWMA_ALPHA) * prev,
            None => sample,
        });
    }

    fn record_failure(&mut self, error: String) {
        self.failures += 1;
        self.last_error = Some(error);
    }
}

// ── Snapshot row ────────────────────────────────────────────────────────────

/// A point-in-time view of one upstream's health, produced by
/// [`UpstreamHealth::snapshot`]. Consumed by the admin dashboard (E15.3) and
/// the latency-weighted selector (E15.4).
#[derive(Debug, Clone, PartialEq)]
pub struct UpstreamHealthRow {
    /// The upstream resolver's address.
    pub addr: SocketAddr,
    /// Successful exchanges so far.
    pub successes: u64,
    /// Failed attempts so far.
    pub failures: u64,
    /// Fraction of attempts that succeeded (`successes / (successes+failures)`);
    /// `0.0` when no attempts have been made.
    pub success_rate: f64,
    /// EWMA latency in milliseconds; `None` until the first success.
    pub ewma_latency_ms: Option<f64>,
    /// The most recent failure's error string.
    pub last_error: Option<String>,
}

impl UpstreamHealthRow {
    /// Total attempts (successes + failures).
    #[must_use]
    pub fn attempts(&self) -> u64 {
        self.successes + self.failures
    }
}

// ── UpstreamHealth ──────────────────────────────────────────────────────────

/// In-memory per-upstream health tracker. Shared via
/// [`Arc`](std::sync::Arc); resets on restart.
#[derive(Debug, Default)]
pub struct UpstreamHealth {
    rows: Mutex<HashMap<SocketAddr, UpstreamStat>>,
}

impl UpstreamHealth {
    /// Create an empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a successful exchange against `addr` with its measured `latency`.
    pub fn record_success(&self, addr: SocketAddr, latency: Duration) {
        self.rows
            .lock()
            .expect("upstream-health mutex poisoned")
            .entry(addr)
            .or_default()
            .record_success(latency);
    }

    /// Record a failed attempt against `addr`, retaining `error` as the last
    /// error. Does not touch the latency EWMA.
    pub fn record_failure(&self, addr: SocketAddr, error: String) {
        self.rows
            .lock()
            .expect("upstream-health mutex poisoned")
            .entry(addr)
            .or_default()
            .record_failure(error);
    }

    /// Take a snapshot of all tracked upstreams, sorted by address for stable
    /// rendering.
    #[must_use]
    pub fn snapshot(&self) -> Vec<UpstreamHealthRow> {
        let rows = self.rows.lock().expect("upstream-health mutex poisoned");
        let mut out: Vec<UpstreamHealthRow> = rows
            .iter()
            .map(|(&addr, stat)| {
                let attempts = stat.successes + stat.failures;
                let success_rate = if attempts == 0 {
                    0.0
                } else {
                    stat.successes as f64 / attempts as f64
                };
                UpstreamHealthRow {
                    addr,
                    successes: stat.successes,
                    failures: stat.failures,
                    success_rate,
                    ewma_latency_ms: stat.ewma_latency_ms,
                    last_error: stat.last_error.clone(),
                }
            })
            .collect();
        out.sort_unstable_by_key(|r| r.addr);
        out
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().expect("valid socket addr")
    }

    #[test]
    fn success_updates_count_and_latency_for_the_right_upstream() {
        let h = UpstreamHealth::new();
        let a = addr("1.1.1.1:53");
        let b = addr("9.9.9.9:53");

        h.record_success(a, Duration::from_millis(20));
        h.record_success(a, Duration::from_millis(40));
        h.record_success(b, Duration::from_millis(100));

        let snap = h.snapshot();
        assert_eq!(snap.len(), 2);

        let row_a = snap.iter().find(|r| r.addr == a).unwrap();
        assert_eq!(row_a.successes, 2);
        assert_eq!(row_a.failures, 0);
        // First sample seeds the EWMA (20), second pulls it toward 40:
        // 0.2*40 + 0.8*20 = 24.
        let ewma = row_a.ewma_latency_ms.expect("latency recorded");
        assert!((ewma - 24.0).abs() < 1e-9, "ewma was {ewma}");
        assert!((row_a.success_rate - 1.0).abs() < 1e-9);

        let row_b = snap.iter().find(|r| r.addr == b).unwrap();
        assert_eq!(row_b.successes, 1);
        assert_eq!(row_b.ewma_latency_ms, Some(100.0));
    }

    #[test]
    fn failure_increments_count_and_records_error_without_touching_latency() {
        let h = UpstreamHealth::new();
        let a = addr("1.1.1.1:53");

        h.record_success(a, Duration::from_millis(30));
        h.record_failure(a, "upstream UDP query timed out".to_owned());

        let snap = h.snapshot();
        let row = &snap[0];
        assert_eq!(row.successes, 1);
        assert_eq!(row.failures, 1);
        assert_eq!(row.attempts(), 2);
        // Latency EWMA is unchanged by the failure (still the single success).
        assert_eq!(row.ewma_latency_ms, Some(30.0));
        assert_eq!(
            row.last_error.as_deref(),
            Some("upstream UDP query timed out")
        );
        assert!((row.success_rate - 0.5).abs() < 1e-9);
    }

    #[test]
    fn failure_only_upstream_has_no_latency() {
        let h = UpstreamHealth::new();
        let a = addr("8.8.8.8:53");
        h.record_failure(a, "boom".to_owned());

        let snap = h.snapshot();
        let row = &snap[0];
        assert_eq!(row.successes, 0);
        assert_eq!(row.failures, 1);
        assert_eq!(row.ewma_latency_ms, None);
        assert_eq!(row.success_rate, 0.0);
    }

    #[test]
    fn empty_snapshot_is_empty() {
        assert!(UpstreamHealth::new().snapshot().is_empty());
    }
}
