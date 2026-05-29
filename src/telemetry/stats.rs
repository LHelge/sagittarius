//! Runtime counters and top-N accumulators for DNS query statistics.
//!
//! [`Stats`] collects per-query telemetry in-memory with no persistence.  All
//! data is lost on restart — the design is intentional for v0.1 (SPEC §9
//! "runtime-only").
//!
//! # Thread-safety
//!
//! Scalar counters use [`std::sync::atomic::AtomicU64`] with `Relaxed` ordering
//! (counter increments do not need to synchronise with other memory accesses;
//! only eventual visibility is required).  Per-domain and per-client maps use
//! `std::sync::Mutex<HashMap<…>>` — correctness over lock-free in v0.1.
//!
//! [`Stats`] is `Send + Sync` and intended to be shared via [`std::sync::Arc`].

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use super::event::QueryEvent;
use crate::resolver::pipeline::Outcome;

// ── StatsSnapshot ─────────────────────────────────────────────────────────────

/// A point-in-time copy of the runtime counters and top-N lists.
///
/// Produced by [`Stats::snapshot`].
#[derive(Debug, Clone)]
pub struct StatsSnapshot {
    /// Total number of queries processed.
    pub total: u64,
    /// Number of queries that were blocked (admin or blocklist).
    pub blocked: u64,
    /// Number of queries answered from the moka cache.
    pub cached: u64,
    /// Number of queries forwarded to an upstream resolver.
    pub forwarded: u64,
    /// Fraction of queries that were blocked: `blocked / total` (0.0 when total == 0).
    pub blocked_ratio: f64,
    /// Top-N queried domain names, sorted by descending count (then by name for ties).
    pub top_domains: Vec<(String, u64)>,
    /// Top-N querying client IP addresses, sorted by descending count (then by address for ties).
    pub top_clients: Vec<(IpAddr, u64)>,
}

// ── Stats ─────────────────────────────────────────────────────────────────────

/// In-memory runtime counters and top-N accumulators.
///
/// All state is reset when the process restarts.  Share via [`std::sync::Arc`].
pub struct Stats {
    total: AtomicU64,
    blocked: AtomicU64,
    cached: AtomicU64,
    forwarded: AtomicU64,
    /// Per-domain query count (keyed by the FQDN string).
    domains: Mutex<HashMap<String, u64>>,
    /// Per-client IP query count.
    clients: Mutex<HashMap<IpAddr, u64>>,
}

impl Stats {
    /// Create a new, zeroed [`Stats`].
    pub fn new() -> Self {
        Self {
            total: AtomicU64::new(0),
            blocked: AtomicU64::new(0),
            cached: AtomicU64::new(0),
            forwarded: AtomicU64::new(0),
            domains: Mutex::new(HashMap::new()),
            clients: Mutex::new(HashMap::new()),
        }
    }

    /// Record a single query event.
    ///
    /// Increments the relevant scalar counters and bumps the per-domain and
    /// per-client frequency maps.  All operations are `Relaxed` — only eventual
    /// visibility is needed; there is no happens-before relationship required
    /// with other memory accesses.
    pub fn record(&self, event: &QueryEvent) {
        self.total.fetch_add(1, Ordering::Relaxed);

        if event.outcome.is_blocked() {
            self.blocked.fetch_add(1, Ordering::Relaxed);
        }
        match event.outcome {
            Outcome::Cached => {
                self.cached.fetch_add(1, Ordering::Relaxed);
            }
            Outcome::Forwarded => {
                self.forwarded.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }

        // Per-domain map.
        {
            let mut map = self.domains.lock().expect("domains mutex poisoned");
            *map.entry(event.qname.to_string()).or_insert(0) += 1;
        }

        // Per-client map.
        {
            let mut map = self.clients.lock().expect("clients mutex poisoned");
            *map.entry(event.client.ip()).or_insert(0) += 1;
        }
    }

    /// Take a point-in-time snapshot of the counters and top-N lists.
    ///
    /// `top_n` controls how many entries appear in [`StatsSnapshot::top_domains`]
    /// and [`StatsSnapshot::top_clients`].  Pass `0` to get empty lists.
    ///
    /// Ties in frequency are broken deterministically: domains are compared by
    /// their string key; client IPs are compared by their canonical string
    /// representation (`IpAddr`'s natural ordering is by numeric value, which is
    /// deterministic and stable).
    pub fn snapshot(&self, top_n: usize) -> StatsSnapshot {
        let total = self.total.load(Ordering::Relaxed);
        let blocked = self.blocked.load(Ordering::Relaxed);
        let cached = self.cached.load(Ordering::Relaxed);
        let forwarded = self.forwarded.load(Ordering::Relaxed);

        let blocked_ratio = if total == 0 {
            0.0_f64
        } else {
            blocked as f64 / total as f64
        };

        let top_domains = {
            let map = self.domains.lock().expect("domains mutex poisoned");
            let mut pairs: Vec<(String, u64)> = map.iter().map(|(k, &v)| (k.clone(), v)).collect();
            // Sort: primary = descending count; secondary = ascending name (deterministic).
            pairs.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            pairs.truncate(top_n);
            pairs
        };

        let top_clients = {
            let map = self.clients.lock().expect("clients mutex poisoned");
            let mut pairs: Vec<(IpAddr, u64)> = map.iter().map(|(k, &v)| (*k, v)).collect();
            // Sort: primary = descending count; secondary = ascending IP (deterministic).
            pairs.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            pairs.truncate(top_n);
            pairs
        };

        StatsSnapshot {
            total,
            blocked,
            cached,
            forwarded,
            blocked_ratio,
            top_domains,
            top_clients,
        }
    }
}

impl Default for Stats {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        codec::{message::Qtype, name::Name},
        resolver::pipeline::Outcome,
        telemetry::event::QueryEvent,
    };
    use std::net::SocketAddr;

    fn make_event(domain: &str, client: &str, outcome: Outcome) -> QueryEvent {
        let client: SocketAddr = client.parse().unwrap();
        let qname: Name = domain.parse().unwrap();
        QueryEvent::new(client, qname, Qtype::A, outcome)
    }

    // ── Scalar counters ───────────────────────────────────────────────────────

    /// Record a mix: 2 blocked (1 by admin, 1 by blocklist), 1 cached, 1 forwarded.
    /// Asserts total == 4, blocked == 2, cached == 1, forwarded == 1,
    /// blocked_ratio == 0.5.
    #[test]
    fn counters_mixed_outcomes() {
        let stats = Stats::new();

        stats.record(&make_event(
            "a.test",
            "203.0.113.1:1000",
            Outcome::BlockedByAdmin,
        ));
        stats.record(&make_event(
            "b.test",
            "203.0.113.2:1001",
            Outcome::BlockedByBlocklist,
        ));
        stats.record(&make_event("c.test", "203.0.113.3:1002", Outcome::Cached));
        stats.record(&make_event(
            "d.test",
            "203.0.113.4:1003",
            Outcome::Forwarded,
        ));

        let snap = stats.snapshot(10);

        assert_eq!(snap.total, 4);
        assert_eq!(snap.blocked, 2);
        assert_eq!(snap.cached, 1);
        assert_eq!(snap.forwarded, 1);

        // Compare as integer per-mille to avoid float equality pitfalls.
        let ratio_permille = (snap.blocked_ratio * 1000.0).round() as u64;
        assert_eq!(ratio_permille, 500, "blocked_ratio should be 0.5");
    }

    #[test]
    fn blocked_ratio_zero_when_no_queries() {
        let stats = Stats::new();
        let snap = stats.snapshot(10);
        assert_eq!(snap.total, 0);
        // Exact comparison to 0.0 is safe here — it is set explicitly, not computed.
        #[allow(clippy::float_cmp)]
        {
            assert_eq!(snap.blocked_ratio, 0.0_f64);
        }
    }

    // ── Top-N domains ─────────────────────────────────────────────────────────

    /// Record several events across a few domains with different frequencies;
    /// assert snapshot(2).top_domains lists the two most frequent in descending
    /// order with correct counts.
    #[test]
    fn top_domains_sorted_by_count() {
        let stats = Stats::new();

        // popular.test: 4 queries
        for _ in 0..4 {
            stats.record(&make_event(
                "popular.test",
                "10.0.0.1:1000",
                Outcome::Forwarded,
            ));
        }
        // medium.test: 2 queries
        for _ in 0..2 {
            stats.record(&make_event(
                "medium.test",
                "10.0.0.1:1001",
                Outcome::Forwarded,
            ));
        }
        // rare.test: 1 query
        stats.record(&make_event(
            "rare.test",
            "10.0.0.1:1002",
            Outcome::Forwarded,
        ));

        let snap = stats.snapshot(2);

        assert_eq!(snap.top_domains.len(), 2);
        // Highest count first.
        assert_eq!(snap.top_domains[0].0, "popular.test.");
        assert_eq!(snap.top_domains[0].1, 4);
        assert_eq!(snap.top_domains[1].0, "medium.test.");
        assert_eq!(snap.top_domains[1].1, 2);
    }

    // ── Top-N clients ─────────────────────────────────────────────────────────

    /// Record events from several clients with different frequencies; assert
    /// snapshot(2).top_clients lists the two most active in descending order.
    #[test]
    fn top_clients_sorted_by_count() {
        let stats = Stats::new();

        // 10.0.0.1: 3 queries
        for _ in 0..3 {
            stats.record(&make_event("x.test", "10.0.0.1:1000", Outcome::Forwarded));
        }
        // 10.0.0.2: 5 queries
        for _ in 0..5 {
            stats.record(&make_event("y.test", "10.0.0.2:1001", Outcome::Forwarded));
        }
        // 10.0.0.3: 1 query
        stats.record(&make_event("z.test", "10.0.0.3:1002", Outcome::Forwarded));

        let snap = stats.snapshot(2);

        assert_eq!(snap.top_clients.len(), 2);
        // 10.0.0.2 has the most queries.
        assert_eq!(snap.top_clients[0].0, "10.0.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(snap.top_clients[0].1, 5);
        assert_eq!(snap.top_clients[1].0, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(snap.top_clients[1].1, 3);
    }

    /// When counts tie, domain names break the tie alphabetically (ascending).
    #[test]
    fn top_domains_tie_broken_by_name() {
        let stats = Stats::new();

        // Two domains with the same count.
        stats.record(&make_event(
            "zebra.test",
            "10.0.0.1:1000",
            Outcome::Forwarded,
        ));
        stats.record(&make_event(
            "apple.test",
            "10.0.0.1:1001",
            Outcome::Forwarded,
        ));

        let snap = stats.snapshot(2);
        assert_eq!(snap.top_domains.len(), 2);
        // "apple.test." sorts before "zebra.test." when counts are equal.
        assert_eq!(snap.top_domains[0].0, "apple.test.");
        assert_eq!(snap.top_domains[1].0, "zebra.test.");
    }
}
