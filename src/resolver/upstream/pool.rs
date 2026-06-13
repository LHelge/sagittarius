//! Upstream pool: random-selection + failover across multiple [`UpstreamClient`]s.
//!
//! The pool is an **immutable snapshot** — built once from a slice of
//! [`UpstreamConfig`]s, shared via [`Arc`], and replaced wholesale when
//! settings change.  [`SharedUpstreamPool`] wraps the snapshot in an
//! [`arc_swap::ArcSwap`] so a settings change can swap the pool atomically
//! while in-flight queries continue on the old snapshot.
//!
//! # Selection and failover
//!
//! The [`UpstreamSelector`] trait decouples the ordering strategy from the
//! forwarding logic.  The default [`RandomSelector`] shuffles the upstream
//! indices uniformly; future strategies (round-robin, weighted, etc.) can be
//! plugged in without touching the pool.
//!
//! The pool tries upstreams in the order returned by the selector, stopping
//! as soon as one succeeds.  It respects the `failover_budget` — the number
//! of *additional* upstreams to try after the first — so the worst-case
//! latency is bounded.

use std::{collections::HashMap, fmt, net::SocketAddr, sync::Arc, time::Duration};

use tokio::task::JoinSet;
use tokio_util::task::TaskTracker;
use tracing::warn;

use crate::codec::message::Question;

use super::{
    DEFAULT_QUERY_TIMEOUT, Error, ForwardResult, Result, UpstreamClient, UpstreamConfig,
    health::UpstreamHealth,
};

// ── Default constants ─────────────────────────────────────────────────────────

/// Default number of additional upstreams to try after the first failure.
///
/// Combined with [`DEFAULT_QUERY_TIMEOUT`] (2 s), this keeps the worst-case
/// latency comfortably under the E6.4 pipeline timeout of 5 s: 2 × 2 s = 4 s.
pub const DEFAULT_FAILOVER_BUDGET: usize = 1;

// ── Per-upstream observation ────────────────────────────────────────────────

/// The health signal a [`UpstreamSelector`] sees for one upstream when ordering
/// a single query (E15.4). Built per-query by the pool from the shared
/// [`UpstreamHealth`] tracker; index in the slice matches the upstream index.
#[derive(Debug, Clone, Copy)]
pub struct UpstreamObservation {
    /// EWMA latency in milliseconds; `None` until the first success.
    pub ewma_latency_ms: Option<f64>,
    /// Success fraction in `[0, 1]`; `0.0` when never attempted.
    pub success_rate: f64,
    /// Total attempts so far. `0` marks a never-tried upstream, which
    /// health-aware selectors should still explore.
    pub attempts: u64,
}

// ── UpstreamSelector trait ────────────────────────────────────────────────────

/// Strategy for ordering upstream indices when forwarding a query.
///
/// The pool calls [`order`](UpstreamSelector::order) once per query with one
/// [`UpstreamObservation`] per upstream (same index order as the pool's
/// clients) and tries each upstream in the returned order, up to the
/// `max_attempts` budget (sequential) or fan-out (parallel).
///
/// Implement this trait to plug in custom strategies without changing any
/// forwarding logic. Strategies that ignore health (e.g. [`RandomSelector`])
/// use only the slice length.
pub trait UpstreamSelector: fmt::Debug + Send + Sync {
    /// Return the order in which to try the upstreams.
    ///
    /// The return value must be a permutation of `0..upstreams.len()`.
    /// Returning an empty vec for an empty slice is required.
    fn order(&self, upstreams: &[UpstreamObservation]) -> Vec<usize>;
}

// ── RandomSelector ────────────────────────────────────────────────────────────

/// Default selector: a uniformly shuffled permutation, ignoring health.
///
/// Each query sees a fresh shuffle, so load is spread randomly across all
/// upstreams over time.
#[derive(Debug, Default, Clone)]
pub struct RandomSelector;

impl UpstreamSelector for RandomSelector {
    fn order(&self, upstreams: &[UpstreamObservation]) -> Vec<usize> {
        use rand::seq::SliceRandom as _;

        let mut indices: Vec<usize> = (0..upstreams.len()).collect();
        indices.shuffle(&mut rand::rng());
        indices
    }
}

// ── LatencyWeightedSelector ─────────────────────────────────────────────────

/// Health-aware selector: a weighted-random permutation biased toward faster,
/// more reliable upstreams (E15.4).
///
/// Each upstream's weight is `success / latency`, so lower-latency and
/// higher-success upstreams are likelier to be tried first — while the
/// randomness still spreads load and keeps exploring. Never-tried upstreams get
/// an optimistic baseline so they are not starved, and a failing upstream keeps
/// a small floor weight so it is occasionally retried (recovery).
///
/// The ordering remains a full permutation, so sequential failover still walks
/// every upstream if the leaders fail.
#[derive(Debug, Default, Clone)]
pub struct LatencyWeightedSelector;

impl LatencyWeightedSelector {
    /// Optimistic latency (ms) assumed for a never-measured upstream, so it is
    /// explored rather than starved.
    const BASELINE_MS: f64 = 50.0;
    /// Floor on latency to avoid divide-by-zero / runaway weights.
    const MIN_LATENCY_MS: f64 = 1.0;
    /// Floor on success so a currently-failing upstream is still retried.
    const MIN_SUCCESS: f64 = 0.05;

    /// The selection weight for one upstream: higher = tried sooner.
    fn weight(o: &UpstreamObservation) -> f64 {
        let latency = o
            .ewma_latency_ms
            .unwrap_or(Self::BASELINE_MS)
            .max(Self::MIN_LATENCY_MS);
        // A never-tried upstream is treated as fully healthy (explore it).
        let success = if o.attempts == 0 {
            1.0
        } else {
            o.success_rate.max(Self::MIN_SUCCESS)
        };
        success / latency
    }
}

impl UpstreamSelector for LatencyWeightedSelector {
    fn order(&self, upstreams: &[UpstreamObservation]) -> Vec<usize> {
        let weights: Vec<f64> = upstreams.iter().map(Self::weight).collect();
        weighted_permutation(&weights)
    }
}

/// Produce a permutation of `0..weights.len()` by repeated weighted selection
/// without replacement (weight ∝ probability of being picked next). An
/// all-zero (or empty) weight set falls back to the natural order for the
/// remainder.
fn weighted_permutation(weights: &[f64]) -> Vec<usize> {
    use rand::RngExt as _;

    let n = weights.len();
    let mut remaining: Vec<usize> = (0..n).collect();
    let mut order = Vec::with_capacity(n);
    let mut rng = rand::rng();

    while !remaining.is_empty() {
        let total: f64 = remaining.iter().map(|&i| weights[i]).sum();
        // Weights are finite and non-negative, so `total <= 0.0` means every
        // remaining weight is zero — fall back to the natural order.
        if total <= 0.0 {
            order.append(&mut remaining);
            break;
        }
        let mut pick = rng.random::<f64>() * total;
        let mut chosen = remaining.len() - 1; // guard against fp rounding
        for (pos, &i) in remaining.iter().enumerate() {
            pick -= weights[i];
            if pick <= 0.0 {
                chosen = pos;
                break;
            }
        }
        order.push(remaining.remove(chosen));
    }
    order
}

// ── UpstreamPool ──────────────────────────────────────────────────────────────

/// An immutable snapshot of connected upstream clients with a selector and
/// failover budget.
///
/// Build via [`UpstreamPool::connect`] (or the convenience wrapper
/// [`UpstreamPool::connect_with_defaults`]) at startup or whenever the
/// upstream configuration changes.  Share via [`SharedUpstreamPool`] for
/// hot-swap capability.
pub struct UpstreamPool {
    clients: Vec<UpstreamClient>,
    selector: Arc<dyn UpstreamSelector>,
    /// `failover_budget + 1` — the total number of upstreams to try in
    /// sequential mode.
    max_attempts: usize,
    per_attempt_timeout: Duration,
    /// When `Some(n)`, forward in **parallel** mode: race the first `n`
    /// upstreams (in selector order) concurrently and take the first success
    /// (E15.4). `None` is the default sequential-failover mode.
    parallel_fanout: Option<usize>,
}

impl fmt::Debug for UpstreamPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpstreamPool")
            .field("clients", &self.clients.len())
            .field("max_attempts", &self.max_attempts)
            .field("per_attempt_timeout", &self.per_attempt_timeout)
            .field("parallel_fanout", &self.parallel_fanout)
            .finish_non_exhaustive()
    }
}

impl UpstreamPool {
    /// Connect to every upstream in `configs`, registering each background
    /// driver future on `tracker` for graceful drain.
    ///
    /// Upstreams that fail to connect are **skipped with a warning** so the
    /// service can still start when, for example, a DoT endpoint is momentarily
    /// unreachable.  An empty pool is valid; its [`forward`](Self::forward)
    /// returns [`Error::AllUpstreamsFailed`] immediately with `attempts: 0`.
    pub async fn connect(
        configs: &[UpstreamConfig],
        tracker: &TaskTracker,
        selector: Arc<dyn UpstreamSelector>,
        failover_budget: usize,
        per_attempt_timeout: Duration,
    ) -> Self {
        let mut clients = Vec::with_capacity(configs.len());

        for cfg in configs {
            match UpstreamClient::connect(cfg).await {
                Ok((client, bg)) => {
                    tracker.spawn(bg);
                    clients.push(client);
                }
                Err(e) => {
                    warn!(
                        transport = %cfg.transport,
                        addr = %cfg.addr,
                        error = %e,
                        "upstream failed to connect, skipping"
                    );
                }
            }
        }

        Self {
            clients,
            selector,
            max_attempts: failover_budget + 1,
            per_attempt_timeout,
            parallel_fanout: None,
        }
    }

    /// Convenience constructor: uses [`RandomSelector`], [`DEFAULT_FAILOVER_BUDGET`],
    /// and [`DEFAULT_QUERY_TIMEOUT`].
    pub async fn connect_with_defaults(configs: &[UpstreamConfig], tracker: &TaskTracker) -> Self {
        Self::connect(
            configs,
            tracker,
            Arc::new(RandomSelector),
            DEFAULT_FAILOVER_BUDGET,
            DEFAULT_QUERY_TIMEOUT,
        )
        .await
    }

    /// Switch this pool to **parallel** forwarding: race the first `fanout`
    /// upstreams (in selector order) concurrently per query and take the first
    /// success (E15.4). `fanout` is floored at 1. Consuming builder so it
    /// chains after [`connect`](Self::connect); E15.5 calls it when the
    /// operator selects the parallel strategy.
    #[must_use]
    pub fn with_parallel_fanout(mut self, fanout: usize) -> Self {
        self.parallel_fanout = Some(fanout.max(1));
        self
    }

    /// Forward `question` to the best available upstream, failing over on
    /// error or timeout, recording per-attempt health into `health` (E15.2).
    ///
    /// Returns the first successful [`ForwardResult`].  If all attempted
    /// upstreams fail (or the pool is empty), returns
    /// [`Error::AllUpstreamsFailed`] with the number of attempts made.
    ///
    /// Every attempt updates `health`: a success records the answering
    /// upstream's latency, a failure bumps its failure count and last-error.
    /// Per-upstream attribution is only possible here, inside the failover
    /// loop — callers see only the final aggregated result.
    pub async fn forward(
        &self,
        question: &Question,
        health: &UpstreamHealth,
    ) -> Result<ForwardResult> {
        if self.clients.is_empty() {
            return Err(Error::AllUpstreamsFailed { attempts: 0 });
        }

        // Ask the selector for an ordering, giving it the current per-upstream
        // health (E15.4); the slice is index-aligned with `self.clients`.
        let order = self.selector.order(&self.observations(health));

        match self.parallel_fanout {
            Some(fanout) => {
                self.forward_parallel(question, health, &order, fanout)
                    .await
            }
            None => self.forward_sequential(question, health, &order).await,
        }
    }

    /// Build one [`UpstreamObservation`] per client (index-aligned) from the
    /// shared health tracker, for the selector to weigh.
    fn observations(&self, health: &UpstreamHealth) -> Vec<UpstreamObservation> {
        let by_addr: HashMap<SocketAddr, _> = health
            .snapshot()
            .into_iter()
            .map(|row| (row.addr, row))
            .collect();
        self.clients
            .iter()
            .map(|client| match by_addr.get(&client.addr()) {
                Some(row) => UpstreamObservation {
                    ewma_latency_ms: row.ewma_latency_ms,
                    success_rate: row.success_rate,
                    attempts: row.attempts(),
                },
                None => UpstreamObservation {
                    ewma_latency_ms: None,
                    success_rate: 0.0,
                    attempts: 0,
                },
            })
            .collect()
    }

    /// Sequential failover: try upstreams in `order`, one at a time, up to the
    /// `max_attempts` budget, returning the first success.
    async fn forward_sequential(
        &self,
        question: &Question,
        health: &UpstreamHealth,
        order: &[usize],
    ) -> Result<ForwardResult> {
        let mut attempts: usize = 0;

        for idx in order.iter().take(self.max_attempts) {
            let Some(client) = self.clients.get(*idx) else {
                continue;
            };

            attempts += 1;

            match client.forward(question, self.per_attempt_timeout).await {
                Ok(result) => {
                    // Reuse the exchange latency measured by the client (E15.1)
                    // rather than re-timing here.
                    health.record_success(client.addr(), result.latency);
                    return Ok(result);
                }
                Err(e) => {
                    health.record_failure(client.addr(), e.to_string());
                    warn!(
                        upstream_index = idx,
                        transport = %client.transport(),
                        error = %e,
                        "upstream failed, trying next"
                    );
                }
            }
        }

        Err(Error::AllUpstreamsFailed { attempts })
    }

    /// Parallel race: fan out to the first `fanout` upstreams in `order`
    /// concurrently and return the first success, aborting the rest. Each
    /// completed attempt records into `health`; the winner's latency is the
    /// client-measured exchange time (E15.1). Losers are cancelled, so only
    /// attempts that actually finished are recorded.
    async fn forward_parallel(
        &self,
        question: &Question,
        health: &UpstreamHealth,
        order: &[usize],
        fanout: usize,
    ) -> Result<ForwardResult> {
        let mut set: JoinSet<(SocketAddr, Result<ForwardResult>)> = JoinSet::new();
        // UpstreamClient and Question are cheap to clone (refcounted handle /
        // small owned value), letting each attempt run as its own task that the
        // JoinSet aborts on drop once we have a winner.
        for idx in order.iter().take(fanout) {
            let Some(client) = self.clients.get(*idx) else {
                continue;
            };
            let client = client.clone();
            let question = question.clone();
            let timeout = self.per_attempt_timeout;
            set.spawn(async move {
                let result = client.forward(&question, timeout).await;
                (client.addr(), result)
            });
        }

        let mut attempts: usize = 0;
        while let Some(joined) = set.join_next().await {
            let (addr, result) = joined.expect("upstream forward task panicked");
            attempts += 1;
            match result {
                Ok(forward) => {
                    health.record_success(addr, forward.latency);
                    // Dropping `set` aborts the still-running attempts.
                    return Ok(forward);
                }
                Err(e) => {
                    health.record_failure(addr, e.to_string());
                    warn!(
                        upstream = %addr,
                        error = %e,
                        "parallel upstream attempt failed"
                    );
                }
            }
        }

        Err(Error::AllUpstreamsFailed { attempts })
    }

    /// Returns the number of connected clients in this pool.
    pub fn len(&self) -> usize {
        self.clients.len()
    }

    /// Returns `true` if the pool has no connected clients.
    pub fn is_empty(&self) -> bool {
        self.clients.is_empty()
    }

    /// Returns the maximum number of upstreams this pool will try per query
    /// (`failover_budget + 1`).
    pub fn max_attempts(&self) -> usize {
        self.max_attempts
    }
}

// ── SharedUpstreamPool ────────────────────────────────────────────────────────

/// A hot-swappable handle to an [`UpstreamPool`] snapshot.
///
/// Backed by [`arc_swap::ArcSwap`], so readers on the hot path never block
/// and see a consistent snapshot for the lifetime of their query.  E8.9
/// replaces the pool atomically via [`store`](Self::store) when upstream
/// settings change; in-flight queries complete on the old snapshot.
pub struct SharedUpstreamPool {
    inner: arc_swap::ArcSwap<UpstreamPool>,
    /// Per-upstream health, kept *outside* the swapped snapshot so history
    /// survives a pool rebuild on an upstream-config edit (E15.2).
    health: Arc<UpstreamHealth>,
}

impl fmt::Debug for SharedUpstreamPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedUpstreamPool")
            .field("pool", &*self.inner.load())
            .finish()
    }
}

impl SharedUpstreamPool {
    /// Wrap an [`UpstreamPool`] in a [`SharedUpstreamPool`] with a fresh
    /// health tracker.
    pub fn new(pool: UpstreamPool) -> Self {
        Self {
            inner: arc_swap::ArcSwap::from_pointee(pool),
            health: Arc::new(UpstreamHealth::new()),
        }
    }

    /// The shared per-upstream health tracker (E15.2), read by the admin
    /// dashboard (E15.3) and the latency-weighted selector (E15.4).
    pub fn health(&self) -> &Arc<UpstreamHealth> {
        &self.health
    }

    /// Load the current pool snapshot without incrementing the reference count.
    ///
    /// Prefer this for synchronous reads.  For use across an `await` point,
    /// see [`forward`](Self::forward) which takes an owned snapshot internally.
    pub fn load(&self) -> arc_swap::Guard<Arc<UpstreamPool>> {
        self.inner.load()
    }

    /// Atomically replace the pool snapshot.
    ///
    /// In-flight queries on the old snapshot complete normally; new queries
    /// immediately use the new snapshot.
    pub fn store(&self, pool: UpstreamPool) {
        self.inner.store(Arc::new(pool));
    }

    /// Forward `question` using the current pool snapshot.
    ///
    /// Takes an owned `Arc<UpstreamPool>` before the first `.await` so the
    /// snapshot stays alive even if another task calls [`store`](Self::store)
    /// concurrently.
    pub async fn forward(&self, question: &Question) -> Result<ForwardResult> {
        let pool = self.inner.load_full();
        pool.forward(question, &self.health).await
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, time::Duration};

    use tokio::time::timeout;
    use tokio_util::task::TaskTracker;

    use super::*;
    use crate::resolver::upstream::{UpstreamConfig, UpstreamHealth, UpstreamTransport};
    use crate::test_support::{
        mock_udp_upstream, nxdomain_handler, positive_a_handler, silent_handler, stock_question,
    };

    /// Build a UDP [`UpstreamConfig`] pointing at `addr`.
    fn udp_config(addr: SocketAddr) -> UpstreamConfig {
        UpstreamConfig {
            addr,
            transport: UpstreamTransport::Udp,
            tls_server_name: None,
            http_endpoint: None,
        }
    }

    // ── Deterministic test selector ───────────────────────────────────────────

    /// Test selector that always returns indices in order `0, 1, 2, …`
    /// (sequential / deterministic).
    #[derive(Debug)]
    struct SequentialSelector;

    impl UpstreamSelector for SequentialSelector {
        fn order(&self, upstreams: &[UpstreamObservation]) -> Vec<usize> {
            (0..upstreams.len()).collect()
        }
    }

    /// `n` health-neutral observations, for selector tests that only care about
    /// the slice length (Random / Sequential).
    fn obs(n: usize) -> Vec<UpstreamObservation> {
        vec![
            UpstreamObservation {
                ewma_latency_ms: None,
                success_rate: 0.0,
                attempts: 0,
            };
            n
        ]
    }

    // ── Selector unit tests (no network) ─────────────────────────────────────

    #[test]
    fn random_selector_order_is_permutation() {
        let sel = RandomSelector;

        // order(0) must be empty
        assert_eq!(sel.order(&obs(0)), Vec::<usize>::new());

        // order(3) must always be a permutation of 0..3
        for _ in 0..100 {
            let mut o = sel.order(&obs(3));
            o.sort_unstable();
            assert_eq!(o, vec![0, 1, 2]);
        }
    }

    #[test]
    fn random_selector_spread() {
        let sel = RandomSelector;
        let trials = 3000usize;
        let count = 3usize;
        let mut first_tally = vec![0usize; count];

        for _ in 0..trials {
            let o = sel.order(&obs(count));
            first_tally[o[0]] += 1;
        }

        // Each index should appear as first roughly 1/3 of the time.
        // Use a loose bound: between 20% and 47%.
        let lo = (trials as f64 * 0.20) as usize;
        let hi = (trials as f64 * 0.47) as usize;
        for (i, &tally) in first_tally.iter().enumerate() {
            assert!(
                tally >= lo && tally <= hi,
                "index {i} appeared {tally} times as first in {trials} trials \
                 (expected {lo}–{hi})"
            );
        }
    }

    #[test]
    fn sequential_selector_order() {
        let sel = SequentialSelector;
        assert_eq!(sel.order(&obs(0)), Vec::<usize>::new());
        assert_eq!(sel.order(&obs(1)), vec![0]);
        assert_eq!(sel.order(&obs(3)), vec![0, 1, 2]);
    }

    /// The latency-weighted selector must put the faster, healthier upstream
    /// first the large majority of the time, while still returning a full
    /// permutation (statistical, loose bounds — mirrors `random_selector_spread`).
    #[test]
    fn latency_weighted_favors_faster_upstream() {
        let sel = LatencyWeightedSelector;
        // Index 0 is ~40× faster; both fully healthy.
        let upstreams = vec![
            UpstreamObservation {
                ewma_latency_ms: Some(5.0),
                success_rate: 1.0,
                attempts: 100,
            },
            UpstreamObservation {
                ewma_latency_ms: Some(200.0),
                success_rate: 1.0,
                attempts: 100,
            },
        ];

        let trials = 2000usize;
        let mut fast_first = 0usize;
        for _ in 0..trials {
            let order = sel.order(&upstreams);
            // Always a permutation of 0..2.
            assert_eq!(order.len(), 2);
            assert!(order.contains(&0) && order.contains(&1));
            if order[0] == 0 {
                fast_first += 1;
            }
        }

        // Weights 1/5 vs 1/200 ⇒ P(fast first) ≈ 0.98; require a comfortable
        // majority to keep the test non-flaky.
        let lo = (trials as f64 * 0.8) as usize;
        assert!(
            fast_first > lo,
            "fast upstream led {fast_first}/{trials} times (expected > {lo})"
        );
    }

    /// A never-tried upstream (attempts == 0) is treated optimistically, not
    /// starved: with one fast-but-known and one unknown, both still appear.
    #[test]
    fn latency_weighted_explores_unknown_upstream() {
        let sel = LatencyWeightedSelector;
        let upstreams = vec![
            UpstreamObservation {
                ewma_latency_ms: Some(5.0),
                success_rate: 1.0,
                attempts: 100,
            },
            UpstreamObservation {
                ewma_latency_ms: None,
                success_rate: 0.0,
                attempts: 0,
            },
        ];
        let mut unknown_first = 0usize;
        for _ in 0..2000 {
            if sel.order(&upstreams)[0] == 1 {
                unknown_first += 1;
            }
        }
        // The unknown upstream uses the 50ms baseline, so it should still lead a
        // non-trivial fraction of the time (not starved to ~0).
        assert!(
            unknown_first > 50,
            "unknown upstream was starved: led only {unknown_first}/2000"
        );
    }

    /// Parallel mode must return the fastest responder without waiting for a
    /// slow/silent upstream's per-attempt timeout.
    #[tokio::test]
    async fn parallel_returns_fastest_and_ignores_silent() {
        let silent_addr = mock_udp_upstream(silent_handler).await;
        let answer_addr = mock_udp_upstream(positive_a_handler).await;

        let configs = vec![udp_config(silent_addr), udp_config(answer_addr)];
        let tracker = TaskTracker::new();
        // A deliberately generous per-attempt timeout: if parallel waited on the
        // silent upstream, the call would take ~2 s. It must not.
        let pool = UpstreamPool::connect(
            &configs,
            &tracker,
            Arc::new(SequentialSelector),
            1,
            Duration::from_secs(2),
        )
        .await
        .with_parallel_fanout(2);

        let health = UpstreamHealth::new();
        let result = timeout(
            Duration::from_millis(500),
            pool.forward(&stock_question(), &health),
        )
        .await
        .expect("parallel must not block on the silent upstream's timeout")
        .expect("forward must succeed via the fast upstream");

        assert!(!result.is_negative);
        assert_eq!(
            result.upstream, answer_addr,
            "the fast upstream must win the race"
        );

        // The winner recorded a success; the silent attempt was aborted, so it
        // has no completed record.
        let snap = health.snapshot();
        let answer = snap
            .iter()
            .find(|r| r.addr == answer_addr)
            .expect("winner tracked");
        assert_eq!(answer.successes, 1);
    }

    // ── Pool: empty ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn empty_pool_returns_all_failed_attempts_zero() {
        let tracker = TaskTracker::new();
        let pool = UpstreamPool::connect(
            &[],
            &tracker,
            Arc::new(SequentialSelector),
            1,
            Duration::from_millis(150),
        )
        .await;

        assert!(pool.is_empty());
        assert_eq!(pool.len(), 0);

        let result = timeout(
            Duration::from_secs(5),
            pool.forward(&stock_question(), &UpstreamHealth::new()),
        )
        .await
        .expect("safety timeout");

        assert!(
            matches!(result, Err(Error::AllUpstreamsFailed { attempts: 0 })),
            "expected AllUpstreamsFailed {{ attempts: 0 }}, got: {result:?}"
        );
    }

    // ── Pool: success / failover ──────────────────────────────────────────────

    /// Index 0 is silent (times out); index 1 returns a positive A answer.
    /// Pool uses SequentialSelector and budget=1, so both are tried.
    /// Expected: Ok(ForwardResult { is_negative: false }).
    #[tokio::test]
    async fn failover_to_second_upstream_on_timeout() {
        let silent_addr = mock_udp_upstream(silent_handler).await;
        let answer_addr = mock_udp_upstream(positive_a_handler).await;

        let configs = vec![udp_config(silent_addr), udp_config(answer_addr)];
        let tracker = TaskTracker::new();
        let pool = UpstreamPool::connect(
            &configs,
            &tracker,
            Arc::new(SequentialSelector),
            1, // budget = 1 → max_attempts = 2
            Duration::from_millis(150),
        )
        .await;

        assert_eq!(pool.max_attempts(), 2);

        let result = timeout(
            Duration::from_secs(5),
            pool.forward(&stock_question(), &UpstreamHealth::new()),
        )
        .await
        .expect("safety timeout")
        .expect("forward must succeed after failover");

        assert!(
            !result.is_negative,
            "failover result must be a positive answer"
        );
        // E15: the answer is attributed to the upstream that actually responded
        // (the second one), not the silent first attempt.
        assert_eq!(
            result.upstream, answer_addr,
            "must record the upstream that answered after failover"
        );
        assert!(result.latency > Duration::ZERO, "latency must be measured");
    }

    /// `forward` must attribute per-upstream health: the silent upstream gets a
    /// failure (no latency), the answering one a success (with latency).
    #[tokio::test]
    async fn forward_records_per_upstream_health() {
        let silent_addr = mock_udp_upstream(silent_handler).await;
        let answer_addr = mock_udp_upstream(positive_a_handler).await;

        let configs = vec![udp_config(silent_addr), udp_config(answer_addr)];
        let tracker = TaskTracker::new();
        let pool = UpstreamPool::connect(
            &configs,
            &tracker,
            Arc::new(SequentialSelector),
            1,
            Duration::from_millis(150),
        )
        .await;

        let health = UpstreamHealth::new();
        timeout(
            Duration::from_secs(5),
            pool.forward(&stock_question(), &health),
        )
        .await
        .expect("safety timeout")
        .expect("forward succeeds after failover");

        let snap = health.snapshot();

        let silent = snap
            .iter()
            .find(|r| r.addr == silent_addr)
            .expect("silent upstream tracked");
        assert_eq!(silent.failures, 1, "silent upstream recorded a failure");
        assert_eq!(silent.successes, 0);
        assert_eq!(silent.ewma_latency_ms, None, "a failure has no latency");
        assert!(
            silent.last_error.is_some(),
            "failure retains an error string"
        );

        let answer = snap
            .iter()
            .find(|r| r.addr == answer_addr)
            .expect("answering upstream tracked");
        assert_eq!(answer.successes, 1, "answering upstream recorded a success");
        assert_eq!(answer.failures, 0);
        assert!(
            answer.ewma_latency_ms.is_some(),
            "success records a latency"
        );
    }

    // ── Pool: all-fail ────────────────────────────────────────────────────────

    /// Both upstreams are silent; budget = 1 → AllUpstreamsFailed { attempts: 2 }.
    #[tokio::test]
    async fn all_fail_returns_all_upstreams_failed() {
        let s0 = mock_udp_upstream(silent_handler).await;
        let s1 = mock_udp_upstream(silent_handler).await;

        let configs = vec![udp_config(s0), udp_config(s1)];
        let tracker = TaskTracker::new();
        let pool = UpstreamPool::connect(
            &configs,
            &tracker,
            Arc::new(SequentialSelector),
            1, // budget = 1 → max_attempts = 2
            Duration::from_millis(150),
        )
        .await;

        let result = timeout(
            Duration::from_secs(5),
            pool.forward(&stock_question(), &UpstreamHealth::new()),
        )
        .await
        .expect("safety timeout");

        assert!(
            matches!(result, Err(Error::AllUpstreamsFailed { attempts: 2 })),
            "expected AllUpstreamsFailed {{ attempts: 2 }}, got: {result:?}"
        );
    }

    // ── Pool: budget bounds attempts ──────────────────────────────────────────

    /// 3 silent upstreams, budget = 1 → only 2 are tried.
    #[tokio::test]
    async fn budget_bounds_attempts() {
        let s0 = mock_udp_upstream(silent_handler).await;
        let s1 = mock_udp_upstream(silent_handler).await;
        let s2 = mock_udp_upstream(silent_handler).await;

        let configs = vec![udp_config(s0), udp_config(s1), udp_config(s2)];
        let tracker = TaskTracker::new();
        let pool = UpstreamPool::connect(
            &configs,
            &tracker,
            Arc::new(SequentialSelector),
            1, // budget = 1 → max_attempts = 2; third upstream must NOT be tried
            Duration::from_millis(150),
        )
        .await;

        let result = timeout(
            Duration::from_secs(5),
            pool.forward(&stock_question(), &UpstreamHealth::new()),
        )
        .await
        .expect("safety timeout");

        assert!(
            matches!(result, Err(Error::AllUpstreamsFailed { attempts: 2 })),
            "expected AllUpstreamsFailed {{ attempts: 2 }}, got: {result:?}"
        );
    }

    // ── SharedUpstreamPool: swap takes effect ─────────────────────────────────

    /// Pool A returns a positive answer; pool B returns NXDOMAIN.
    /// After `store(pool_b)`, `forward` must observe the new pool.
    #[tokio::test]
    async fn shared_pool_swap_takes_effect() {
        let positive_addr = mock_udp_upstream(positive_a_handler).await;
        let nxdomain_addr = mock_udp_upstream(nxdomain_handler).await;

        let tracker = TaskTracker::new();

        let pool_a = UpstreamPool::connect(
            &[udp_config(positive_addr)],
            &tracker,
            Arc::new(SequentialSelector),
            0, // single attempt
            Duration::from_millis(500),
        )
        .await;

        let pool_b = UpstreamPool::connect(
            &[udp_config(nxdomain_addr)],
            &tracker,
            Arc::new(SequentialSelector),
            0,
            Duration::from_millis(500),
        )
        .await;

        let shared = SharedUpstreamPool::new(pool_a);
        let q = stock_question();

        // Pool A: positive answer.
        let res_a = timeout(Duration::from_secs(5), shared.forward(&q))
            .await
            .expect("safety timeout")
            .expect("pool_a forward must succeed");
        assert!(!res_a.is_negative, "pool_a must return a positive answer");

        // Swap to pool B.
        shared.store(pool_b);

        // Pool B: NXDOMAIN (negative).
        let res_b = timeout(Duration::from_secs(5), shared.forward(&q))
            .await
            .expect("safety timeout")
            .expect("pool_b forward must succeed");
        assert!(res_b.is_negative, "pool_b must return a negative answer");
    }
}
