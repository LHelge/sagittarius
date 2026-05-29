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

use std::{fmt, sync::Arc, time::Duration};

use tokio_util::task::TaskTracker;
use tracing::warn;

use crate::codec::message::Question;

use super::{DEFAULT_QUERY_TIMEOUT, Error, ForwardResult, Result, UpstreamClient, UpstreamConfig};

// ── Default constants ─────────────────────────────────────────────────────────

/// Default number of additional upstreams to try after the first failure.
///
/// Combined with [`DEFAULT_QUERY_TIMEOUT`] (2 s), this keeps the worst-case
/// latency comfortably under the E6.4 pipeline timeout of 5 s: 2 × 2 s = 4 s.
pub const DEFAULT_FAILOVER_BUDGET: usize = 1;

// ── UpstreamSelector trait ────────────────────────────────────────────────────

/// Strategy for ordering upstream indices when forwarding a query.
///
/// The pool calls [`order`](UpstreamSelector::order) once per query and
/// iterates the returned vec, trying each upstream in that order up to the
/// `max_attempts` budget.
///
/// Implement this trait to plug in custom strategies (round-robin, weighted,
/// etc.) without changing any forwarding logic.
pub trait UpstreamSelector: fmt::Debug + Send + Sync {
    /// Return the order in which to try `count` upstreams.
    ///
    /// The return value must be a permutation of `0..count`
    /// (implementations may return a shorter vec to further limit attempts,
    /// but the pool already enforces `max_attempts`).  Returning an empty
    /// vec for `count == 0` is required.
    fn order(&self, count: usize) -> Vec<usize>;
}

// ── RandomSelector ────────────────────────────────────────────────────────────

/// Production selector: returns a uniformly shuffled permutation of `0..count`.
///
/// This is the default strategy.  Each query sees a fresh shuffle, so load is
/// spread randomly across all healthy upstreams over time.
#[derive(Debug, Default, Clone)]
pub struct RandomSelector;

impl UpstreamSelector for RandomSelector {
    fn order(&self, count: usize) -> Vec<usize> {
        use rand::seq::SliceRandom as _;

        let mut indices: Vec<usize> = (0..count).collect();
        indices.shuffle(&mut rand::rng());
        indices
    }
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
    /// `failover_budget + 1` — the total number of upstreams to try.
    max_attempts: usize,
    per_attempt_timeout: Duration,
}

impl fmt::Debug for UpstreamPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpstreamPool")
            .field("clients", &self.clients.len())
            .field("max_attempts", &self.max_attempts)
            .field("per_attempt_timeout", &self.per_attempt_timeout)
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

    /// Forward `question` to the best available upstream, failing over on
    /// error or timeout.
    ///
    /// Returns the first successful [`ForwardResult`].  If all attempted
    /// upstreams fail (or the pool is empty), returns
    /// [`Error::AllUpstreamsFailed`] with the number of attempts made.
    pub async fn forward(&self, question: &Question) -> Result<ForwardResult> {
        if self.clients.is_empty() {
            return Err(Error::AllUpstreamsFailed { attempts: 0 });
        }

        let order = self.selector.order(self.clients.len());
        let mut attempts: usize = 0;

        for idx in order.iter().take(self.max_attempts) {
            let Some(client) = self.clients.get(*idx) else {
                continue;
            };

            attempts += 1;

            match client.forward(question, self.per_attempt_timeout).await {
                Ok(result) => return Ok(result),
                Err(e) => {
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
}

impl fmt::Debug for SharedUpstreamPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedUpstreamPool")
            .field("pool", &*self.inner.load())
            .finish()
    }
}

impl SharedUpstreamPool {
    /// Wrap an [`UpstreamPool`] in a [`SharedUpstreamPool`].
    pub fn new(pool: UpstreamPool) -> Self {
        Self {
            inner: arc_swap::ArcSwap::from_pointee(pool),
        }
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
        pool.forward(question).await
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, time::Duration};

    use hickory_net::proto::op::{Message, MessageType, ResponseCode};
    use hickory_net::proto::rr::{Name, RData, Record, rdata::A};
    use tokio::net::UdpSocket;
    use tokio::time::timeout;
    use tokio_util::task::TaskTracker;

    use super::*;
    use crate::codec::message::{Qclass, Qtype, Question};
    use crate::resolver::upstream::{UpstreamConfig, UpstreamTransport};

    // ── Mock UDP upstream ─────────────────────────────────────────────────────

    /// Spawn a UDP mock upstream on an ephemeral port.
    ///
    /// For each datagram received the request is parsed with hickory, handed to
    /// `handler`, and — if it returns `Some(response)` — the response is
    /// serialised and sent back.  Returning `None` simulates a dead / silent
    /// upstream (nothing is sent, so `forward()` will time out).
    async fn spawn_mock_udp<F>(mut handler: F) -> SocketAddr
    where
        F: FnMut(Message) -> Option<Message> + Send + 'static,
    {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 512];
            loop {
                let Ok((len, peer)) = sock.recv_from(&mut buf).await else {
                    break;
                };
                let Ok(req) = Message::from_vec(&buf[..len]) else {
                    continue;
                };
                if let Some(resp) = handler(req)
                    && let Ok(resp_bytes) = resp.to_vec()
                {
                    let _ = sock.send_to(&resp_bytes, peer).await;
                }
            }
        });

        addr
    }

    /// Positive A-record mock handler.
    fn positive_a_handler(req: Message) -> Option<Message> {
        let mut resp = req.clone();
        resp.metadata.message_type = MessageType::Response;
        resp.metadata.response_code = ResponseCode::NoError;
        let name = Name::from_ascii("example.com.").unwrap();
        let rdata = RData::A(A::new(93, 184, 216, 34));
        resp.add_answer(Record::from_rdata(name, 300, rdata));
        Some(resp)
    }

    /// NXDOMAIN mock handler.
    fn nxdomain_handler(req: Message) -> Option<Message> {
        let mut resp = req.clone();
        resp.metadata.message_type = MessageType::Response;
        resp.metadata.response_code = ResponseCode::NXDomain;
        Some(resp)
    }

    /// Silent mock handler (simulates a timeout).
    fn silent_handler(_req: Message) -> Option<Message> {
        None
    }

    /// Build the stock question used in every test: `example.com. A IN`.
    fn stock_question() -> Question {
        Question {
            name: "example.com".parse().unwrap(),
            qtype: Qtype::A,
            qclass: Qclass::In,
        }
    }

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
        fn order(&self, count: usize) -> Vec<usize> {
            (0..count).collect()
        }
    }

    // ── Selector unit tests (no network) ─────────────────────────────────────

    #[test]
    fn random_selector_order_is_permutation() {
        let sel = RandomSelector;

        // order(0) must be empty
        assert_eq!(sel.order(0), Vec::<usize>::new());

        // order(3) must always be a permutation of 0..3
        for _ in 0..100 {
            let mut o = sel.order(3);
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
            let o = sel.order(count);
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
        assert_eq!(sel.order(0), Vec::<usize>::new());
        assert_eq!(sel.order(1), vec![0]);
        assert_eq!(sel.order(3), vec![0, 1, 2]);
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

        let result = timeout(Duration::from_secs(5), pool.forward(&stock_question()))
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
        let silent_addr = spawn_mock_udp(silent_handler).await;
        let answer_addr = spawn_mock_udp(positive_a_handler).await;

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

        let result = timeout(Duration::from_secs(5), pool.forward(&stock_question()))
            .await
            .expect("safety timeout")
            .expect("forward must succeed after failover");

        assert!(
            !result.is_negative,
            "failover result must be a positive answer"
        );
    }

    // ── Pool: all-fail ────────────────────────────────────────────────────────

    /// Both upstreams are silent; budget = 1 → AllUpstreamsFailed { attempts: 2 }.
    #[tokio::test]
    async fn all_fail_returns_all_upstreams_failed() {
        let s0 = spawn_mock_udp(silent_handler).await;
        let s1 = spawn_mock_udp(silent_handler).await;

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

        let result = timeout(Duration::from_secs(5), pool.forward(&stock_question()))
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
        let s0 = spawn_mock_udp(silent_handler).await;
        let s1 = spawn_mock_udp(silent_handler).await;
        let s2 = spawn_mock_udp(silent_handler).await;

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

        let result = timeout(Duration::from_secs(5), pool.forward(&stock_question()))
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
        let positive_addr = spawn_mock_udp(positive_a_handler).await;
        let nxdomain_addr = spawn_mock_udp(nxdomain_handler).await;

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
