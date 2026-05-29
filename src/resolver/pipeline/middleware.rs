//! Protective tower middleware for the DNS pipeline: SPEC §5, §6.
//!
//! This module assembles the outermost defence layers that guard the resolution
//! stack from abusive or overloaded clients.  The layers, ordered outermost-first:
//!
//! 1. **[`KeyedRateLimitLayer`]** — per-client-IP rate limit via `governor`.
//!    Denied requests return [`RateLimited`], which the listener maps to REFUSED.
//! 2. **`tower::load_shed::LoadShedLayer`** — sheds requests when the inner
//!    service is not ready.  Yields `Overloaded`, mapped to REFUSED.
//! 3. **`tower::limit::GlobalConcurrencyLimitLayer`** — shared semaphore across
//!    all datagram clones; caps simultaneous in-flight requests.
//! 4. **`tower::timeout::TimeoutLayer`** — per-request deadline.
//!    On expiry yields `Elapsed`, mapped to SERVFAIL.
//!
//! # Cloning semantics
//!
//! [`build_protective_service`] returns a [`tower::util::BoxCloneService`].
//! The caller (the UDP listener, E6.5) clones this service once per datagram.
//! Because:
//! - `KeyedRateLimitLayer` holds an `Arc<DefaultKeyedRateLimiter<IpAddr>>`, all
//!   clones share the same per-IP rate-limit state.
//! - `GlobalConcurrencyLimitLayer` holds an `Arc<Semaphore>`, all clones share
//!   the same concurrency cap.
//!
//! NOTE: the per-IP state in the keyed limiter grows with distinct client IPs.
//! Bounded cleanup is future scope.

use std::{
    future::{Future, ready},
    net::IpAddr,
    num::NonZeroU32,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use tower::{Layer, Service, ServiceBuilder, ServiceExt as _};

use crate::{
    codec::header::Rcode,
    resolver::pipeline::{BoxError, DnsRequest, Outcome, PipelineResponse},
};

// ── RateLimited error ─────────────────────────────────────────────────────────

/// Error returned when a client has exceeded its per-IP rate limit.
///
/// The listener (E6.5) downcasts the [`BoxError`] to this type to decide
/// whether to respond with REFUSED (rate-limited) vs SERVFAIL (timeout/other).
#[derive(Debug)]
pub struct RateLimited;

impl std::fmt::Display for RateLimited {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("per-client rate limit exceeded")
    }
}

impl std::error::Error for RateLimited {}

// ── KeyedRateLimitLayer ───────────────────────────────────────────────────────

/// A [`tower::Layer`] that enforces a per-client-IP token-bucket rate limit.
///
/// Internally holds an `Arc<DefaultKeyedRateLimiter<IpAddr>>` so that all
/// service clones share the same limiter state.  Denied requests immediately
/// return `Err(BoxError)` wrapping [`RateLimited`] without touching the inner
/// service.
pub struct KeyedRateLimitLayer {
    limiter: Arc<DefaultKeyedRateLimiter<IpAddr>>,
}

impl KeyedRateLimitLayer {
    /// Create a new layer from a pre-built (and `Arc`-wrapped) limiter.
    pub fn new(limiter: Arc<DefaultKeyedRateLimiter<IpAddr>>) -> Self {
        Self { limiter }
    }
}

impl<S> Layer<S> for KeyedRateLimitLayer {
    type Service = KeyedRateLimitService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        KeyedRateLimitService {
            limiter: self.limiter.clone(),
            inner,
        }
    }
}

// ── KeyedRateLimitService ─────────────────────────────────────────────────────

/// The service produced by [`KeyedRateLimitLayer`].
#[derive(Clone)]
pub struct KeyedRateLimitService<S> {
    limiter: Arc<DefaultKeyedRateLimiter<IpAddr>>,
    inner: S,
}

impl<S> Service<DnsRequest> for KeyedRateLimitService<S>
where
    S: Service<DnsRequest, Response = PipelineResponse, Error = BoxError> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = PipelineResponse;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<PipelineResponse, BoxError>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: DnsRequest) -> Self::Future {
        let ip = req.client().ip();

        match self.limiter.check_key(&ip) {
            Ok(()) => {
                // Clone-and-replace pattern: move the poll_ready'd service into
                // the future and leave a fresh clone in `self`.
                let clone = self.inner.clone();
                let mut inner = std::mem::replace(&mut self.inner, clone);
                Box::pin(async move { inner.call(req).await })
            }
            Err(_) => Box::pin(ready(Err(Box::new(RateLimited) as BoxError))),
        }
    }
}

// ── ProtectiveConfig ──────────────────────────────────────────────────────────

/// Configuration for the protective middleware stack.
///
/// All limits are global (shared across all datagram clones):
/// - `rate_per_second` / `rate_burst` govern the per-client-IP token bucket.
/// - `concurrency_cap` is enforced via a shared `Arc<Semaphore>`.
/// - `request_timeout` is applied per request by the timeout layer.
#[derive(Debug, Clone)]
pub struct ProtectiveConfig {
    /// Sustained per-client-IP request rate (tokens per second).
    pub rate_per_second: u32,
    /// Burst allowance above the sustained rate.
    pub rate_burst: u32,
    /// Maximum simultaneous in-flight requests across all datagram clones.
    pub concurrency_cap: usize,
    /// Per-request deadline.  Exceeded requests return SERVFAIL.
    pub request_timeout: Duration,
}

impl Default for ProtectiveConfig {
    fn default() -> Self {
        Self {
            rate_per_second: 100,
            rate_burst: 200,
            concurrency_cap: 1024,
            request_timeout: Duration::from_secs(5),
        }
    }
}

// ── build_protective_service ──────────────────────────────────────────────────

/// Assemble the full protective middleware stack around `resolve` and return a
/// [`tower::util::BoxCloneService`] that the listener clones once per datagram.
///
/// Layer order (outermost → innermost):
/// 1. [`KeyedRateLimitLayer`] — per-client-IP rate limit → [`RateLimited`]
/// 2. `LoadShedLayer` — shed when inner not ready → `Overloaded`
/// 3. `GlobalConcurrencyLimitLayer` — global in-flight cap (shared `Arc<Semaphore>`)
/// 4. `TimeoutLayer` — per-request deadline → `Elapsed`
/// 5. `resolve` — the inner decision/forward stack
///
/// The rate-limiter `Arc` and the global concurrency semaphore are constructed
/// once here and shared across all clones of the returned service.
///
/// NOTE: the keyed limiter's per-IP state grows with distinct client IPs;
/// bounded cleanup is future scope.
pub fn build_protective_service<S>(
    config: &ProtectiveConfig,
    resolve: S,
) -> tower::util::BoxCloneService<DnsRequest, PipelineResponse, BoxError>
where
    S: Service<DnsRequest, Response = PipelineResponse, Error = BoxError> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    let nz = |x: u32| NonZeroU32::new(x).expect("rate limit must be non-zero");

    let quota = Quota::per_second(nz(config.rate_per_second)).allow_burst(nz(config.rate_burst));
    let rate_limiter: Arc<DefaultKeyedRateLimiter<IpAddr>> = Arc::new(RateLimiter::keyed(quota));

    ServiceBuilder::new()
        .layer(KeyedRateLimitLayer::new(rate_limiter))
        .layer(tower::load_shed::LoadShedLayer::new())
        .layer(tower::limit::GlobalConcurrencyLimitLayer::new(
            config.concurrency_cap,
        ))
        .layer(tower::timeout::TimeoutLayer::new(config.request_timeout))
        .service(resolve)
        .boxed_clone()
}

// ── classify_rejection ────────────────────────────────────────────────────────

/// Map a protective-middleware error to the wire response policy.
///
/// - [`RateLimited`] → REFUSED (per-client quota exceeded)
/// - `Overloaded` (load-shed) → REFUSED (server temporarily full)
/// - `Elapsed` (timeout) and anything else → SERVFAIL
pub fn classify_rejection(err: &BoxError) -> (Outcome, Rcode) {
    if err.is::<RateLimited>() || err.is::<tower::load_shed::error::Overloaded>() {
        (Outcome::Refused, Rcode::Refused)
    } else {
        // Elapsed and any other error → SERVFAIL.
        (Outcome::Servfail, Rcode::ServFail)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, sync::Arc, time::Duration};

    use bytes::Bytes;
    use tokio::sync::Notify;
    use tower::ServiceExt as _;

    use super::*;
    use crate::{
        codec::{header::Header, message::Query, name::Name, writer::Writer},
        resolver::pipeline::{BoxError, DnsRequest, Outcome, PipelineResponse},
    };

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Build a minimal DNS A-query datagram with the given transaction id.
    fn build_a_query(id: u16, domain: &str) -> Bytes {
        let mut w = Writer::with_capacity(64);
        Header::new(id).with_qdcount(1).with_rd(true).write(&mut w);
        let n: Name = domain.parse().expect("valid name in test helper");
        n.write(&mut w);
        w.write_u16(1u16); // QTYPE A
        w.write_u16(1u16); // QCLASS IN
        w.finish()
    }

    /// Wrap raw datagram bytes as a [`DnsRequest`] from the given client socket.
    fn make_request(raw: Bytes, client: SocketAddr) -> DnsRequest {
        let query = Query::try_from(raw).expect("valid query");
        DnsRequest::new(query, client)
    }

    /// Stub inner service: echoes the raw bytes with `Outcome::Forwarded`.
    fn stub_fn(req: DnsRequest) -> std::future::Ready<Result<PipelineResponse, BoxError>> {
        std::future::ready(Ok(PipelineResponse::new(
            req.raw().clone(),
            Outcome::Forwarded,
        )))
    }

    // ── happy_path ────────────────────────────────────────────────────────────

    /// Under generous limits a request flows through to the stub and returns Ok.
    #[tokio::test]
    async fn happy_path_returns_forwarded() {
        let config = ProtectiveConfig::default();
        let svc = build_protective_service(&config, tower::service_fn(stub_fn));

        let raw = build_a_query(0x0001, "example.com");
        let req = make_request(raw, "10.0.0.1:1234".parse().unwrap());

        let resp = svc.clone().oneshot(req).await.expect("must succeed");
        assert_eq!(resp.outcome, Outcome::Forwarded);
    }

    // ── rate_limit_throttles_one_client_others_pass ───────────────────────────

    /// With burst=1 the first request from 1.1.1.1 passes, a second back-to-back
    /// request from the same IP is rate-limited → classify_rejection → REFUSED.
    /// A request from a different IP 2.2.2.2 still passes — proving per-client keying.
    #[tokio::test]
    async fn rate_limit_throttles_one_client_others_pass() {
        let config = ProtectiveConfig {
            rate_per_second: 1,
            rate_burst: 1,
            concurrency_cap: 1024,
            request_timeout: Duration::from_secs(5),
        };
        let svc = build_protective_service(&config, tower::service_fn(stub_fn));

        let ip1: SocketAddr = "1.1.1.1:1234".parse().unwrap();
        let ip2: SocketAddr = "2.2.2.2:1234".parse().unwrap();

        let raw1 = build_a_query(0x0001, "example.com");
        let raw2 = build_a_query(0x0002, "example.com");
        let raw3 = build_a_query(0x0003, "example.com");

        // First request from 1.1.1.1 must succeed.
        let r1 = svc.clone().oneshot(make_request(raw1, ip1)).await;
        assert!(r1.is_ok(), "first request from 1.1.1.1 must succeed");

        // Second immediate request from 1.1.1.1 must be rate-limited.
        let r2 = svc.clone().oneshot(make_request(raw2, ip1)).await;
        let err = r2.expect_err("second request from 1.1.1.1 must be rate-limited");
        let (outcome, rcode) = classify_rejection(&err);
        assert_eq!(outcome, Outcome::Refused, "rate-limited must be Refused");
        assert_eq!(rcode, Rcode::Refused, "rcode must be Refused");

        // Request from 2.2.2.2 (different IP) must still pass.
        let r3 = svc.clone().oneshot(make_request(raw3, ip2)).await;
        assert!(r3.is_ok(), "request from different IP must still pass");
    }

    // ── timeout_returns_servfail ──────────────────────────────────────────────

    /// A stub that sleeps 500ms under a 50ms deadline is timed out.
    /// classify_rejection maps the Elapsed error to (Servfail, ServFail).
    #[tokio::test]
    async fn timeout_returns_servfail() {
        let config = ProtectiveConfig {
            rate_per_second: 100,
            rate_burst: 200,
            concurrency_cap: 1024,
            request_timeout: Duration::from_millis(50),
        };

        // Slow stub: sleeps longer than the deadline.
        let slow_svc = tower::service_fn(|req: DnsRequest| async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            Ok::<_, BoxError>(PipelineResponse::new(req.raw().clone(), Outcome::Forwarded))
        });

        let svc = build_protective_service(&config, slow_svc);

        let raw = build_a_query(0x0004, "slow.example.com");
        let req = make_request(raw, "10.0.0.2:1234".parse().unwrap());

        let err = svc
            .oneshot(req)
            .await
            .expect_err("slow request must time out");
        let (outcome, rcode) = classify_rejection(&err);
        assert_eq!(outcome, Outcome::Servfail, "timeout must be Servfail");
        assert_eq!(rcode, Rcode::ServFail, "rcode must be ServFail");
    }

    // ── concurrency_load_shed_returns_refused ─────────────────────────────────

    /// With concurrency_cap=1 and a blocking stub:
    /// - Request A grabs the only permit and is in-flight.
    /// - Request B arrives while A is still in-flight and is load-shed → REFUSED.
    ///
    /// A `Notify` gates the stub so A holds the permit until we tell it to proceed.
    /// The test is staggered: B is started after a short yield to ensure A holds
    /// the permit.  An outer timeout bounds the test well under one second.
    #[tokio::test]
    async fn concurrency_load_shed_returns_refused() {
        let config = ProtectiveConfig {
            rate_per_second: 1000,
            rate_burst: 1000,
            concurrency_cap: 1,
            request_timeout: Duration::from_secs(5),
        };

        // A Notify that releases the blocking stub.
        let gate = Arc::new(Notify::new());
        let gate_clone = gate.clone();

        // Blocking stub: waits for the gate before returning.
        let blocking_svc = tower::service_fn(move |req: DnsRequest| {
            let gate = gate_clone.clone();
            async move {
                gate.notified().await;
                Ok::<_, BoxError>(PipelineResponse::new(req.raw().clone(), Outcome::Forwarded))
            }
        });

        let svc = build_protective_service(&config, blocking_svc);

        let raw_a = build_a_query(0x0005, "a.example.com");
        let raw_b = build_a_query(0x0006, "b.example.com");
        let addr: SocketAddr = "10.0.0.3:1234".parse().unwrap();

        // Use an outer timeout to keep the test bounded.
        tokio::time::timeout(Duration::from_secs(2), async {
            // Start request A — it acquires the semaphore permit and blocks.
            let req_a = make_request(raw_a, addr);
            let mut svc_a = svc.clone();
            let fut_a = tokio::spawn(async move {
                svc_a.ready().await.expect("ready");
                svc_a.call(req_a).await
            });

            // Yield a bit to let A acquire the permit before B arrives.
            tokio::time::sleep(Duration::from_millis(20)).await;

            // Start request B — the semaphore is full, it should be load-shed.
            let req_b = make_request(raw_b, addr);
            let result_b = svc.clone().oneshot(req_b).await;

            let err = result_b.expect_err("request B must be load-shed");
            let (outcome, rcode) = classify_rejection(&err);
            assert_eq!(outcome, Outcome::Refused, "load-shed must be Refused");
            assert_eq!(rcode, Rcode::Refused, "rcode must be Refused");

            // Release A so the test can finish cleanly.
            gate.notify_one();
            fut_a
                .await
                .expect("task A must complete")
                .expect("A must succeed");
        })
        .await
        .expect("test must complete within the outer timeout");
    }

    // ── classifier_unit_test ──────────────────────────────────────────────────

    /// Direct unit tests for classify_rejection without going through the full stack.
    #[test]
    fn classifier_rate_limited_maps_to_refused() {
        let err: BoxError = Box::new(RateLimited);
        let (outcome, rcode) = classify_rejection(&err);
        assert_eq!(outcome, Outcome::Refused);
        assert_eq!(rcode, Rcode::Refused);
    }

    #[test]
    fn classifier_overloaded_maps_to_refused() {
        let err: BoxError = Box::new(tower::load_shed::error::Overloaded::new());
        let (outcome, rcode) = classify_rejection(&err);
        assert_eq!(outcome, Outcome::Refused);
        assert_eq!(rcode, Rcode::Refused);
    }

    #[test]
    fn classifier_elapsed_maps_to_servfail() {
        let err: BoxError = Box::new(tower::timeout::error::Elapsed::new());
        let (outcome, rcode) = classify_rejection(&err);
        assert_eq!(outcome, Outcome::Servfail);
        assert_eq!(rcode, Rcode::ServFail);
    }

    #[test]
    fn classifier_generic_error_maps_to_servfail() {
        // Any error type that is neither RateLimited nor Overloaded nor Elapsed
        // must default to SERVFAIL.
        let err: BoxError = "oops".into();
        let (outcome, rcode) = classify_rejection(&err);
        assert_eq!(outcome, Outcome::Servfail);
        assert_eq!(rcode, Rcode::ServFail);
    }
}
