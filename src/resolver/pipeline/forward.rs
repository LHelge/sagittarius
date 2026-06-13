//! Forward inner service: SPEC §5 steps 8–9, §8.
//!
//! [`ForwardService`] is the **leaf** of the DNS pipeline — the innermost
//! [`tower::Service`], reached on a cache miss (the [`CacheService`] sits
//! directly above it).  It:
//!
//! 1. Forwards the query to an upstream resolver via [`SharedUpstreamPool`].
//! 2. Decides the cache-store policy (positive vs. negative vs. not-cached) and
//!    emits it as a [`CacheDirective`] — the [`CacheService`] executes the store.
//! 3. Patches the transaction ID in the reply back to the client's query ID.
//! 4. Returns [`Outcome::Forwarded`] on success or [`Outcome::Servfail`] when
//!    all upstreams have failed, bundled with the directive in a [`ForwardOutput`].
//!
//! # Cache-store policy (SPEC §8)
//!
//! | Response type | Directive | Expiry |
//! |---|---|---|
//! | Positive (has real RRs) | `Store` | `scan.min_ttl` |
//! | Positive (no real TTL RRs) | `Skip` | — |
//! | Negative with SOA | `Store` | `min(negative_ttl, cap)` |
//! | Negative without SOA | `Skip` | — |
//! | Scan error | `Skip` | — |
//!
//! The policy lives here because the upstream metadata (TTL-field offsets, the
//! positive min TTL, the RFC 2308 negative TTL) is only available at this leaf.
//! The [`CacheService`] owns the mechanism and clamps the expiry to
//! `[cache_min_ttl, cache_max_ttl]` on insert.
//!
//! # Transaction-ID patching
//!
//! The upstream bytes carry hickory's internal transaction ID, not the client's.
//! [`DnsMessageBytes::with_txn_id`] copies the bytes and overwrites the first two
//! bytes with the client's query ID for the reply.  The directive caches the **un-patched**
//! upstream bytes; patching (and TTL decrement) happens at serve time in
//! [`DnsCache::get`](crate::resolver::cache::DnsCache::get).
//!
//! [`CacheService`]: crate::resolver::pipeline::cache_layer::CacheService

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::{Bytes, BytesMut};
use tower::Service;

use crate::{
    codec::{header::Rcode, synth::Response, ttl::TtlScan},
    resolver::{
        pipeline::{
            BoxError, DnsRequest, Outcome, PipelineResponse,
            cache_layer::{CacheDirective, ForwardOutput},
        },
        state::ResolverState,
        upstream::SharedUpstreamPool,
    },
};

// ── ForwardService ────────────────────────────────────────────────────────────

/// The innermost leaf [`tower::Service`] of the DNS pipeline.
///
/// Forwards the query to the upstream pool, decides the cache-store policy
/// (emitted as a [`CacheDirective`] for the cache layer to execute), patches
/// the transaction ID for the client reply, and returns a [`ForwardOutput`].
///
/// Both fields are [`Arc`]-wrapped so the service is cheaply [`Clone`]able —
/// a requirement because the [`CacheService`](super::cache_layer::CacheService)
/// that wraps it must be `Clone`.
#[derive(Clone)]
pub struct ForwardService {
    pool: Arc<SharedUpstreamPool>,
    state: Arc<ResolverState>,
}

impl ForwardService {
    /// Create a new [`ForwardService`].
    pub fn new(pool: Arc<SharedUpstreamPool>, state: Arc<ResolverState>) -> Self {
        Self { pool, state }
    }
}

// ── tower::Service impl ───────────────────────────────────────────────────────

impl Service<DnsRequest> for ForwardService {
    type Response = ForwardOutput;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<ForwardOutput, BoxError>> + Send>>;

    /// The leaf service is always ready — it has no inner service to poll.
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: DnsRequest) -> Self::Future {
        // Clone the Arcs into the future. No clone-and-replace dance is needed
        // here because this is a leaf service (no inner service to protect).
        let pool = self.pool.clone();
        let state = self.state.clone();

        Box::pin(async move {
            // Extract owned values before the first await so there are no
            // borrows of `req` across await points.
            let question = req.question().clone();
            let client_id = req.header().id;

            match pool.forward(&question).await {
                Ok(fr) => {
                    // ── Cache-store policy (SPEC §5 step 9, §8) ───────────────
                    //
                    // We decide *whether and for how long* to cache here — the
                    // upstream metadata (TTL-field offsets, positive min TTL,
                    // RFC 2308 negative TTL) lives only at this leaf — and hand
                    // the decision to the cache layer as a `CacheDirective`,
                    // which executes the store. `settings_full()` returns an
                    // owned Arc, safe across awaits.
                    let settings = state.settings_full();
                    // Scan the upstream bytes for the TTL-field offsets and the
                    // positive min TTL (OPT pseudo-RRs already excluded).
                    let scan = TtlScan::scan(&fr.bytes);

                    let directive = if let Ok(s) = scan.as_ref() {
                        let expiry = if fr.is_negative {
                            // Negatives: RFC 2308 negative TTL, capped at the
                            // configured cap. None (no SOA) → do NOT cache.
                            fr.negative_ttl.map(|t| t.min(settings.negative_ttl_cap))
                        } else {
                            // Positives: the scan's min non-OPT RR TTL.
                            // None (no TTL-bearing RRs) → do NOT cache.
                            s.min_ttl
                        };
                        match expiry {
                            Some(expiry) => CacheDirective::Store {
                                bytes: fr.bytes.clone(),
                                ttl_offsets: s.ttl_offsets.clone(),
                                expiry,
                            },
                            None => CacheDirective::Skip,
                        }
                    } else {
                        // Unscannable upstream response — reply but do not cache.
                        CacheDirective::Skip
                    };

                    // Patch the transaction ID for the client reply: the upstream
                    // bytes carry hickory's internal txn-id, not the client's.
                    // (The cache stores the un-patched bytes; DnsCache::get
                    // re-patches per requesting client on serve.)
                    let reply = fr.bytes.with_txn_id(client_id);
                    Ok(ForwardOutput::new(
                        PipelineResponse::new(reply, Outcome::Forwarded).with_upstream(fr.upstream),
                        directive,
                    ))
                }
                Err(e) => {
                    // All upstreams failed (or the pool is empty) → SERVFAIL.
                    tracing::warn!(
                        qname = %question.name,
                        qtype = %question.qtype,
                        error = %e,
                        "all upstreams failed; returning SERVFAIL"
                    );
                    let bytes = Response::error_response(req.query(), Rcode::ServFail, req.edns());
                    Ok(ForwardOutput::new(
                        PipelineResponse::new(bytes, Outcome::Servfail),
                        CacheDirective::Skip,
                    ))
                }
            }
        })
    }
}

// ── DNS message bytes helpers ──────────────────────────────────────────────────

/// Rewrites the transaction id on a raw DNS message buffer.
trait DnsMessageBytes {
    /// Copy the message and overwrite the first two bytes (the DNS transaction
    /// id) with `id` in big-endian order.
    ///
    /// Bounds-guarded: a buffer shorter than 2 bytes is returned unchanged.
    fn with_txn_id(&self, id: u16) -> Bytes;
}

impl DnsMessageBytes for Bytes {
    fn with_txn_id(&self, id: u16) -> Bytes {
        if self.len() < 2 {
            return self.clone();
        }
        let mut buf = BytesMut::from(&self[..]);
        buf[0..2].copy_from_slice(&id.to_be_bytes());
        buf.freeze()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, sync::Arc, time::Duration};

    use bytes::Bytes;
    use tokio::time::timeout;
    use tokio_util::task::TaskTracker;
    use tower::ServiceExt as _;

    use super::*;
    use crate::{
        codec::{header::Header, message::Query, reader::Reader},
        resolver::{
            state::ResolverState,
            upstream::{UpstreamConfig, UpstreamPool, UpstreamTransport},
        },
        test_support::{
            a_query, mock_udp_upstream, nxdomain_handler, nxdomain_with_soa_handler,
            positive_a_handler,
        },
    };

    #[test]
    fn with_txn_id_rewrites_first_two_bytes() {
        let msg = Bytes::from_static(&[0x12, 0x34, 0xAA, 0xBB]);
        let patched = msg.with_txn_id(0xBEEF);
        assert_eq!(&patched[..], &[0xBE, 0xEF, 0xAA, 0xBB]);
    }

    #[test]
    fn with_txn_id_short_buffer_is_unchanged() {
        let one = Bytes::from_static(&[0xAA]);
        assert_eq!(&one.with_txn_id(0xBEEF)[..], &[0xAA]);
        assert_eq!(Bytes::new().with_txn_id(0x1234).len(), 0);
    }

    // ── Test helpers ──────────────────────────────────────────────────────────

    /// Build a UDP [`UpstreamConfig`] pointing at `addr`.
    fn udp_config(addr: SocketAddr) -> UpstreamConfig {
        UpstreamConfig {
            addr,
            transport: UpstreamTransport::Udp,
            tls_server_name: None,
            http_endpoint: None,
        }
    }

    /// Build a [`DnsRequest`] from a raw datagram.
    fn make_request(raw: Bytes) -> DnsRequest {
        let client: SocketAddr = "127.0.0.1:5353".parse().unwrap();
        let query = Query::try_from(raw).expect("valid query");
        DnsRequest::new(query, client)
    }

    /// Parse the DNS header from raw bytes.
    fn parse_header(bytes: &Bytes) -> Header {
        let mut r = Reader::new(bytes.clone());
        Header::read(&mut r).expect("valid DNS header")
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    /// The forward service returns the reply with the **client's** query id,
    /// even though the mock returns a response with hickory's internal id
    /// (which echoes the request id — same for a real round-trip, but proves
    /// we patch it when they differ by using a known fixed id in the response).
    /// Outcome must be `Forwarded`.
    #[tokio::test]
    async fn forward_returns_reply_with_client_id() {
        let client_query_id: u16 = 0xBEEF;

        let addr = mock_udp_upstream(positive_a_handler).await;

        let tracker = TaskTracker::new();
        let pool = UpstreamPool::connect(
            &[udp_config(addr)],
            &tracker,
            Arc::new(crate::resolver::upstream::RandomSelector),
            0,
            Duration::from_millis(500),
        )
        .await;
        let pool = Arc::new(SharedUpstreamPool::new(pool));

        let (_dir, db) = crate::test_support::temp_db().await;
        let state = ResolverState::hydrate(&db).await.expect("hydrate");

        let svc = ForwardService::new(pool, state);

        let raw = a_query(client_query_id, "example.com");
        let req = make_request(raw);

        let out = timeout(Duration::from_secs(5), svc.oneshot(req))
            .await
            .expect("safety timeout")
            .expect("service must not error");

        assert_eq!(
            out.reply.outcome,
            Outcome::Forwarded,
            "outcome must be Forwarded"
        );

        // E15: the forwarded reply carries the answering upstream up the stack
        // (the telemetry layer reads this to populate QueryEvent.upstream).
        assert_eq!(
            out.reply.upstream,
            Some(addr),
            "forwarded reply must attribute the answering upstream"
        );

        // The reply's transaction ID must equal the client's query id.
        let hdr = parse_header(&out.reply.bytes);
        assert_eq!(
            hdr.id, client_query_id,
            "reply txn-id must be patched to the client's query id"
        );
    }

    /// A positive A-record answer must yield a `Store` directive carrying the
    /// min-TTL (the cache layer executes the actual insert — see
    /// `cache_layer` tests).
    #[tokio::test]
    async fn positive_answer_directive_stores_min_ttl() {
        let addr = mock_udp_upstream(positive_a_handler).await;

        let tracker = TaskTracker::new();
        let pool = UpstreamPool::connect(
            &[udp_config(addr)],
            &tracker,
            Arc::new(crate::resolver::upstream::RandomSelector),
            0,
            Duration::from_millis(500),
        )
        .await;
        let pool = Arc::new(SharedUpstreamPool::new(pool));

        let (_dir, db) = crate::test_support::temp_db().await;
        let state = ResolverState::hydrate(&db).await.expect("hydrate");

        let svc = ForwardService::new(pool, state);

        let raw = a_query(0x1234, "example.com");
        let req = make_request(raw);

        let out = timeout(Duration::from_secs(5), svc.oneshot(req))
            .await
            .expect("safety timeout")
            .expect("service must not error");

        assert_eq!(out.reply.outcome, Outcome::Forwarded);
        assert!(
            matches!(out.directive, CacheDirective::Store { expiry: 300, .. }),
            "positive answer → Store with min TTL 300, got {:?}",
            out.directive
        );
    }

    /// NXDOMAIN with a SOA (so `negative_ttl` is `Some`) must yield a `Store`
    /// directive with the RFC 2308 negative TTL.  Outcome is `Forwarded` (the
    /// leaf does not distinguish sign — it forwards and emits a directive).
    #[tokio::test]
    async fn negative_with_soa_directive_stores() {
        let addr = mock_udp_upstream(nxdomain_with_soa_handler).await;

        let tracker = TaskTracker::new();
        let pool = UpstreamPool::connect(
            &[udp_config(addr)],
            &tracker,
            Arc::new(crate::resolver::upstream::RandomSelector),
            0,
            Duration::from_millis(500),
        )
        .await;
        let pool = Arc::new(SharedUpstreamPool::new(pool));

        let (_dir, db) = crate::test_support::temp_db().await;
        let state = ResolverState::hydrate(&db).await.expect("hydrate");

        let svc = ForwardService::new(pool, state);

        let raw = a_query(0x5678, "example.com");
        let req = make_request(raw);

        let out = timeout(Duration::from_secs(5), svc.oneshot(req))
            .await
            .expect("safety timeout")
            .expect("service must not error");

        assert_eq!(
            out.reply.outcome,
            Outcome::Forwarded,
            "NXDOMAIN with SOA must still return Forwarded"
        );
        // RFC 2308: min(soa_ttl=120, soa_minimum=60) = 60, under the cap.
        assert!(
            matches!(out.directive, CacheDirective::Store { expiry: 60, .. }),
            "NXDOMAIN with SOA → Store with negative TTL 60, got {:?}",
            out.directive
        );
    }

    /// NXDOMAIN with **no** SOA (`negative_ttl == None`) must yield `Skip`.
    #[tokio::test]
    async fn negative_without_soa_directive_skips() {
        let addr = mock_udp_upstream(nxdomain_handler).await;

        let tracker = TaskTracker::new();
        let pool = UpstreamPool::connect(
            &[udp_config(addr)],
            &tracker,
            Arc::new(crate::resolver::upstream::RandomSelector),
            0,
            Duration::from_millis(500),
        )
        .await;
        let pool = Arc::new(SharedUpstreamPool::new(pool));

        let (_dir, db) = crate::test_support::temp_db().await;
        let state = ResolverState::hydrate(&db).await.expect("hydrate");

        let svc = ForwardService::new(pool, state);

        let raw = a_query(0x9ABC, "example.com");
        let req = make_request(raw);

        let out = timeout(Duration::from_secs(5), svc.oneshot(req))
            .await
            .expect("safety timeout")
            .expect("service must not error");

        assert!(
            matches!(out.directive, CacheDirective::Skip),
            "NXDOMAIN without SOA → Skip (not cacheable), got {:?}",
            out.directive
        );
    }

    /// When all upstreams fail (empty pool → `AllUpstreamsFailed` immediately),
    /// the service must return `Outcome::Servfail` and the reply must parse
    /// with `Rcode::ServFail` and the client's query id.
    #[tokio::test]
    async fn all_upstreams_fail_returns_servfail() {
        // Empty pool: connect with no configs → AllUpstreamsFailed { attempts: 0 }.
        let tracker = TaskTracker::new();
        let pool = UpstreamPool::connect(
            &[],
            &tracker,
            Arc::new(crate::resolver::upstream::RandomSelector),
            0,
            Duration::from_millis(500),
        )
        .await;
        let pool = Arc::new(SharedUpstreamPool::new(pool));

        let (_dir, db) = crate::test_support::temp_db().await;
        let state = ResolverState::hydrate(&db).await.expect("hydrate");

        let svc = ForwardService::new(pool, state);

        let client_id: u16 = 0xDEAD;
        let raw = a_query(client_id, "example.com");
        let req = make_request(raw);

        let out = timeout(Duration::from_secs(5), svc.oneshot(req))
            .await
            .expect("safety timeout")
            .expect("service must not error");

        assert_eq!(
            out.reply.outcome,
            Outcome::Servfail,
            "outcome must be Servfail"
        );
        assert!(
            matches!(out.directive, CacheDirective::Skip),
            "SERVFAIL must not be cached"
        );

        let hdr = parse_header(&out.reply.bytes);
        assert_eq!(
            hdr.id, client_id,
            "SERVFAIL reply must echo the client's query id"
        );
        assert_eq!(
            hdr.rcode(),
            crate::codec::header::Rcode::ServFail,
            "RCODE must be ServFail"
        );
    }
}
