//! Forward-and-cache-store inner service: SPEC §5 steps 8–9, §8.
//!
//! [`ForwardService`] is the **leaf** of the DNS pipeline — the innermost
//! [`tower::Service`] that the [`super::layers::DecisionStack`] delegates to on
//! a cache miss.  It:
//!
//! 1. Forwards the query to an upstream resolver via [`SharedUpstreamPool`].
//! 2. Applies the cache-store TTL policy (positive vs. negative vs. not-cached).
//! 3. Patches the transaction ID in the reply back to the client's query ID.
//! 4. Returns [`Outcome::Forwarded`] on success or [`Outcome::Servfail`] when
//!    all upstreams have failed.
//!
//! # Cache-store policy (SPEC §8)
//!
//! | Response type | Cache key TTL | Stored? |
//! |---|---|---|
//! | Positive (has real RRs) | `scan.min_ttl` | Yes, when `Some` and scan OK |
//! | Negative with SOA | `min(negative_ttl, cap)` | Yes, when SOA present |
//! | Negative without SOA | — | No |
//! | Scan error | — | No |
//!
//! The [`DnsCache`] clamps the supplied expiry to `[cache_min_ttl, cache_max_ttl]`
//! internally.
//!
//! # Transaction-ID patching
//!
//! The upstream bytes carry hickory's internal transaction ID, not the client's.
//! [`patch_txn_id`] copies the bytes and overwrites the first two bytes with the
//! client's query ID before returning the reply.  The cache stores the
//! **un-patched** upstream bytes; patching (and TTL decrement) happens at serve
//! time in [`DnsCache::get`].

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::{Bytes, BytesMut};
use tower::Service;

use crate::{
    codec::{
        header::Rcode,
        synth::{EdnsInfo, Response},
        ttl::TtlScan,
    },
    resolver::{
        pipeline::{BoxError, DnsRequest, Outcome, PipelineResponse},
        state::ResolverState,
        upstream::SharedUpstreamPool,
    },
};

// ── ForwardService ────────────────────────────────────────────────────────────

/// The innermost leaf [`tower::Service`] of the DNS pipeline.
///
/// Forwards the query to the upstream pool, stores the result in the cache
/// under the correct TTL policy, patches the transaction ID, and returns a
/// [`PipelineResponse`].
///
/// Both fields are [`Arc`]-wrapped so the service is cheaply [`Clone`]able —
/// a requirement because [`super::layers::DecisionStack`] wraps a `Clone` inner
/// service.
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
    type Response = PipelineResponse;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<PipelineResponse, BoxError>> + Send>>;

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
            let edns = EdnsInfo::scan(req.query()); // for the SERVFAIL path

            match pool.forward(&question).await {
                Ok(fr) => {
                    // ── Cache-store TTL policy (SPEC §5 step 9, §8) ──────────

                    // `settings_full()` returns an owned Arc; safe across awaits.
                    let settings = state.settings_full();
                    // Scan the upstream bytes for TTL field offsets.
                    // OPT pseudo-RRs are already excluded by TtlScan.
                    let scan = TtlScan::scan(&fr.bytes);

                    let expiry: Option<u32> = if fr.is_negative {
                        // Negatives: RFC 2308 negative TTL from the SOA record,
                        // capped at the configured cap.  None (no SOA) → do NOT cache.
                        fr.negative_ttl.map(|t| t.min(settings.negative_ttl_cap))
                    } else {
                        // Positives: the scan's minimum non-OPT RR TTL.
                        // None (no TTL-bearing RRs, or scan failed) → do NOT cache.
                        scan.as_ref().ok().and_then(|s| s.min_ttl)
                    };

                    // Cache only when we have both a valid expiry and a
                    // successful scan (needed for the TTL-field offsets).
                    // The cache stores upstream bytes unchanged; it patches the
                    // txn-id and decrements TTLs at serve time (DnsCache::get).
                    if let (Some(exp), Ok(s)) = (expiry, scan.as_ref()) {
                        state
                            .cache()
                            .insert(
                                question.clone(),
                                fr.bytes.clone(),
                                s.ttl_offsets.clone(),
                                exp,
                            )
                            .await;
                    }

                    // Patch the transaction ID: the upstream bytes carry
                    // hickory's internal txn-id, not the client's.
                    let reply = patch_txn_id(&fr.bytes, client_id);
                    Ok(PipelineResponse::new(reply, Outcome::Forwarded))
                }
                Err(e) => {
                    // All upstreams failed (or the pool is empty) → SERVFAIL.
                    tracing::warn!(
                        qname = %question.name,
                        qtype = ?question.qtype,
                        error = %e,
                        "all upstreams failed; returning SERVFAIL"
                    );
                    let bytes =
                        Response::error_response(req.query(), Rcode::ServFail, edns.as_ref());
                    Ok(PipelineResponse::new(bytes, Outcome::Servfail))
                }
            }
        })
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Copy `bytes` and overwrite the first two bytes (the DNS transaction ID)
/// with `id` in big-endian order.
///
/// Bounds-guarded: if `bytes` is shorter than 2 bytes, the original bytes
/// are returned unchanged (no panic).
fn patch_txn_id(bytes: &Bytes, id: u16) -> Bytes {
    if bytes.len() < 2 {
        return bytes.clone();
    }
    let mut buf = BytesMut::from(&bytes[..]);
    buf[0..2].copy_from_slice(&id.to_be_bytes());
    buf.freeze()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, sync::Arc, time::Duration};

    use bytes::Bytes;
    use hickory_net::proto::op::{Message, MessageType, ResponseCode};
    use hickory_net::proto::rr::rdata::{A, SOA};
    use hickory_net::proto::rr::{Name, RData, Record};
    use tempfile::TempDir;
    use tokio::net::UdpSocket;
    use tokio::time::timeout;
    use tokio_util::task::TaskTracker;
    use tower::ServiceExt as _;

    use super::*;
    use crate::{
        codec::{
            header::Header,
            message::{Qclass, Qtype, Query, Question},
            name::Name as DnsName,
            reader::Reader,
            writer::Writer,
        },
        resolver::{
            state::ResolverState,
            upstream::{UpstreamConfig, UpstreamPool, UpstreamTransport},
        },
        storage::Db,
    };

    // ── Test helpers ──────────────────────────────────────────────────────────

    /// Open a temporary SQLite database and return the handle.
    async fn open_temp_db() -> (TempDir, Db) {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("test.db");
        let db = Db::connect(&path).await.expect("connect");
        (dir, db)
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

    /// Build a minimal DNS A query datagram for `name` with `id`.
    fn build_a_query(id: u16, name: &str) -> Bytes {
        let mut w = Writer::with_capacity(64);
        Header::new(id).with_qdcount(1).with_rd(true).write(&mut w);
        let n: DnsName = name.parse().expect("valid name");
        n.write(&mut w);
        w.write_u16(1u16); // QTYPE A
        w.write_u16(1u16); // QCLASS IN
        w.finish()
    }

    /// Build a [`DnsRequest`] from a raw datagram.
    fn make_request(raw: Bytes) -> DnsRequest {
        let client: SocketAddr = "127.0.0.1:5353".parse().unwrap();
        let query = Query::try_from(raw).expect("valid query");
        DnsRequest::new(query, client)
    }

    /// Spawn a UDP mock upstream on an ephemeral port.
    ///
    /// For each datagram received the request is parsed with hickory, handed to
    /// `handler`, and — if it returns `Some(response)` — the response is
    /// serialised and sent back.  Returning `None` simulates a dead / silent
    /// upstream.
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

    /// Build a Question for `example.com. A IN`.
    fn stock_question() -> Question {
        Question {
            name: "example.com".parse().unwrap(),
            qtype: Qtype::A,
            qclass: Qclass::In,
        }
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

        let addr = spawn_mock_udp(|req| {
            let mut resp = req.clone();
            resp.metadata.message_type = MessageType::Response;
            resp.metadata.response_code = ResponseCode::NoError;
            let name = Name::from_ascii("example.com.").unwrap();
            let rdata = RData::A(A::new(93, 184, 216, 34));
            resp.add_answer(Record::from_rdata(name, 300, rdata));
            Some(resp)
        })
        .await;

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

        let (_dir, db) = open_temp_db().await;
        let state = ResolverState::hydrate(&db).await.expect("hydrate");

        let svc = ForwardService::new(pool, state);

        let raw = build_a_query(client_query_id, "example.com");
        let req = make_request(raw);

        let resp = timeout(Duration::from_secs(5), svc.oneshot(req))
            .await
            .expect("safety timeout")
            .expect("service must not error");

        assert_eq!(
            resp.outcome,
            Outcome::Forwarded,
            "outcome must be Forwarded"
        );

        // The reply's transaction ID must equal the client's query id.
        let hdr = parse_header(&resp.bytes);
        assert_eq!(
            hdr.id, client_query_id,
            "reply txn-id must be patched to the client's query id"
        );
    }

    /// A positive A-record answer must be stored in the cache under the min-TTL
    /// policy.  After the call `cache.get(&question, any_id)` must return `Some`.
    #[tokio::test]
    async fn positive_answer_cached_with_min_ttl() {
        let addr = spawn_mock_udp(|req| {
            let mut resp = req.clone();
            resp.metadata.message_type = MessageType::Response;
            resp.metadata.response_code = ResponseCode::NoError;
            let name = Name::from_ascii("example.com.").unwrap();
            let rdata = RData::A(A::new(93, 184, 216, 34));
            resp.add_answer(Record::from_rdata(name, 300, rdata));
            Some(resp)
        })
        .await;

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

        let (_dir, db) = open_temp_db().await;
        let state = ResolverState::hydrate(&db).await.expect("hydrate");

        let svc = ForwardService::new(pool, state.clone());

        let raw = build_a_query(0x1234, "example.com");
        let req = make_request(raw);

        timeout(Duration::from_secs(5), svc.oneshot(req))
            .await
            .expect("safety timeout")
            .expect("service must not error");

        // The cache must now contain an entry for `example.com. A IN`.
        let question = stock_question();
        let cached = state.cache().get(&question, 0xABCD).await;
        assert!(
            cached.is_some(),
            "positive answer must be stored in the cache"
        );
    }

    /// NXDOMAIN with a SOA (so `negative_ttl` is `Some`) must be cached.
    /// Outcome must be `Forwarded` (the inner service does not distinguish —
    /// it forwards and stores regardless of sign).
    #[tokio::test]
    async fn negative_with_soa_cached() {
        let addr = spawn_mock_udp(|req| {
            let mut resp = req.clone();
            resp.metadata.message_type = MessageType::Response;
            resp.metadata.response_code = ResponseCode::NXDomain;
            // Add a SOA to the authority section.
            let zone = Name::from_ascii("example.com.").unwrap();
            let mname = Name::from_ascii("ns1.example.com.").unwrap();
            let rname = Name::from_ascii("hostmaster.example.com.").unwrap();
            let soa = SOA::new(mname, rname, 1, 3600, 900, 604800, 60);
            resp.add_authority(Record::from_rdata(zone, 120, RData::SOA(soa)));
            Some(resp)
        })
        .await;

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

        let (_dir, db) = open_temp_db().await;
        let state = ResolverState::hydrate(&db).await.expect("hydrate");

        let svc = ForwardService::new(pool, state.clone());

        let raw = build_a_query(0x5678, "example.com");
        let req = make_request(raw);

        let resp = timeout(Duration::from_secs(5), svc.oneshot(req))
            .await
            .expect("safety timeout")
            .expect("service must not error");

        assert_eq!(
            resp.outcome,
            Outcome::Forwarded,
            "NXDOMAIN with SOA must still return Forwarded"
        );

        // The negative response must be cached under the negative-TTL policy.
        let question = stock_question();
        let cached = state.cache().get(&question, 0xABCD).await;
        assert!(
            cached.is_some(),
            "NXDOMAIN with SOA must be stored in the cache"
        );
    }

    /// NXDOMAIN with **no** SOA (`negative_ttl == None`) must NOT be cached.
    #[tokio::test]
    async fn negative_without_soa_not_cached() {
        let addr = spawn_mock_udp(|req| {
            let mut resp = req.clone();
            resp.metadata.message_type = MessageType::Response;
            resp.metadata.response_code = ResponseCode::NXDomain;
            // No SOA in authority — negative_ttl will be None.
            Some(resp)
        })
        .await;

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

        let (_dir, db) = open_temp_db().await;
        let state = ResolverState::hydrate(&db).await.expect("hydrate");

        let svc = ForwardService::new(pool, state.clone());

        let raw = build_a_query(0x9ABC, "example.com");
        let req = make_request(raw);

        timeout(Duration::from_secs(5), svc.oneshot(req))
            .await
            .expect("safety timeout")
            .expect("service must not error");

        // The cache must NOT contain the response (no SOA → no negative caching).
        let question = stock_question();
        let cached = state.cache().get(&question, 0xABCD).await;
        assert!(
            cached.is_none(),
            "NXDOMAIN without SOA must NOT be stored in the cache"
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

        let (_dir, db) = open_temp_db().await;
        let state = ResolverState::hydrate(&db).await.expect("hydrate");

        let svc = ForwardService::new(pool, state);

        let client_id: u16 = 0xDEAD;
        let raw = build_a_query(client_id, "example.com");
        let req = make_request(raw);

        let resp = timeout(Duration::from_secs(5), svc.oneshot(req))
            .await
            .expect("safety timeout")
            .expect("service must not error");

        assert_eq!(resp.outcome, Outcome::Servfail, "outcome must be Servfail");

        let hdr = parse_header(&resp.bytes);
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
