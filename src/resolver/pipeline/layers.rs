//! Decision-stack layer: SPEC §5 match precedence as a single wrapping service.
//!
//! [`DecisionStack`] implements the list/local precedence checks described in
//! SPEC §5, short-circuiting on a hit and falling through to the inner service
//! on a miss.  The inner service is the cache layer
//! ([`CacheService`](crate::resolver::pipeline::cache_layer::CacheService)),
//! which wraps the upstream-forward leaf (E6.3); the cache lookup/store lives
//! there, not here.  Tested with a stub inner.
//!
//! # Precedence (ordered, each stage short-circuits except allowlist)
//!
//! 1. **Local records** — authoritative answer for this server's own names;
//!    wins over all blocking.
//! 2. **Admin blacklist** — unconditional sinkhole; the allowlist cannot override.
//! 3. **Allowlist** — sets a bypass flag; never short-circuits.
//! 4. **Blocklist** — sinkhole for aggregated third-party lists; bypassed by
//!    the allowlist.
//! 5. **Miss** — fall through to the inner service (cache layer → forward).

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use tower::{Layer, Service};

use crate::{
    codec::message::Qtype,
    codec::synth::{LocalRecord, Response},
    resolver::{
        local::{LocalMatch, RecordData},
        pipeline::{BoxError, DnsRequest, Outcome, PipelineResponse},
        state::ResolverState,
    },
};

// ── Constants ─────────────────────────────────────────────────────────────────

/// TTL placed on synthesized sinkhole responses, in seconds.
///
/// A fixed v0.1 policy; there is no per-settings field for this yet.
/// Clients will cache a block result for this many seconds before re-querying.
pub const BLOCK_TTL_SECS: u32 = 60;

// ── DecisionStack ─────────────────────────────────────────────────────────────

/// A tower [`Service`] that implements the SPEC §5 resolution precedence.
///
/// Wraps an inner service (the cache layer, which wraps the forward leaf) and
/// short-circuits based on local records, admin blacklist, allowlist, and
/// blocklist — in that order.  A miss on all checks falls through to the inner
/// service.
///
/// Construct via [`DecisionStack::new`] or [`DecisionLayer`].
#[derive(Clone)]
pub struct DecisionStack<S> {
    state: Arc<ResolverState>,
    inner: S,
}

impl<S> DecisionStack<S> {
    /// Create a new [`DecisionStack`] backed by `state` and wrapping `inner`.
    pub fn new(state: Arc<ResolverState>, inner: S) -> Self {
        Self { state, inner }
    }
}

// ── tower::Service impl ───────────────────────────────────────────────────────

impl<S> Service<DnsRequest> for DecisionStack<S>
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

    fn call(&mut self, mut req: DnsRequest) -> Self::Future {
        let state = self.state.clone();

        // Tower contract: the future may be polled after `self` is borrowed
        // again, so move the poll_ready'd inner service into the future and
        // leave a fresh clone in `self` (the standard clone-and-replace
        // pattern for stateful tower services).
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            let name = req.question().name.clone();
            let qtype = req.question().qtype;

            // EDNS info was scanned once at request construction; clone the
            // small owned value out so stage 3 can take `&mut req` while the
            // later stages still synthesize with it.
            let edns = req.edns().cloned();

            // Clone block_mode out of the arc-swap Guard so we never hold
            // the Guard across an .await boundary.
            let block_mode = state.settings().block_mode.clone();

            // ── Stage 1: Local records ────────────────────────────────────────
            //
            // Local wins over all blocking.  The name is private to this
            // server and must never be forwarded.

            // 1a. Reverse PTR: answer authoritatively for IPs we own.  A reverse
            // query for an address we do NOT own falls through (Miss) so it can
            // reach conditional forwarding / the upstream pool (E13.4) — we must
            // not answer NODATA for arbitrary reverse zones (that is the
            // router's job).  Local PTR synth therefore wins over forwarding.
            if qtype == Qtype::Ptr
                && let Some(ip) = name.reverse_addr()
                && let Some((target, ttl)) = state.local().reverse_lookup(ip)
            {
                let bytes = Response::local_ptr(req.query(), &target, ttl, edns.as_ref());
                return Ok(PipelineResponse::new(bytes, Outcome::Local));
            }

            // 1b. Forward records (A/AAAA and authoritative NODATA).
            match state.local().lookup(&name, qtype) {
                LocalMatch::Answer { data, ttl } => {
                    // Map the typed data to a wire LocalRecord.
                    // Bind octets to a local `let` so the slice borrow lives
                    // long enough for the Response::local call.
                    let bytes = match data {
                        RecordData::A(addr) => {
                            let octets = addr.octets();
                            let record = LocalRecord {
                                rtype: 1,
                                rdata: &octets,
                            };
                            Response::local(req.query(), &[record], ttl, edns.as_ref())
                        }
                        RecordData::Aaaa(addr) => {
                            let octets = addr.octets();
                            let record = LocalRecord {
                                rtype: 28,
                                rdata: &octets,
                            };
                            Response::local(req.query(), &[record], ttl, edns.as_ref())
                        }
                    };
                    return Ok(PipelineResponse::new(bytes, Outcome::Local));
                }
                LocalMatch::NameExistsNoData => {
                    let bytes = Response::local_nodata(req.query(), edns.as_ref());
                    return Ok(PipelineResponse::new(bytes, Outcome::LocalNoData));
                }
                LocalMatch::Miss => {} // fall through
            }

            // ── Pause gate (E12) ──────────────────────────────────────────────
            //
            // When blocking is paused, skip every blocking stage (blacklist,
            // allowlist, blocklist) and fall through to the inner service.
            // Local records above are unaffected — they are authoritative and
            // must keep answering. Auto-resumes by comparison: the first query
            // after the deadline takes the normal path again.
            if state.blocking_paused() {
                return inner.call(req).await;
            }

            // ── Stage 2: Admin blacklist ──────────────────────────────────────
            //
            // The allowlist cannot override the admin blacklist.
            if state.blacklist().contains(&name) {
                let bytes =
                    Response::block(req.query(), &block_mode, BLOCK_TTL_SECS, edns.as_ref());
                return Ok(PipelineResponse::new(bytes, Outcome::BlockedByAdmin));
            }

            // ── Stage 3: Allowlist ────────────────────────────────────────────
            //
            // Never short-circuits — only sets the bypass flag so that stage 4
            // (bulk blocklist) is skipped.
            let mut bypass = false;
            if state.allowlist().contains(&name) {
                bypass = true;
                req.set_allow_bypass(true);
            }

            // ── Stage 4: Blocklist ────────────────────────────────────────────
            //
            // Skipped when the allowlist granted bypass.
            if !bypass && state.blocklist().contains(&name) {
                let bytes =
                    Response::block(req.query(), &block_mode, BLOCK_TTL_SECS, edns.as_ref());
                return Ok(PipelineResponse::new(bytes, Outcome::BlockedByBlocklist));
            }

            // ── Stage 5: Miss — hand off to the inner service ─────────────────
            //
            // The inner service is the cache layer (lookup + store) wrapping the
            // upstream-forward leaf; the cache read/write lives there, not here.
            inner.call(req).await
        })
    }
}

// ── DecisionLayer ─────────────────────────────────────────────────────────────

/// A [`tower::Layer`] that wraps a service with [`DecisionStack`].
///
/// Inject into a tower [`ServiceBuilder`](tower::ServiceBuilder) to apply the
/// full SPEC §5 precedence stack:
///
/// ```rust,ignore
/// let svc = ServiceBuilder::new()
///     .layer(DecisionLayer::new(state.clone()))
///     .service(forward_service);
/// ```
pub struct DecisionLayer {
    state: Arc<ResolverState>,
}

impl DecisionLayer {
    /// Create a new [`DecisionLayer`] backed by `state`.
    pub fn new(state: Arc<ResolverState>) -> Self {
        Self { state }
    }
}

impl<S> Layer<S> for DecisionLayer {
    type Service = DecisionStack<S>;

    fn layer(&self, inner: S) -> Self::Service {
        DecisionStack::new(self.state.clone(), inner)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use bytes::Bytes;

    use tower::ServiceExt as _;

    use super::*;
    use crate::test_support::{a_query, aaaa_query, ptr_query};
    use crate::{
        codec::{
            header::{Header, Rcode},
            message::Query,
            name::Name,
            reader::Reader,
        },
        resolver::{
            local::{LocalRecords, RecordData as LRecordData},
            pipeline::{BoxError, DnsRequest, Outcome, PipelineResponse},
            state::{ResolverState, RuntimeSettings},
        },
    };

    // ── Test helpers ──────────────────────────────────────────────────────────

    /// Parse a domain name.
    fn name(s: &str) -> Name {
        s.parse().expect("valid domain name")
    }

    /// Build a [`DnsRequest`] from a raw datagram.
    fn make_request(raw: Bytes) -> DnsRequest {
        let client: SocketAddr = "127.0.0.1:5353".parse().unwrap();
        let query = Query::try_from(raw).expect("valid query");
        DnsRequest::new(query, client)
    }

    /// Stub inner service: echoes the raw query bytes with `Outcome::Forwarded`.
    ///
    /// Uses a bare function pointer so the type is concrete and carries the
    /// `Clone + Send + 'static` bounds that `DecisionStack<S>` requires.
    fn stub_fn(req: DnsRequest) -> std::future::Ready<Result<PipelineResponse, BoxError>> {
        std::future::ready(Ok(PipelineResponse::new(
            req.raw().clone(),
            Outcome::Forwarded,
        )))
    }

    /// Parse the DNS header from raw response bytes.
    fn parse_header(bytes: &Bytes) -> Header {
        let mut r = Reader::new(bytes.clone());
        Header::read(&mut r).expect("valid DNS header")
    }

    // ── Precedence tests ──────────────────────────────────────────────────────

    /// A name on both the admin blacklist and the allowlist must still be
    /// `BlockedByAdmin` — the allowlist cannot override the admin blacklist.
    #[tokio::test]
    async fn blacklisted_and_allowlisted_still_blocked_by_admin() {
        let (_dir, db) = crate::test_support::temp_db().await;
        let state = ResolverState::hydrate(&db).await.expect("hydrate");

        // Install both blacklist and allowlist containing the same name.
        let target = name("evil.example.com");
        state
            .blacklist()
            .store([target.clone()].into_iter().collect());
        state
            .allowlist()
            .store([target.clone()].into_iter().collect());

        let raw = a_query(0x0001, "evil.example.com");
        let req = make_request(raw);

        let stack = DecisionStack::new(state, tower::service_fn(stub_fn));
        let resp = stack.oneshot(req).await.unwrap();

        assert_eq!(
            resp.outcome,
            Outcome::BlockedByAdmin,
            "admin blacklist must win over allowlist"
        );
    }

    /// A name on both the allowlist and the blocklist must fall through to the
    /// inner service (allowlist bypasses blocklist → Forwarded from stub).
    #[tokio::test]
    async fn allowlisted_and_blocklisted_forwards() {
        let (_dir, db) = crate::test_support::temp_db().await;
        let state = ResolverState::hydrate(&db).await.expect("hydrate");

        let target = name("safe.example.com");
        state
            .allowlist()
            .store([target.clone()].into_iter().collect());
        state
            .blocklist()
            .store([(target.clone(), 1)].into_iter().collect());

        let raw = a_query(0x0002, "safe.example.com");
        let req = make_request(raw);

        let stack = DecisionStack::new(state, tower::service_fn(stub_fn));
        let resp = stack.oneshot(req).await.unwrap();

        assert_eq!(
            resp.outcome,
            Outcome::Forwarded,
            "allowlist must bypass blocklist → stub returns Forwarded"
        );
    }

    /// A local A record for a name must return `Outcome::Local`, even if the
    /// same name is also on the blacklist and blocklist.
    #[tokio::test]
    async fn local_record_wins_over_all_blocking() {
        let (_dir, db) = crate::test_support::temp_db().await;
        let state = ResolverState::hydrate(&db).await.expect("hydrate");

        let target = name("router.home.lan");

        // Put the name on both blacklist and blocklist to make sure local wins.
        state
            .blacklist()
            .store([target.clone()].into_iter().collect());
        state
            .blocklist()
            .store([(target.clone(), 1)].into_iter().collect());

        // Install a local A record.
        let mut b = LocalRecords::builder();
        b.add(
            "router.home.lan",
            LRecordData::A("192.168.1.1".parse().unwrap()),
            300,
        )
        .unwrap();
        state.local().store(b.build());

        let raw = a_query(0x0003, "router.home.lan");
        let req = make_request(raw);

        let stack = DecisionStack::new(state, tower::service_fn(stub_fn));
        let resp = stack.oneshot(req).await.unwrap();

        assert_eq!(
            resp.outcome,
            Outcome::Local,
            "local record must win over all blocking"
        );
    }

    /// When a local name exists but only has an A record and the query is AAAA,
    /// the result must be `Outcome::LocalNoData` (not forwarded, not blocked).
    #[tokio::test]
    async fn local_name_exists_but_qtype_absent_returns_nodata() {
        let (_dir, db) = crate::test_support::temp_db().await;
        let state = ResolverState::hydrate(&db).await.expect("hydrate");

        // Install an A record only.
        let mut b = LocalRecords::builder();
        b.add("host.lan", LRecordData::A("10.0.0.1".parse().unwrap()), 60)
            .unwrap();
        state.local().store(b.build());

        // Query for AAAA — the name exists but has no AAAA record.
        let raw = aaaa_query(0x0004, "host.lan");
        let req = make_request(raw);

        let stack = DecisionStack::new(state, tower::service_fn(stub_fn));
        let resp = stack.oneshot(req).await.unwrap();

        assert_eq!(
            resp.outcome,
            Outcome::LocalNoData,
            "AAAA query for A-only local name must return LocalNoData"
        );
    }

    /// A name on the blocklist (not allowlisted) must return
    /// `Outcome::BlockedByBlocklist`.
    #[tokio::test]
    async fn plain_blocklist_hit_returns_blocked_by_blocklist() {
        let (_dir, db) = crate::test_support::temp_db().await;
        let state = ResolverState::hydrate(&db).await.expect("hydrate");

        let target = name("tracker.bad.example");
        state
            .blocklist()
            .store([(target.clone(), 1)].into_iter().collect());

        let raw = a_query(0x0005, "tracker.bad.example");
        let req = make_request(raw);

        let stack = DecisionStack::new(state, tower::service_fn(stub_fn));
        let resp = stack.oneshot(req).await.unwrap();

        assert_eq!(
            resp.outcome,
            Outcome::BlockedByBlocklist,
            "plain blocklist hit must return BlockedByBlocklist"
        );
    }

    /// A name not on any list, with an empty cache, must fall through to the
    /// inner service and return `Outcome::Forwarded`.
    #[tokio::test]
    async fn plain_non_match_falls_through_to_forwarded() {
        let (_dir, db) = crate::test_support::temp_db().await;
        let state = ResolverState::hydrate(&db).await.expect("hydrate");
        // All lists and cache are empty after hydration.

        let raw = a_query(0x0006, "nobody.example.com");
        let req = make_request(raw);

        let stack = DecisionStack::new(state, tower::service_fn(stub_fn));
        let resp = stack.oneshot(req).await.unwrap();

        assert_eq!(
            resp.outcome,
            Outcome::Forwarded,
            "plain miss must fall through to Forwarded"
        );
    }

    /// Verify synthesized block response properties for a blocklist hit in
    /// null-IP mode: the response header must echo the query id, RCODE must be
    /// NoError (null-IP mode for A query), and the answer must carry 0.0.0.0.
    #[tokio::test]
    async fn blocklist_null_ip_response_is_well_formed() {
        let (_dir, db) = crate::test_support::temp_db().await;
        let state = ResolverState::hydrate(&db).await.expect("hydrate");

        // Ensure the settings are in null-ip mode (the seeded default).
        let settings_guard = state.settings();
        assert_eq!(
            settings_guard.block_mode,
            crate::codec::synth::BlockMode::null_ip(),
            "seeded default must be null-ip"
        );
        drop(settings_guard);

        let target = name("blocked.example");
        state
            .blocklist()
            .store([(target.clone(), 1)].into_iter().collect());

        let query_id: u16 = 0x1234;
        let raw = a_query(query_id, "blocked.example");
        let req = make_request(raw);

        let stack = DecisionStack::new(state, tower::service_fn(stub_fn));
        let resp = stack.oneshot(req).await.unwrap();

        assert_eq!(resp.outcome, Outcome::BlockedByBlocklist);

        // Parse the response header.
        let hdr = parse_header(&resp.bytes);
        assert_eq!(hdr.id, query_id, "response id must match query id");
        assert!(hdr.qr(), "QR must be set");
        assert_eq!(hdr.rcode(), Rcode::NoError, "null-ip A → NOERROR");
        assert_eq!(hdr.ancount, 1, "null-ip A → one answer RR");
    }

    /// Verify synthesized block response in NxDomain mode returns RCODE=NXDOMAIN.
    #[tokio::test]
    async fn admin_blacklist_nxdomain_response_is_well_formed() {
        let (_dir, db) = crate::test_support::temp_db().await;
        let state = ResolverState::hydrate(&db).await.expect("hydrate");

        // Swap settings to NxDomain blocking mode.
        let new_settings = RuntimeSettings {
            block_mode: crate::codec::synth::BlockMode::NxDomain,
            ..(*state.settings_full()).clone()
        };
        state.store_settings(new_settings);

        let target = name("evil.example");
        state
            .blacklist()
            .store([target.clone()].into_iter().collect());

        let query_id: u16 = 0x5678;
        let raw = a_query(query_id, "evil.example");
        let req = make_request(raw);

        let stack = DecisionStack::new(state, tower::service_fn(stub_fn));
        let resp = stack.oneshot(req).await.unwrap();

        assert_eq!(resp.outcome, Outcome::BlockedByAdmin);

        let hdr = parse_header(&resp.bytes);
        assert_eq!(hdr.id, query_id, "response id must match query id");
        assert_eq!(hdr.rcode(), Rcode::NxDomain, "NxDomain mode → NXDOMAIN");
        assert_eq!(hdr.ancount, 0, "NXDOMAIN → no answer RRs");
    }

    // ── Pause gate (E12) ──────────────────────────────────────────────────────

    /// While paused, a blacklisted name must fall through to the inner service
    /// (Forwarded) rather than being blocked.
    #[tokio::test]
    async fn paused_blacklisted_name_falls_through() {
        let (_dir, db) = crate::test_support::temp_db().await;
        let state = ResolverState::hydrate(&db).await.expect("hydrate");

        let target = name("evil.example.com");
        state
            .blacklist()
            .store([target.clone()].into_iter().collect());
        state.pause_for_secs(300);

        let raw = a_query(0x0101, "evil.example.com");
        let req = make_request(raw);

        let stack = DecisionStack::new(state, tower::service_fn(stub_fn));
        let resp = stack.oneshot(req).await.unwrap();

        assert_eq!(
            resp.outcome,
            Outcome::Forwarded,
            "paused blocking must let a blacklisted name through"
        );
    }

    /// While paused, a blocklisted name must also fall through to Forwarded.
    #[tokio::test]
    async fn paused_blocklisted_name_falls_through() {
        let (_dir, db) = crate::test_support::temp_db().await;
        let state = ResolverState::hydrate(&db).await.expect("hydrate");

        let target = name("tracker.bad.example");
        state
            .blocklist()
            .store([(target.clone(), 1)].into_iter().collect());
        state.pause_for_secs(300);

        let raw = a_query(0x0102, "tracker.bad.example");
        let req = make_request(raw);

        let stack = DecisionStack::new(state, tower::service_fn(stub_fn));
        let resp = stack.oneshot(req).await.unwrap();

        assert_eq!(
            resp.outcome,
            Outcome::Forwarded,
            "paused blocking must let a blocklisted name through"
        );
    }

    /// While paused, a local record must still answer authoritatively — the
    /// pause gate sits below Stage 1.
    #[tokio::test]
    async fn paused_local_record_still_answers() {
        let (_dir, db) = crate::test_support::temp_db().await;
        let state = ResolverState::hydrate(&db).await.expect("hydrate");

        let mut b = LocalRecords::builder();
        b.add(
            "router.home.lan",
            LRecordData::A("192.168.1.1".parse().unwrap()),
            300,
        )
        .unwrap();
        state.local().store(b.build());
        state.pause_for_secs(300);

        let raw = a_query(0x0103, "router.home.lan");
        let req = make_request(raw);

        let stack = DecisionStack::new(state, tower::service_fn(stub_fn));
        let resp = stack.oneshot(req).await.unwrap();

        assert_eq!(
            resp.outcome,
            Outcome::Local,
            "local records must answer even while blocking is paused"
        );
    }

    /// After a pause is resumed, blocking takes effect again immediately.
    #[tokio::test]
    async fn resumed_blocking_blocks_again() {
        let (_dir, db) = crate::test_support::temp_db().await;
        let state = ResolverState::hydrate(&db).await.expect("hydrate");

        let target = name("ads.example.com");
        state
            .blacklist()
            .store([target.clone()].into_iter().collect());

        state.pause_for_secs(300);
        state.resume();

        let raw = a_query(0x0104, "ads.example.com");
        let req = make_request(raw);

        let stack = DecisionStack::new(state, tower::service_fn(stub_fn));
        let resp = stack.oneshot(req).await.unwrap();

        assert_eq!(
            resp.outcome,
            Outcome::BlockedByAdmin,
            "resuming must restore blocking immediately"
        );
    }

    /// `DecisionLayer` must produce the same stack as `DecisionStack::new`.
    #[tokio::test]
    async fn decision_layer_wraps_correctly() {
        let (_dir, db) = crate::test_support::temp_db().await;
        let state = ResolverState::hydrate(&db).await.expect("hydrate");

        let layer = DecisionLayer::new(state);
        let svc = layer.layer(tower::service_fn(stub_fn));

        let raw = a_query(0x9999, "via-layer.example.com");
        let req = make_request(raw);

        let resp = svc.oneshot(req).await.unwrap();
        // Empty state → falls through to stub → Forwarded.
        assert_eq!(resp.outcome, Outcome::Forwarded);
    }

    /// Verify that a local A record answer is synthesized correctly: the
    /// response must have AA=1, RCODE=NOERROR, and ANCOUNT=1 with the right IP.
    #[tokio::test]
    async fn local_a_record_response_is_authoritative() {
        let (_dir, db) = crate::test_support::temp_db().await;
        let state = ResolverState::hydrate(&db).await.expect("hydrate");

        let ip: Ipv4Addr = "192.168.1.42".parse().unwrap();
        let mut b = LocalRecords::builder();
        b.add("myhost.lan", LRecordData::A(ip), 120).unwrap();
        state.local().store(b.build());

        let query_id: u16 = 0xABCD;
        let raw = a_query(query_id, "myhost.lan");
        let req = make_request(raw);

        let stack = DecisionStack::new(state, tower::service_fn(stub_fn));
        let resp = stack.oneshot(req).await.unwrap();

        assert_eq!(resp.outcome, Outcome::Local);

        let hdr = parse_header(&resp.bytes);
        assert_eq!(hdr.id, query_id);
        assert!(hdr.aa(), "local record must set AA=1");
        assert_eq!(hdr.rcode(), Rcode::NoError);
        assert_eq!(hdr.ancount, 1);
    }

    /// A PTR query for an IP we own (a local A record) must be answered
    /// authoritatively from the reverse index: Outcome::Local, AA=1, ANCOUNT=1.
    #[tokio::test]
    async fn ptr_for_local_record_is_authoritative() {
        let (_dir, db) = crate::test_support::temp_db().await;
        let state = ResolverState::hydrate(&db).await.expect("hydrate");

        let mut b = LocalRecords::builder();
        b.add(
            "router.home.lan",
            LRecordData::A("192.168.1.1".parse().unwrap()),
            300,
        )
        .unwrap();
        state.local().store(b.build());

        let query_id: u16 = 0x0ABC;
        let raw = ptr_query(query_id, "1.1.168.192.in-addr.arpa");
        let req = make_request(raw);

        let stack = DecisionStack::new(state, tower::service_fn(stub_fn));
        let resp = stack.oneshot(req).await.unwrap();

        assert_eq!(resp.outcome, Outcome::Local, "PTR for owned IP → Local");

        let hdr = parse_header(&resp.bytes);
        assert_eq!(hdr.id, query_id);
        assert!(hdr.aa(), "PTR answer must be authoritative");
        assert_eq!(hdr.rcode(), Rcode::NoError);
        assert_eq!(hdr.ancount, 1, "one PTR answer RR");
    }

    /// A PTR query for an IP we do **not** own must fall through to the inner
    /// service (Forwarded) — not answered NODATA here, so conditional forwarding
    /// (E13.4) and the upstream pool can handle it.
    #[tokio::test]
    async fn ptr_for_unknown_ip_falls_through() {
        let (_dir, db) = crate::test_support::temp_db().await;
        let state = ResolverState::hydrate(&db).await.expect("hydrate");
        // No local records → no reverse entries.

        let raw = ptr_query(0x0DEF, "5.1.168.192.in-addr.arpa");
        let req = make_request(raw);

        let stack = DecisionStack::new(state, tower::service_fn(stub_fn));
        let resp = stack.oneshot(req).await.unwrap();

        assert_eq!(
            resp.outcome,
            Outcome::Forwarded,
            "PTR for an unknown IP must fall through, not be answered here"
        );
    }

    /// A local NODATA response must have AA=1, RCODE=NOERROR, ANCOUNT=0.
    #[tokio::test]
    async fn local_nodata_response_is_authoritative_nodata() {
        let (_dir, db) = crate::test_support::temp_db().await;
        let state = ResolverState::hydrate(&db).await.expect("hydrate");

        // A-only record; AAAA query → NODATA.
        let mut b = LocalRecords::builder();
        b.add(
            "nodata.lan",
            LRecordData::A("10.0.0.2".parse().unwrap()),
            60,
        )
        .unwrap();
        state.local().store(b.build());

        let query_id: u16 = 0xDEAD;
        let raw = aaaa_query(query_id, "nodata.lan");
        let req = make_request(raw);

        let stack = DecisionStack::new(state, tower::service_fn(stub_fn));
        let resp = stack.oneshot(req).await.unwrap();

        assert_eq!(resp.outcome, Outcome::LocalNoData);

        let hdr = parse_header(&resp.bytes);
        assert_eq!(hdr.id, query_id);
        assert!(hdr.aa(), "NODATA response must be authoritative");
        assert_eq!(hdr.rcode(), Rcode::NoError);
        assert_eq!(hdr.ancount, 0, "NODATA must have no answer RRs");
    }
}
