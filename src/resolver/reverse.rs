//! Internal reverse-lookup service: client IP → hostname (E14.1).
//!
//! Turns a client `IpAddr` into a hostname by issuing a PTR query through
//! Sagittarius's own resolution path, so **private IPs resolve via E13** (local
//! PTR synth / conditional forwarding) and public IPs via the normal upstream
//! pool — and caches the result in a bounded, TTL'd store with **negative
//! caching** so a chatty query log never hammers the router.
//!
//! # Off the hot path
//!
//! This sits entirely beside the DNS response path. The admin render layer
//! (E14.2) reads cached names with [`ReverseResolver::cached`] (never blocking
//! on the network) and kicks off [`ReverseResolver::warm`] for misses; the
//! background warm populates the cache for the next render. The wired-in
//! service is the *internal* decision→cache→forward stack
//! ([`build_internal_service`](crate::resolver::pipeline::engine::build_internal_service)) —
//! **not** the full engine — so reverse lookups never appear in the live log or
//! count toward telemetry.
//!
//! # Single-flight
//!
//! Concurrent lookups for the same IP coalesce via `moka`'s `get_with`, so a
//! burst of rows for one client issues at most one PTR query.

use std::{net::IpAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use moka::future::Cache;
use tower::{Service, ServiceExt as _};

use crate::{
    codec::{
        header::Header,
        message::{Qtype, Query},
        name::Name,
        writer::Writer,
    },
    resolver::pipeline::{BoxError, DnsRequest, PipelineResponse},
};

/// Default maximum number of distinct client IPs to remember.
const DEFAULT_CAPACITY: u64 = 4_096;

/// Default lifetime of a cached reverse-lookup result (positive *or* negative).
///
/// A modest window bounds how stale a name can be after a DHCP lease changes
/// while still absorbing a chatty log; expiry drives the lazy "periodic
/// refresh" on the next access.
const DEFAULT_TTL: Duration = Duration::from_secs(15 * 60);

/// Synthetic client address stamped on internally-issued PTR queries.
///
/// The query never leaves the process, so the value is cosmetic — it only
/// needs to be a valid loopback socket address for [`DnsRequest::new`].
fn synthetic_client() -> std::net::SocketAddr {
    std::net::SocketAddr::from(([127, 0, 0, 1], 0))
}

// ── ReverseResolver ────────────────────────────────────────────────────────────

/// Resolves client IPs to hostnames through an internal DNS service, caching
/// results (including "no hostname") in a bounded, TTL'd store.
///
/// Generic over the inner service `S` so tests can wire a stub (or the real
/// E13-backed decision stack); production stores the boxed internal stack via
/// [`SharedReverseResolver`].
///
/// The service is held behind a [`std::sync::Mutex`] purely so the whole
/// resolver is `Sync` (a boxed `tower` service is `Send` but not `Sync`); the
/// lock is held only long enough to clone the cheap [`Clone`] handle, never
/// across an `.await`.
pub struct ReverseResolver<S> {
    service: std::sync::Mutex<S>,
    cache: Cache<IpAddr, Option<Name>>,
}

impl<S> ReverseResolver<S>
where
    S: Service<DnsRequest, Response = PipelineResponse, Error = BoxError> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    /// Build a resolver over `service` with the default capacity and TTL.
    pub fn new(service: S) -> Self {
        Self::with_bounds(service, DEFAULT_CAPACITY, DEFAULT_TTL)
    }

    /// Build a resolver with explicit cache bounds (used by tests).
    pub fn with_bounds(service: S, capacity: u64, ttl: Duration) -> Self {
        let cache = Cache::builder()
            .max_capacity(capacity)
            .time_to_live(ttl)
            .build();
        Self {
            service: std::sync::Mutex::new(service),
            cache,
        }
    }

    /// Resolve `ip` to a hostname, consulting and populating the cache.
    ///
    /// A successful PTR answer caches the name; a failure or an answer with no
    /// PTR record caches `None` (negative caching). Concurrent lookups for the
    /// same IP coalesce into a single query.
    pub async fn lookup(&self, ip: IpAddr) -> Option<Name> {
        let service = self
            .service
            .lock()
            .expect("reverse-lookup service mutex poisoned")
            .clone();
        self.cache.get_with(ip, Self::resolve(service, ip)).await
    }

    /// Return a cached hostname for `ip` **without** issuing a lookup.
    ///
    /// Returns `Some(name)` only when a positive result is already cached;
    /// `None` for a cache miss *or* a cached negative result. The render layer
    /// uses this so a page never blocks on the router.
    pub async fn cached(&self, ip: IpAddr) -> Option<Name> {
        self.cache.get(&ip).await.flatten()
    }

    /// Warm the cache for `ip` in the background, if it is not already cached.
    ///
    /// Fire-and-forget: spawns a detached task that runs [`lookup`](Self::lookup)
    /// (single-flighted, so duplicate warms collapse). The render layer calls
    /// this on a cache miss so the *next* page render shows the hostname.
    ///
    /// The [`Mutex`](std::sync::Mutex) makes `ReverseResolver` `Sync` even when
    /// the inner service is only `Send` (a boxed `tower` service), so an
    /// `Arc<Self>` is `Send` and can cross the spawn boundary.
    pub fn warm(self: &Arc<Self>, ip: IpAddr) {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            this.lookup(ip).await;
        });
    }

    /// Issue the PTR query through the internal service and extract the name.
    async fn resolve(service: S, ip: IpAddr) -> Option<Name> {
        let raw = ptr_query_datagram(&Name::reverse_query(ip));
        let query = Query::try_from(raw).ok()?;
        let request = DnsRequest::new(query, synthetic_client());
        let response = service.oneshot(request).await.ok()?;
        extract_ptr(&response.bytes)
    }
}

// ── Wire helpers ────────────────────────────────────────────────────────────────

/// Encode a minimal PTR query datagram for the reverse-zone `name`.
fn ptr_query_datagram(name: &Name) -> Bytes {
    let mut w = Writer::with_capacity(64);
    Header::new(0).with_qdcount(1).with_rd(true).write(&mut w);
    name.write(&mut w);
    w.write_u16(u16::from(Qtype::Ptr));
    w.write_u16(1); // QCLASS IN
    w.finish()
}

/// Extract the first PTR target name from a DNS response, or `None` if the
/// response is unparsable or carries no PTR answer.
fn extract_ptr(bytes: &[u8]) -> Option<Name> {
    use hickory_net::proto::op::Message;
    use hickory_net::proto::rr::RData;

    let message = Message::from_vec(bytes).ok()?;
    message
        .answers
        .iter()
        .find_map(|record| match &record.data {
            // hickory's PTR `Display` yields the target without a trailing dot;
            // our `Name` parser accepts that and re-normalizes.
            RData::PTR(ptr) => ptr.to_string().parse::<Name>().ok(),
            _ => None,
        })
}

// ── Shared alias ────────────────────────────────────────────────────────────────

/// The boxed internal DNS service the production resolver runs over.
pub type InternalDnsService = tower::util::BoxCloneService<DnsRequest, PipelineResponse, BoxError>;

/// Shared, app-wide reverse resolver handle stored in the web `AppState`.
pub type SharedReverseResolver = Arc<ReverseResolver<InternalDnsService>>;

// ── Tests ───────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use bytes::Bytes;
    use tower::ServiceExt as _;

    use super::*;
    use crate::codec::{
        header::{Header, Rcode},
        name::Name,
        writer::Writer,
    };
    use crate::resolver::pipeline::{DnsRequest, Outcome, PipelineResponse};

    /// Build a PTR response: QR=1, one answer `<question> PTR <target>`.
    ///
    /// The owner name is the question's reverse name (copied via the answer
    /// owner compression pointer to offset 12), and the RDATA is `target`.
    fn ptr_response(req: &DnsRequest, target: &str) -> Bytes {
        let mut w = Writer::with_capacity(128);
        Header::new(req.header().id)
            .with_qr(true)
            .with_rcode(Rcode::NoError)
            .with_qdcount(1)
            .with_ancount(1)
            .write(&mut w);
        // Question section: the reverse-zone name / PTR / IN.
        req.question().name.write(&mut w);
        w.write_u16(u16::from(Qtype::Ptr));
        w.write_u16(1); // IN

        // Answer: owner = pointer to the question name at offset 12.
        w.write_u8(0xC0);
        w.write_u8(0x0C);
        w.write_u16(u16::from(Qtype::Ptr));
        w.write_u16(1); // IN
        w.write_u32(300); // TTL
        let target_name: Name = target.parse().unwrap();
        let mut rdata = Writer::with_capacity(64);
        target_name.write(&mut rdata);
        let rdata = rdata.finish();
        w.write_u16(rdata.len() as u16);
        w.write_slice(&rdata);
        w.finish()
    }

    /// A cloneable stub service that answers PTR for one known IP and counts
    /// how many times it was actually called (to prove caching).
    #[derive(Clone)]
    struct StubService {
        target: &'static str,
        calls: Arc<AtomicUsize>,
    }

    impl Service<DnsRequest> for StubService {
        type Response = PipelineResponse;
        type Error = BoxError;
        type Future = std::future::Ready<Result<PipelineResponse, BoxError>>;

        fn poll_ready(
            &mut self,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: DnsRequest) -> Self::Future {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let bytes = ptr_response(&req, self.target);
            std::future::ready(Ok(PipelineResponse::new(bytes, Outcome::Local)))
        }
    }

    /// A stub that always replies NXDOMAIN-ish (no answers), so the resolver
    /// must cache a negative result.
    #[derive(Clone)]
    struct EmptyService {
        calls: Arc<AtomicUsize>,
    }

    impl Service<DnsRequest> for EmptyService {
        type Response = PipelineResponse;
        type Error = BoxError;
        type Future = std::future::Ready<Result<PipelineResponse, BoxError>>;

        fn poll_ready(
            &mut self,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: DnsRequest) -> Self::Future {
            self.calls.fetch_add(1, Ordering::SeqCst);
            // A bare header (QR=1, no answers) is enough for hickory to parse
            // and find no PTR.
            let mut w = Writer::with_capacity(32);
            Header::new(req.header().id)
                .with_qr(true)
                .with_qdcount(1)
                .write(&mut w);
            req.question().name.write(&mut w);
            w.write_u16(u16::from(Qtype::Ptr));
            w.write_u16(1);
            std::future::ready(Ok(PipelineResponse::new(w.finish(), Outcome::Servfail)))
        }
    }

    #[tokio::test]
    async fn resolves_and_caches_a_hostname() {
        let calls = Arc::new(AtomicUsize::new(0));
        let svc = StubService {
            target: "router.home.lan",
            calls: Arc::clone(&calls),
        };
        let resolver = ReverseResolver::new(svc);

        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let name = resolver.lookup(ip).await.expect("hostname");
        assert_eq!(name.to_string(), "router.home.lan.");
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // A repeated lookup is served from the cache — no second query.
        let again = resolver.lookup(ip).await.expect("cached hostname");
        assert_eq!(again.to_string(), "router.home.lan.");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "must not re-query");
    }

    #[tokio::test]
    async fn negative_result_is_cached() {
        let calls = Arc::new(AtomicUsize::new(0));
        let svc = EmptyService {
            calls: Arc::clone(&calls),
        };
        let resolver = ReverseResolver::new(svc);

        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        assert!(resolver.lookup(ip).await.is_none(), "no PTR → None");
        assert!(resolver.lookup(ip).await.is_none(), "still None");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "negative result must be cached (one query only)"
        );
    }

    #[tokio::test]
    async fn cached_does_not_trigger_a_lookup() {
        let calls = Arc::new(AtomicUsize::new(0));
        let svc = StubService {
            target: "host.lan",
            calls: Arc::clone(&calls),
        };
        let resolver = ReverseResolver::new(svc);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));

        // Nothing cached yet → cached() returns None and issues no query.
        assert!(resolver.cached(ip).await.is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 0, "cached() must not query");

        // After a lookup, the cached value is available without re-querying.
        resolver.lookup(ip).await.expect("hostname");
        assert_eq!(
            resolver.cached(ip).await.map(|n| n.to_string()),
            Some("host.lan.".to_owned())
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn warm_populates_the_cache() {
        let calls = Arc::new(AtomicUsize::new(0));
        let svc = StubService {
            target: "warm.lan",
            calls: Arc::clone(&calls),
        };
        let resolver = Arc::new(ReverseResolver::new(svc));
        let ip = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));

        resolver.warm(ip);
        // Poll the cache until the background warm lands (bounded).
        let mut name = None;
        for _ in 0..100 {
            if let Some(n) = resolver.cached(ip).await {
                name = Some(n);
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(
            name.map(|n| n.to_string()),
            Some("warm.lan.".to_owned()),
            "warm must populate the cache"
        );
    }

    /// End-to-end through the *real* internal service (E13 local PTR synth):
    /// a local A record's IP resolves to its hostname via the decision stack,
    /// with no upstream involved.
    #[tokio::test]
    async fn resolves_local_record_through_real_engine() {
        use std::time::Duration;

        use crate::resolver::{
            local::{LocalRecords, RecordData},
            pipeline::engine::build_internal_service,
            state::ResolverState,
            upstream::{RandomSelector, SharedUpstreamPool, UpstreamPool},
        };
        use tokio_util::task::TaskTracker;

        let (_dir, db) = crate::test_support::temp_db().await;
        let state = ResolverState::hydrate(&db).await.expect("hydrate");

        // A local A record gives the reverse index (E13.2) something to answer.
        let mut b = LocalRecords::builder();
        b.add(
            "router.home.lan",
            RecordData::A("192.168.1.1".parse().unwrap()),
            300,
        )
        .unwrap();
        state.local().store(b.build());

        // Empty upstream pool: a non-local reverse query would SERVFAIL, so a
        // resolved name proves it came from the local synth path.
        let tracker = TaskTracker::new();
        let pool = Arc::new(SharedUpstreamPool::new(
            UpstreamPool::connect(
                &[],
                &tracker,
                Arc::new(RandomSelector),
                0,
                Duration::from_millis(500),
            )
            .await,
        ));

        let resolver = ReverseResolver::new(build_internal_service(state, pool));

        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(
            resolver.lookup(ip).await.map(|n| n.to_string()),
            Some("router.home.lan.".to_owned()),
            "local IP must resolve via the E13 reverse index"
        );

        // An IP we do not own has no PTR and no upstream → negative cache.
        let unknown = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200));
        assert!(resolver.lookup(unknown).await.is_none());
    }

    /// The stub composes as a real `tower` service (oneshot round-trip).
    #[tokio::test]
    async fn stub_service_shape_round_trips() {
        let svc = StubService {
            target: "x.lan",
            calls: Arc::new(AtomicUsize::new(0)),
        };
        let raw = ptr_query_datagram(&Name::reverse_query(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
        let req = DnsRequest::new(Query::try_from(raw).unwrap(), synthetic_client());
        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(
            extract_ptr(&resp.bytes).map(|n| n.to_string()),
            Some("x.lan.".to_owned())
        );
    }
}
