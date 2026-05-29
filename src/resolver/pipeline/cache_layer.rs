//! Read-through cache layer (SPEC §5 step 7, §8).
//!
//! [`CacheService`] is a `tower` layer that sits between the decision stack
//! (E6.2) and the upstream-forward leaf (E6.3).  It owns the cache **mechanism**
//! — lookup on the way in, store on the way out — while the *policy* (what TTL,
//! whether an answer is cacheable at all) stays in the forward service, which
//! communicates it back via a [`CacheDirective`] carried in [`ForwardOutput`].
//!
//! Splitting the cache out as its own layer (rather than folding the read into
//! the decision stack and the write into the leaf) keeps the cache↔forward
//! boundary a real composition seam: future middleware that should run only on
//! cache *misses* — upstream rate limiting, single-flight request coalescing,
//! upstream metrics, DNSSEC validation — slots in between [`CacheService`] and
//! the forward service without touching either.
//!
//! # Flow
//!
//! On `call`:
//! 1. Look up `(qname, qtype, qclass)` in the [`DnsCache`](crate::resolver::cache::DnsCache).
//!    On a hit, serve the patched bytes immediately ([`Outcome::Cached`]) — the
//!    inner service is never polled.
//! 2. On a miss, call the inner service.  Its [`ForwardOutput`] carries the
//!    client-facing reply plus a [`CacheDirective`]: [`CacheDirective::Store`]
//!    inserts the upstream bytes under the supplied expiry; [`CacheDirective::Skip`]
//!    leaves the cache untouched.
//! 3. Return the inner service's reply to the caller.

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use tower::{Layer, Service};

use crate::resolver::{
    pipeline::{BoxError, DnsRequest, Outcome, PipelineResponse},
    state::ResolverState,
};

// ── CacheDirective ──────────────────────────────────────────────────────────

/// What the cache layer should do with the inner service's response.
///
/// Produced by the forward service (which alone has the upstream response
/// metadata — TTL-field offsets, the positive min TTL, and the RFC 2308
/// negative TTL) and executed by [`CacheService`].  This keeps the cache
/// *policy* in the forward leaf and the *mechanism* in this layer.
#[derive(Debug, Clone)]
pub enum CacheDirective {
    /// Store these exact upstream wire bytes under the given clamped expiry.
    ///
    /// `bytes` are the raw upstream response (un-patched transaction ID); the
    /// cache patches the ID and decrements the TTLs at the recorded
    /// `ttl_offsets` on serve.  `expiry` is the caller-computed lifetime in
    /// seconds (negative-TTL cap already applied); the cache clamps it to the
    /// configured min/max bounds on insert.
    Store {
        /// Upstream response bytes to cache.
        bytes: Bytes,
        /// Byte offsets of each real RR TTL field (from the TTL scan).
        ttl_offsets: Vec<usize>,
        /// Pre-clamp expiry in seconds.
        expiry: u32,
    },
    /// Do not cache this response (SOA-less negative, no real TTL-bearing RRs,
    /// an unscannable response, or an error reply such as SERVFAIL).
    Skip,
}

// ── ForwardOutput ─────────────────────────────────────────────────────────────

/// The response type of the inner (forward) service wrapped by [`CacheService`].
///
/// Bundles the client-facing [`PipelineResponse`] with the [`CacheDirective`]
/// the cache layer should act on.  The directive is stripped by the cache layer,
/// so everything above it sees a plain [`PipelineResponse`].
#[derive(Debug, Clone)]
pub struct ForwardOutput {
    /// The reply to return to the client (transaction ID already patched).
    pub reply: PipelineResponse,
    /// How the cache layer should treat this response.
    pub directive: CacheDirective,
}

impl ForwardOutput {
    /// Bundle a client reply with its cache directive.
    pub fn new(reply: PipelineResponse, directive: CacheDirective) -> Self {
        Self { reply, directive }
    }
}

// ── CacheLayer ──────────────────────────────────────────────────────────────

/// A [`tower::Layer`] that wraps a forward service with [`CacheService`].
pub struct CacheLayer {
    state: Arc<ResolverState>,
}

impl CacheLayer {
    /// Create a new [`CacheLayer`] backed by `state`'s cache.
    pub fn new(state: Arc<ResolverState>) -> Self {
        Self { state }
    }
}

impl<S> Layer<S> for CacheLayer {
    type Service = CacheService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CacheService::new(self.state.clone(), inner)
    }
}

// ── CacheService ──────────────────────────────────────────────────────────────

/// A read-through cache wrapping an inner forward service.
///
/// `S` is the forward service: `Service<DnsRequest, Response = ForwardOutput>`.
/// On a cache hit the inner service is not called; on a miss its directive
/// drives the store.
#[derive(Clone)]
pub struct CacheService<S> {
    state: Arc<ResolverState>,
    inner: S,
}

impl<S> CacheService<S> {
    /// Create a new [`CacheService`] wrapping `inner`, backed by `state`'s cache.
    pub fn new(state: Arc<ResolverState>, inner: S) -> Self {
        Self { state, inner }
    }
}

impl<S> Service<DnsRequest> for CacheService<S>
where
    S: Service<DnsRequest, Response = ForwardOutput, Error = BoxError> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = PipelineResponse;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<PipelineResponse, BoxError>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: DnsRequest) -> Self::Future {
        let question = req.question().clone();
        let client_id = req.header().id;
        let state = self.state.clone();

        // Clone-and-replace: move the poll_ready'd inner into the future and
        // leave a fresh clone in `self` (the standard tower pattern).
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            // Read: serve from cache on a hit (bytes already patched with the
            // client's id + decremented TTLs by DnsCache::get).
            if let Some(bytes) = state.cache().get(&question, client_id).await {
                return Ok(PipelineResponse::new(bytes, Outcome::Cached));
            }

            // Miss: forward, then store per the directive.
            let out = inner.call(req).await?;
            if let CacheDirective::Store {
                bytes,
                ttl_offsets,
                expiry,
            } = out.directive
            {
                state
                    .cache()
                    .insert(question, bytes, ttl_offsets, expiry)
                    .await;
            }
            Ok(out.reply)
        })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, time::Duration};

    use bytes::Bytes;
    use tempfile::TempDir;
    use tokio::time::timeout;
    use tower::ServiceExt as _;

    use super::*;
    use crate::{
        codec::{
            header::Header,
            message::{Qclass, Qtype, Query, Question},
            name::Name,
            writer::Writer,
        },
        resolver::state::ResolverState,
        storage::Db,
    };

    async fn hydrate_state() -> (TempDir, Arc<ResolverState>) {
        let dir = TempDir::new().expect("temp dir");
        let db = Db::connect(dir.path().join("test.db"))
            .await
            .expect("connect");
        let state = ResolverState::hydrate(&db).await.expect("hydrate");
        (dir, state)
    }

    /// Build a minimal DNS A datagram for `name` with `id` (used as stand-in
    /// "stored bytes"; content is opaque to the cache).
    fn build_a_datagram(id: u16, name: &str) -> Bytes {
        let mut w = Writer::with_capacity(64);
        Header::new(id).with_qdcount(1).with_rd(true).write(&mut w);
        let n: Name = name.parse().expect("valid name");
        n.write(&mut w);
        w.write_u16(1u16); // QTYPE A
        w.write_u16(1u16); // QCLASS IN
        w.finish()
    }

    fn request(id: u16, name: &str) -> DnsRequest {
        let client: SocketAddr = "127.0.0.1:5353".parse().unwrap();
        let query = Query::try_from(build_a_datagram(id, name)).expect("valid query");
        DnsRequest::new(query, client)
    }

    fn question(name: &str) -> Question {
        Question {
            name: name.parse().unwrap(),
            qtype: Qtype::A,
            qclass: Qclass::In,
        }
    }

    /// Read the transaction id (bytes 0–1) from a response buffer.
    fn txn_id(bytes: &Bytes) -> u16 {
        u16::from_be_bytes([bytes[0], bytes[1]])
    }

    // ── Cache hit short-circuits the inner service ─────────────────────────────

    #[tokio::test]
    async fn hit_serves_cached_without_calling_inner() {
        let (_dir, state) = hydrate_state().await;

        // Pre-populate the cache for example.com / A / IN.
        let stored = build_a_datagram(0xAAAA, "example.com");
        state
            .cache()
            .insert(question("example.com"), stored, vec![], 300)
            .await;

        // Inner stub would return Forwarded — if it ran we'd see Forwarded, not Cached.
        let inner = tower::service_fn(|_req: DnsRequest| async move {
            Ok::<_, BoxError>(ForwardOutput::new(
                PipelineResponse::new(Bytes::from_static(b"unused"), Outcome::Forwarded),
                CacheDirective::Skip,
            ))
        });
        let svc = CacheService::new(state, inner);

        let client_id = 0xBEEF;
        let resp = timeout(
            Duration::from_secs(5),
            svc.oneshot(request(client_id, "example.com")),
        )
        .await
        .expect("safety timeout")
        .expect("service ok");

        assert_eq!(resp.outcome, Outcome::Cached, "hit must serve from cache");
        assert_eq!(
            txn_id(&resp.bytes),
            client_id,
            "cache must patch the txn id to the requesting client"
        );
    }

    // ── Miss + Store directive inserts ─────────────────────────────────────────

    #[tokio::test]
    async fn miss_with_store_directive_inserts() {
        let (_dir, state) = hydrate_state().await;

        let inner = tower::service_fn(|req: DnsRequest| async move {
            // Echo the request bytes as the stored payload; empty offsets are fine.
            let bytes = req.raw().clone();
            Ok::<_, BoxError>(ForwardOutput::new(
                PipelineResponse::new(bytes.clone(), Outcome::Forwarded),
                CacheDirective::Store {
                    bytes,
                    ttl_offsets: vec![],
                    expiry: 300,
                },
            ))
        });
        let svc = CacheService::new(state.clone(), inner);

        let resp = timeout(
            Duration::from_secs(5),
            svc.oneshot(request(0x1234, "store.example")),
        )
        .await
        .expect("safety timeout")
        .expect("service ok");
        assert_eq!(resp.outcome, Outcome::Forwarded);

        // The miss path must have stored the entry.
        assert!(
            state
                .cache()
                .get(&question("store.example"), 0x9999)
                .await
                .is_some(),
            "Store directive must insert into the cache"
        );
    }

    // ── Miss + Skip directive does not insert ──────────────────────────────────

    #[tokio::test]
    async fn miss_with_skip_directive_does_not_insert() {
        let (_dir, state) = hydrate_state().await;

        let inner = tower::service_fn(|req: DnsRequest| async move {
            Ok::<_, BoxError>(ForwardOutput::new(
                PipelineResponse::new(req.raw().clone(), Outcome::Servfail),
                CacheDirective::Skip,
            ))
        });
        let svc = CacheService::new(state.clone(), inner);

        let resp = timeout(
            Duration::from_secs(5),
            svc.oneshot(request(0x4321, "skip.example")),
        )
        .await
        .expect("safety timeout")
        .expect("service ok");
        assert_eq!(resp.outcome, Outcome::Servfail);

        assert!(
            state
                .cache()
                .get(&question("skip.example"), 0x9999)
                .await
                .is_none(),
            "Skip directive must not insert into the cache"
        );
    }
}
