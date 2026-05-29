//! DNS query pipeline: request/response model and tower service shape.
//!
//! This module defines the vocabulary that flows through the entire resolution
//! pipeline described in SPEC §5.  Every layer in the stack and the inner
//! forward service implement the same tower [`Service`] shape:
//!
//! ```text
//! tower::Service<DnsRequest, Response = PipelineResponse, Error = BoxError>
//! ```
//!
//! # Layer contract (SPEC §2.1, §5)
//!
//! Decision layers inspect [`DnsRequest::header`] and [`DnsRequest::question`]
//! only — never the raw answer/authority sections.  A layer either:
//! - **Short-circuits**: synthesises a [`PipelineResponse`] directly (e.g.
//!   blocklist hit → NXDOMAIN, cache hit → cached bytes), or
//! - **Falls through**: calls the next service unchanged (or with
//!   [`DnsRequest::set_allow_bypass`] set to `true` for the allowlist layer).
//!
//! The inner-most service is the upstream forwarding service (E6.3), which
//! always calls an upstream resolver and returns `Outcome::Forwarded`.
//!
//! # Error handling
//!
//! The [`BoxError`] alias lets layers return heterogeneous error types.  The
//! outermost error-handling middleware (E6.5) translates errors into
//! `SERVFAIL` or `FORMERR` wire responses before they leave the pipeline.
//!
//! # Module layout
//!
//! This is the pipeline module root.  Later E6 tasks add submodules:
//! - `pipeline/layers.rs` — decision layers (E6.2)
//! - `pipeline/forward.rs` — upstream forwarding inner service (E6.3)

pub mod layers;

use std::net::SocketAddr;

use bytes::Bytes;

use crate::codec::{
    header::Header,
    message::{Query, Question},
};

// ── BoxError ──────────────────────────────────────────────────────────────────

/// Shared boxed-error alias used across the tower stack.
///
/// Every layer and the inner service use this as their `Error` associated type,
/// allowing heterogeneous error sources without a monomorphic error enum.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

// ── DnsRequest ────────────────────────────────────────────────────────────────

/// The request type flowing through the DNS pipeline.
///
/// Wraps a shallow-parsed [`Query`] together with the client's socket address
/// and pipeline-control flags.  Cheap to clone — [`Bytes`] is refcounted,
/// [`Header`] is `Copy`, and [`Question`] holds a small `Name`.
#[derive(Debug, Clone)]
pub struct DnsRequest {
    /// The shallow-parsed DNS query (header + question + raw datagram).
    query: Query,
    /// Source address of the client that sent this query.
    client: SocketAddr,
    /// Set by the allowlist layer to tell the blocklist layer to stand down.
    ///
    /// `false` by default.  When `true`, a [`crate::resolver::matchset`] hit
    /// in the blocklist layer should be skipped and the request forwarded.
    allow_bypass: bool,
}

impl DnsRequest {
    /// Create a new [`DnsRequest`].
    ///
    /// `allow_bypass` starts as `false`; the allowlist layer may flip it via
    /// [`DnsRequest::set_allow_bypass`].
    pub fn new(query: Query, client: SocketAddr) -> Self {
        Self {
            query,
            client,
            allow_bypass: false,
        }
    }

    /// The parsed query (header + question + raw datagram).
    pub fn query(&self) -> &Query {
        &self.query
    }

    /// The raw datagram bytes (refcounted; zero-copy).
    ///
    /// Delegates to [`Query::raw`].
    pub fn raw(&self) -> &Bytes {
        self.query.raw()
    }

    /// The parsed 12-byte DNS header.
    ///
    /// Delegates to [`Query::header`].
    pub fn header(&self) -> &Header {
        self.query.header()
    }

    /// The single parsed question entry (QNAME + QTYPE + QCLASS).
    ///
    /// Delegates to [`Query::question`].
    pub fn question(&self) -> &Question {
        self.query.question()
    }

    /// The client's socket address.
    pub fn client(&self) -> SocketAddr {
        self.client
    }

    /// Whether the allowlist layer has granted bypass for blocklist matching.
    ///
    /// Returns `false` until [`DnsRequest::set_allow_bypass`] is called.
    pub fn allow_bypass(&self) -> bool {
        self.allow_bypass
    }

    /// Set the bypass flag.
    ///
    /// Called by the allowlist layer (E6.2) when the query name matches an
    /// allowlist entry, instructing the blocklist layer to skip its check.
    pub fn set_allow_bypass(&mut self, value: bool) {
        self.allow_bypass = value;
    }
}

// ── Outcome ───────────────────────────────────────────────────────────────────

/// Classifies how a DNS query was answered.
///
/// Used for telemetry (E6.6) and admin UI one-click actions (E8).  The
/// classifier methods [`Outcome::is_blocked`], [`Outcome::offers_whitelist`],
/// and [`Outcome::offers_blacklist`] encode the SPEC §9 rules about which
/// actions are available for each outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Answered from an authoritative local record.
    Local,
    /// Local name exists but has no record for the requested QTYPE
    /// (authoritative NODATA response).
    LocalNoData,
    /// Blocked by the admin blacklist; the allowlist cannot override this.
    BlockedByAdmin,
    /// Blocked by an aggregated blocklist entry; the allowlist *can* override.
    BlockedByBlocklist,
    /// Served from the moka raw-bytes cache (TTL still valid).
    Cached,
    /// Resolved via an upstream resolver.
    Forwarded,
    /// Rejected by protective middleware (rate-limit / load-shed) — REFUSED.
    Refused,
    /// Malformed query with a recoverable transaction ID — FORMERR.
    Formerr,
    /// All upstreams failed or the per-request timeout elapsed — SERVFAIL.
    Servfail,
    /// Internal or other unclassified error.
    Error,
}

impl Outcome {
    /// Returns `true` if the query was blocked (by admin blacklist or blocklist).
    #[must_use]
    pub fn is_blocked(&self) -> bool {
        matches!(self, Self::BlockedByAdmin | Self::BlockedByBlocklist)
    }

    /// Returns `true` if the one-click *whitelist* action is meaningful.
    ///
    /// Only `BlockedByBlocklist` qualifies — an admin block cannot be overridden
    /// by the allowlist, and resolved/local answers are not blocked.
    #[must_use]
    pub fn offers_whitelist(&self) -> bool {
        matches!(self, Self::BlockedByBlocklist)
    }

    /// Returns `true` if the one-click *blacklist* action is meaningful.
    ///
    /// Only `Cached` and `Forwarded` qualify — a resolved answer can be turned
    /// into a block.  Local answers and existing blocks cannot.
    #[must_use]
    pub fn offers_blacklist(&self) -> bool {
        matches!(self, Self::Cached | Self::Forwarded)
    }
}

impl std::fmt::Display for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Local => "local",
            Self::LocalNoData => "local (no data)",
            Self::BlockedByAdmin => "blocked (admin)",
            Self::BlockedByBlocklist => "blocked (blocklist)",
            Self::Cached => "cached",
            Self::Forwarded => "forwarded",
            Self::Refused => "refused",
            Self::Formerr => "formerr",
            Self::Servfail => "servfail",
            Self::Error => "error",
        };
        f.write_str(s)
    }
}

// ── PipelineResponse ──────────────────────────────────────────────────────────

/// The response produced by the DNS pipeline.
///
/// Contains the reply datagram to send back to the client and the outcome
/// classification for telemetry and the admin UI.
#[derive(Debug, Clone)]
pub struct PipelineResponse {
    /// The reply datagram to send to the client.
    pub bytes: Bytes,
    /// How the query was answered.
    pub outcome: Outcome,
}

impl PipelineResponse {
    /// Create a new [`PipelineResponse`].
    pub fn new(bytes: Bytes, outcome: Outcome) -> Self {
        Self { bytes, outcome }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{header::Header, message::Qtype, name::Name, writer::Writer};

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Build a minimal DNS A query datagram for `name` with the given `id`.
    fn build_a_query(id: u16, name: &str) -> Bytes {
        let mut w = Writer::with_capacity(64);
        let hdr = Header::new(id).with_qdcount(1).with_rd(true);
        hdr.write(&mut w);
        let n: Name = name.parse().expect("valid name in test helper");
        n.write(&mut w);
        w.write_u16(1u16); // QTYPE A
        w.write_u16(1u16); // QCLASS IN
        w.finish()
    }

    // ── DnsRequest accessors ──────────────────────────────────────────────────

    #[test]
    fn dns_request_accessors_and_allow_bypass() {
        let raw = build_a_query(0x1234, "example.com");
        let query = Query::try_from(raw.clone()).expect("valid query");
        let client: SocketAddr = "127.0.0.1:5353".parse().unwrap();

        let mut req = DnsRequest::new(query, client);

        // Client address
        assert_eq!(req.client(), client);

        // Header
        assert_eq!(req.header().id, 0x1234);
        assert!(req.header().rd());

        // Question
        assert_eq!(req.question().name.to_string(), "example.com.");
        assert_eq!(req.question().qtype, Qtype::A);

        // Raw bytes match original datagram
        assert_eq!(req.raw(), &raw);

        // allow_bypass starts false
        assert!(!req.allow_bypass());

        // set_allow_bypass flips it
        req.set_allow_bypass(true);
        assert!(req.allow_bypass());

        // And can be cleared
        req.set_allow_bypass(false);
        assert!(!req.allow_bypass());
    }

    // ── Outcome classifiers ───────────────────────────────────────────────────

    #[test]
    fn outcome_is_blocked() {
        assert!(Outcome::BlockedByAdmin.is_blocked());
        assert!(Outcome::BlockedByBlocklist.is_blocked());

        assert!(!Outcome::Local.is_blocked());
        assert!(!Outcome::LocalNoData.is_blocked());
        assert!(!Outcome::Cached.is_blocked());
        assert!(!Outcome::Forwarded.is_blocked());
        assert!(!Outcome::Refused.is_blocked());
        assert!(!Outcome::Formerr.is_blocked());
        assert!(!Outcome::Servfail.is_blocked());
        assert!(!Outcome::Error.is_blocked());
    }

    #[test]
    fn outcome_offers_whitelist() {
        // Only BlockedByBlocklist offers whitelist
        assert!(Outcome::BlockedByBlocklist.offers_whitelist());

        assert!(!Outcome::BlockedByAdmin.offers_whitelist());
        assert!(!Outcome::Local.offers_whitelist());
        assert!(!Outcome::LocalNoData.offers_whitelist());
        assert!(!Outcome::Cached.offers_whitelist());
        assert!(!Outcome::Forwarded.offers_whitelist());
        assert!(!Outcome::Refused.offers_whitelist());
        assert!(!Outcome::Formerr.offers_whitelist());
        assert!(!Outcome::Servfail.offers_whitelist());
        assert!(!Outcome::Error.offers_whitelist());
    }

    #[test]
    fn outcome_offers_blacklist() {
        // Only Cached and Forwarded offer blacklist
        assert!(Outcome::Cached.offers_blacklist());
        assert!(Outcome::Forwarded.offers_blacklist());

        assert!(!Outcome::Local.offers_blacklist());
        assert!(!Outcome::LocalNoData.offers_blacklist());
        assert!(!Outcome::BlockedByAdmin.offers_blacklist());
        assert!(!Outcome::BlockedByBlocklist.offers_blacklist());
        assert!(!Outcome::Refused.offers_blacklist());
        assert!(!Outcome::Formerr.offers_blacklist());
        assert!(!Outcome::Servfail.offers_blacklist());
        assert!(!Outcome::Error.offers_blacklist());
    }

    #[test]
    fn outcome_display() {
        assert_eq!(Outcome::Local.to_string(), "local");
        assert_eq!(Outcome::LocalNoData.to_string(), "local (no data)");
        assert_eq!(Outcome::BlockedByAdmin.to_string(), "blocked (admin)");
        assert_eq!(
            Outcome::BlockedByBlocklist.to_string(),
            "blocked (blocklist)"
        );
        assert_eq!(Outcome::Cached.to_string(), "cached");
        assert_eq!(Outcome::Forwarded.to_string(), "forwarded");
        assert_eq!(Outcome::Refused.to_string(), "refused");
        assert_eq!(Outcome::Formerr.to_string(), "formerr");
        assert_eq!(Outcome::Servfail.to_string(), "servfail");
        assert_eq!(Outcome::Error.to_string(), "error");
    }

    // ── Stub Service round-trip ───────────────────────────────────────────────

    /// Proves the tower::Service<DnsRequest, Response = PipelineResponse, Error = BoxError>
    /// shape compiles and round-trips correctly.
    #[tokio::test]
    async fn service_shape_round_trip() {
        use tower::ServiceExt as _;

        let raw = build_a_query(0xBEEF, "roundtrip.test");
        let query = Query::try_from(raw.clone()).expect("valid query");
        let client: SocketAddr = "127.0.0.1:5353".parse().unwrap();
        let request = DnsRequest::new(query, client);

        let svc = tower::service_fn(|req: DnsRequest| async move {
            Ok::<_, BoxError>(PipelineResponse::new(req.raw().clone(), Outcome::Forwarded))
        });

        let resp = svc.oneshot(request).await.expect("service must not error");

        assert_eq!(resp.outcome, Outcome::Forwarded);
        assert_eq!(resp.bytes, raw);
    }
}
