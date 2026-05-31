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

pub mod cache_layer;
pub mod engine;
pub mod forward;
pub mod layers;
pub mod listener;
pub mod middleware;

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

/// The one-click action the live query log offers for a row, keyed purely on
/// its [`Outcome`] (not on the domain's current list membership).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogAction {
    /// Block a currently-resolving domain (add it to the admin blacklist).
    Block,
    /// Make a blocked domain resolve again.
    Unblock,
}

/// Classifies how a DNS query was answered.
///
/// Used for telemetry (E6.6) and admin UI one-click actions (E8).  The
/// classifier methods [`Outcome::is_blocked`] and [`Outcome::log_action`]
/// encode the SPEC §9 rules about which action each outcome offers.
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

    /// The one-click [`LogAction`] this outcome offers, if any.
    ///
    /// - A resolved answer (`Cached` / `Forwarded`) can be turned into a block.
    /// - A blocked answer (admin or blocklist) can be unblocked.
    /// - Everything else (local answers, errors) offers no action.
    #[must_use]
    pub fn log_action(&self) -> Option<LogAction> {
        match self {
            Self::Cached | Self::Forwarded => Some(LogAction::Block),
            Self::BlockedByAdmin | Self::BlockedByBlocklist => Some(LogAction::Unblock),
            _ => None,
        }
    }

    /// The stable persistence token for this outcome, used as the on-disk
    /// `query_log.outcome` value (E10).
    ///
    /// Unlike [`Display`](std::fmt::Display) (human labels for the UI, which may
    /// change) these tokens are a wire format: kebab-case, distinct per variant,
    /// and the exact inverse of [`FromStr`](std::str::FromStr). Never rename a
    /// token once shipped — old rows would fail to decode.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::LocalNoData => "local-nodata",
            Self::BlockedByAdmin => "blocked-admin",
            Self::BlockedByBlocklist => "blocked-blocklist",
            Self::Cached => "cached",
            Self::Forwarded => "forwarded",
            Self::Refused => "refused",
            Self::Formerr => "formerr",
            Self::Servfail => "servfail",
            Self::Error => "error",
        }
    }

    /// The coarse category used to group outcomes in the live query log
    /// (filtering and badge styling): `blocked`, `cached`, `forwarded`,
    /// `local`, or `other`.
    #[must_use]
    pub fn category(&self) -> &'static str {
        match self {
            Self::BlockedByAdmin | Self::BlockedByBlocklist => "blocked",
            Self::Cached => "cached",
            Self::Forwarded => "forwarded",
            Self::Local | Self::LocalNoData => "local",
            Self::Refused | Self::Formerr | Self::Servfail | Self::Error => "other",
        }
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

/// Error returned by [`Outcome`]'s [`FromStr`](std::str::FromStr) when the input
/// is not one of the stable [`Outcome::as_str`] tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseOutcomeError(String);

impl std::fmt::Display for ParseOutcomeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unknown outcome token: {:?}", self.0)
    }
}

impl std::error::Error for ParseOutcomeError {}

impl std::str::FromStr for Outcome {
    type Err = ParseOutcomeError;

    /// Parse a stable persistence token (the exact inverse of
    /// [`Outcome::as_str`]). Human [`Display`](std::fmt::Display) labels are
    /// *not* accepted.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "local" => Ok(Self::Local),
            "local-nodata" => Ok(Self::LocalNoData),
            "blocked-admin" => Ok(Self::BlockedByAdmin),
            "blocked-blocklist" => Ok(Self::BlockedByBlocklist),
            "cached" => Ok(Self::Cached),
            "forwarded" => Ok(Self::Forwarded),
            "refused" => Ok(Self::Refused),
            "formerr" => Ok(Self::Formerr),
            "servfail" => Ok(Self::Servfail),
            "error" => Ok(Self::Error),
            other => Err(ParseOutcomeError(other.to_owned())),
        }
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
    fn outcome_log_action() {
        // Resolved answers can be blocked.
        assert_eq!(Outcome::Cached.log_action(), Some(LogAction::Block));
        assert_eq!(Outcome::Forwarded.log_action(), Some(LogAction::Block));

        // Both kinds of blocked answer can be unblocked.
        assert_eq!(
            Outcome::BlockedByAdmin.log_action(),
            Some(LogAction::Unblock)
        );
        assert_eq!(
            Outcome::BlockedByBlocklist.log_action(),
            Some(LogAction::Unblock)
        );

        // Everything else offers no action.
        assert_eq!(Outcome::Local.log_action(), None);
        assert_eq!(Outcome::LocalNoData.log_action(), None);
        assert_eq!(Outcome::Refused.log_action(), None);
        assert_eq!(Outcome::Formerr.log_action(), None);
        assert_eq!(Outcome::Servfail.log_action(), None);
        assert_eq!(Outcome::Error.log_action(), None);
    }

    #[test]
    fn outcome_category_groups_variants() {
        assert_eq!(Outcome::BlockedByAdmin.category(), "blocked");
        assert_eq!(Outcome::BlockedByBlocklist.category(), "blocked");
        assert_eq!(Outcome::Cached.category(), "cached");
        assert_eq!(Outcome::Forwarded.category(), "forwarded");
        assert_eq!(Outcome::Local.category(), "local");
        assert_eq!(Outcome::LocalNoData.category(), "local");
        assert_eq!(Outcome::Refused.category(), "other");
        assert_eq!(Outcome::Servfail.category(), "other");
        assert_eq!(Outcome::Error.category(), "other");
    }

    /// Every `Outcome` variant, for exhaustive table-driven tests. A `match` in
    /// `as_str` keeps this honest: adding a variant without updating it fails to
    /// compile, prompting an addition here too.
    const ALL_OUTCOMES: &[Outcome] = &[
        Outcome::Local,
        Outcome::LocalNoData,
        Outcome::BlockedByAdmin,
        Outcome::BlockedByBlocklist,
        Outcome::Cached,
        Outcome::Forwarded,
        Outcome::Refused,
        Outcome::Formerr,
        Outcome::Servfail,
        Outcome::Error,
    ];

    #[test]
    fn outcome_as_str_from_str_round_trips_every_variant() {
        use std::str::FromStr as _;
        for &outcome in ALL_OUTCOMES {
            let token = outcome.as_str();
            let parsed = Outcome::from_str(token)
                .unwrap_or_else(|e| panic!("token {token:?} must parse back: {e}"));
            assert_eq!(parsed, outcome, "round-trip mismatch for {token:?}");
        }
    }

    #[test]
    fn outcome_as_str_tokens_are_distinct() {
        let mut tokens: Vec<&str> = ALL_OUTCOMES.iter().map(|o| o.as_str()).collect();
        let count = tokens.len();
        tokens.sort_unstable();
        tokens.dedup();
        assert_eq!(tokens.len(), count, "as_str tokens must all be distinct");
    }

    #[test]
    fn outcome_from_str_rejects_unknown() {
        use std::str::FromStr as _;
        // An unknown token and a human Display label must both be rejected.
        assert!(Outcome::from_str("nonsense").is_err());
        assert!(
            Outcome::from_str("blocked (admin)").is_err(),
            "Display labels are not the persistence format"
        );
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
