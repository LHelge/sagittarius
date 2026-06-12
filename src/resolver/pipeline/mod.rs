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
    synth::EdnsInfo,
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
    /// EDNS information from the query's OPT pseudo-RR, scanned **once** at
    /// construction and shared by every consumer (UDP size limit, response
    /// synthesis in the decision layers, the SERVFAIL path).
    edns: Option<EdnsInfo>,
    /// Set by the allowlist layer to tell the blocklist layer to stand down.
    ///
    /// `false` by default.  When `true`, a [`crate::resolver::matchset`] hit
    /// in the blocklist layer should be skipped and the request forwarded.
    allow_bypass: bool,
}

impl DnsRequest {
    /// Create a new [`DnsRequest`].
    ///
    /// Scans the query's additional section for EDNS information here, once,
    /// so the pipeline layers can read [`DnsRequest::edns`] instead of
    /// re-walking the RR sections.  `allow_bypass` starts as `false`; the
    /// allowlist layer may flip it via [`DnsRequest::set_allow_bypass`].
    pub fn new(query: Query, client: SocketAddr) -> Self {
        let edns = EdnsInfo::scan(&query);
        Self {
            query,
            client,
            edns,
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

    /// EDNS information from the query's OPT pseudo-RR, if it carried one.
    ///
    /// Scanned once in [`DnsRequest::new`]; pass to the
    /// [`crate::codec::synth::Response`] builders when synthesizing replies.
    pub fn edns(&self) -> Option<&EdnsInfo> {
        self.edns.as_ref()
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
/// The `#[strum(serialize = …)]` tokens are the stable on-disk
/// `query_log.outcome` values: `IntoStaticStr` drives [`Outcome::as_str`] and
/// `EnumString` drives [`FromStr`](std::str::FromStr) from the same single
/// source of truth, so the two can never drift. `EnumIter` lets tests iterate
/// every variant without a hand-maintained list. The human-facing
/// [`Display`](std::fmt::Display) labels are intentionally *separate* (see below).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, strum::EnumString, strum::IntoStaticStr, strum::EnumIter,
)]
pub enum Outcome {
    /// Answered from an authoritative local record.
    #[strum(serialize = "local")]
    Local,
    /// Local name exists but has no record for the requested QTYPE
    /// (authoritative NODATA response).
    #[strum(serialize = "local-nodata")]
    LocalNoData,
    /// Blocked by the admin blacklist; the allowlist cannot override this.
    #[strum(serialize = "blocked-admin")]
    BlockedByAdmin,
    /// Blocked by an aggregated blocklist entry; the allowlist *can* override.
    #[strum(serialize = "blocked-blocklist")]
    BlockedByBlocklist,
    /// Served from the moka raw-bytes cache (TTL still valid).
    #[strum(serialize = "cached")]
    Cached,
    /// Resolved via an upstream resolver.
    #[strum(serialize = "forwarded")]
    Forwarded,
    /// Rejected by protective middleware (rate-limit / load-shed) — REFUSED.
    #[strum(serialize = "refused")]
    Refused,
    /// Malformed query with a recoverable transaction ID — FORMERR.
    #[strum(serialize = "formerr")]
    Formerr,
    /// All upstreams failed or the per-request timeout elapsed — SERVFAIL.
    #[strum(serialize = "servfail")]
    Servfail,
    /// Internal or other unclassified error.
    #[strum(serialize = "error")]
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
    /// `#[strum(serialize)]` token once shipped — old rows would fail to decode.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        self.into()
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

    // ── DnsRequest accessors ──────────────────────────────────────────────────

    #[test]
    fn dns_request_accessors_and_allow_bypass() {
        let raw = crate::test_support::a_query(0x1234, "example.com");
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

    /// The EDNS info is scanned once at construction: absent without an OPT,
    /// present (and matching a fresh scan) with one.
    #[test]
    fn dns_request_carries_edns_info() {
        let client: SocketAddr = "127.0.0.1:5353".parse().unwrap();

        // Plain query — no OPT, no EDNS info.
        let plain = Query::try_from(crate::test_support::a_query(0x0001, "plain.example")).unwrap();
        assert!(DnsRequest::new(plain, client).edns().is_none());

        // Query with an OPT RR advertising a 4096-byte UDP payload.
        let mut w = Writer::with_capacity(64);
        Header::new(0x0002)
            .with_qdcount(1)
            .with_arcount(1)
            .write(&mut w);
        let name: Name = "edns.example".parse().unwrap();
        name.write(&mut w);
        w.write_u16(1); // QTYPE A
        w.write_u16(1); // QCLASS IN
        w.write_u8(0x00); // OPT owner: root
        w.write_u16(41); // TYPE OPT
        w.write_u16(4096); // CLASS = UDP payload size
        w.write_u32(0); // extended RCODE / version / flags
        w.write_u16(0); // RDLENGTH
        let query = Query::try_from(w.finish()).unwrap();

        let req = DnsRequest::new(query, client);
        let edns = req.edns().expect("OPT query must carry EDNS info");
        assert_eq!(edns.udp_payload_size, 4096);
        // The carried value matches a fresh scan of the same query.
        let fresh = EdnsInfo::scan(req.query()).expect("fresh scan finds the OPT");
        assert_eq!(fresh.udp_payload_size, edns.udp_payload_size);
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

    #[test]
    fn outcome_as_str_from_str_round_trips_every_variant() {
        use std::str::FromStr as _;
        use strum::IntoEnumIterator as _;
        for outcome in Outcome::iter() {
            let token = outcome.as_str();
            let parsed = Outcome::from_str(token)
                .unwrap_or_else(|e| panic!("token {token:?} must parse back: {e}"));
            assert_eq!(parsed, outcome, "round-trip mismatch for {token:?}");
        }
    }

    #[test]
    fn outcome_as_str_tokens_are_distinct() {
        use strum::IntoEnumIterator as _;
        let mut tokens: Vec<&str> = Outcome::iter().map(|o| o.as_str()).collect();
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

        let raw = crate::test_support::a_query(0xBEEF, "roundtrip.test");
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
