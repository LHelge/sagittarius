//! DNS resolution pipeline and resolver state.
//!
//! Implements the query lifecycle described in SPEC §5.  The resolution path
//! is expressed as a [`tower`] service stack.  Each layer routes on the
//! shallow parse result (question only) and either short-circuits with a
//! synthesised response (local records, blocklists, cache hits) or hands the
//! request to the next layer.
//!
//! Layers in order (outermost to innermost):
//! 1. Rate-limit / load-shed / timeout (tower middleware)
//! 2. Shallow parse (codec)
//! 3. Local records
//! 4. Admin blacklist
//! 5. Allowlist (sets bypass flag; never short-circuits)
//! 6. Blocklist set
//! 7. Cache lookup
//! 8. Upstream forwarding (inner service)
//!
//! The upstream client uses [`hickory`] for DoT/DoH transport.
//!
//! # Module layout
//!
//! | Submodule | Responsibility |
//! |---|---|
//! | [`cache`] | Raw-bytes moka cache with per-entry TTL expiry and in-place serve-from-cache patching |
//! | [`local`] | Authoritative local-record matcher (exact + wildcard suffix-probe, most-specific wins) |
//! | [`matchset`] | Lock-free, hot-swappable domain name set primitive (admin blacklist, allowlist, blocklist) |
//! | [`pipeline`] | Request/response model ([`pipeline::DnsRequest`], [`pipeline::PipelineResponse`], [`pipeline::Outcome`]) and tower service shape |
//! | [`state`] | [`state::ResolverState`] bundle + startup hydration (SPEC §3.1, §3.2) |
//! | [`upstream`] | Hickory-backed upstream transport clients (UDP/TCP/DoT/DoH) (SPEC §7) |

pub mod cache;
pub mod forward_zone;
pub mod local;
pub mod matchset;
pub mod pipeline;
pub mod state;
pub mod upstream;

/// A type alias for `Result<T, Error>` in the resolver module.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during DNS resolution.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// No upstream resolver is configured or all upstreams are unreachable.
    #[error("no upstream resolver available")]
    NoUpstreamAvailable,

    /// The upstream resolver returned a response that could not be used.
    #[error("upstream error: {0}")]
    Upstream(String),

    /// A storage error occurred during resolver state hydration.
    #[error("storage error during hydration: {0}")]
    Storage(#[from] crate::storage::Error),

    /// A local record row in the database contains an invalid value (e.g. a
    /// malformed IP address string, or a name that cannot be accepted by the
    /// local-record builder).
    #[error("invalid local record: {0}")]
    InvalidLocalRecord(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_variants_display() {
        assert!(!Error::NoUpstreamAvailable.to_string().is_empty());
        assert!(
            Error::Upstream("timeout".into())
                .to_string()
                .contains("timeout")
        );
        assert!(
            Error::InvalidLocalRecord("bad ip".into())
                .to_string()
                .contains("bad ip")
        );
    }
}
