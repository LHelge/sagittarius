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
//! | [`matchset`] | Lock-free, hot-swappable domain name set primitive (admin blacklist, allowlist, blocklist) |

pub mod matchset;

/// Errors that can occur during DNS resolution.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// No upstream resolver is configured or all upstreams are unreachable.
    #[error("no upstream resolver available")]
    NoUpstreamAvailable,

    /// The upstream resolver returned a response that could not be used.
    #[error("upstream error: {0}")]
    Upstream(String),
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
    }
}
