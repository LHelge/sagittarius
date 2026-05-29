//! DNS wire-format codec.
//!
//! A custom, *lazy* parser and serializer over [`bytes::Bytes`].  The design
//! deliberately avoids a full up-front parse: outer tower middleware layers
//! route on a **shallow parse** (12-byte header + the single question only)
//! and can short-circuit without touching the answer or additional sections.
//!
//! Key properties (see SPEC §2.1 for the full rationale):
//! - The question name is never compressed in a well-formed packet, so the
//!   shallow parser needs no name-decompression logic at all.
//! - The original datagram is carried as a refcounted `Bytes` through the
//!   pipeline, avoiding re-serialization for forwarded/cached responses.
//! - The codec defensively rejects packets with `QDCOUNT != 1` and any
//!   compression pointer appearing in the question section.

/// Errors that can occur while parsing or serializing DNS wire format.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The message was too short to contain a valid DNS header.
    #[error("message too short: need at least 12 bytes, got {0}")]
    MessageTooShort(usize),

    /// The question count was not exactly 1.
    #[error("expected QDCOUNT=1, got {0}")]
    InvalidQuestionCount(u16),

    /// A compression pointer was found in the question section.
    #[error("compression pointer in question section is not allowed")]
    CompressionPointerInQuestion,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_variants_display() {
        assert!(Error::MessageTooShort(4).to_string().contains('4'));
        assert!(Error::InvalidQuestionCount(2).to_string().contains('2'));
        assert!(!Error::CompressionPointerInQuestion.to_string().is_empty());
    }
}
