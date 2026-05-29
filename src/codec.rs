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
//!
//! # Module layout
//!
//! | Submodule | Responsibility |
//! |---|---|
//! | [`reader`] | Bounds-checked cursor over `bytes::Bytes` for parsing |
//! | [`writer`] | Append-only output buffer over `bytes::BytesMut` for synthesis |
//! | [`framing`] | UDP/TCP message framing (length-prefix encode/decode) |
//!
//! All submodules share this single [`Error`] type; the crate-level
//! [`crate::error::Error`] wraps it via `#[from]`.

pub mod framing;
pub mod reader;
pub mod writer;

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

    /// A read attempted to consume more bytes than are available in the buffer.
    ///
    /// Returned whenever a `read_u8`, `read_u16`, `read_u32`, or `read_slice`
    /// call would go past the end of the underlying buffer — never panics.
    #[error(
        "unexpected end of buffer at offset {offset}: need {needed} bytes, {available} available"
    )]
    UnexpectedEof {
        /// Byte offset at which the read was attempted.
        offset: usize,
        /// Number of bytes the attempted read needed.
        needed: usize,
        /// Number of bytes actually remaining from that offset.
        available: usize,
    },

    /// A TCP length-prefix frame was truncated: the 2-byte prefix was not fully
    /// received.
    #[error("TCP length prefix is truncated: need 2 bytes, got {0}")]
    TruncatedLengthPrefix(usize),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_variants_display() {
        assert!(Error::MessageTooShort(4).to_string().contains('4'));
        assert!(Error::InvalidQuestionCount(2).to_string().contains('2'));
        assert!(!Error::CompressionPointerInQuestion.to_string().is_empty());

        let eof = Error::UnexpectedEof {
            offset: 10,
            needed: 4,
            available: 2,
        };
        let s = eof.to_string();
        assert!(s.contains("10"), "offset should appear in message: {s}");
        assert!(s.contains('4'), "needed should appear in message: {s}");
        assert!(s.contains('2'), "available should appear in message: {s}");

        assert!(Error::TruncatedLengthPrefix(1).to_string().contains('1'));
    }
}
