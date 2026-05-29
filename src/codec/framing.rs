//! DNS message framing helpers.
//!
//! Covers the two transport framing conventions used by DNS:
//!
//! ## UDP
//!
//! A UDP datagram carries exactly **one** DNS message with no additional
//! framing — the datagram boundary is the message boundary.  The helpers
//! here are trivial pass-throughs that document this property.
//!
//! ## TCP
//!
//! [RFC 1035 §4.2.2](https://www.rfc-editor.org/rfc/rfc1035#section-4.2.2)
//! specifies that DNS messages sent over TCP are prefixed with a **2-byte
//! big-endian length** field indicating the number of bytes in the following
//! message.  The length does **not** include the 2-byte prefix itself.
//!
//! [`tcp::encode_length_prefix`] prepends this prefix to a message buffer.
//! [`tcp::decode_length_prefix`] reads the prefix from a byte slice to learn
//! the expected message length, returning a typed error — never a panic — when
//! the prefix is truncated.

use bytes::{BufMut, Bytes, BytesMut};

use crate::codec::Error;

// ── UDP ──────────────────────────────────────────────────────────────────────

/// UDP framing utilities.
///
/// A UDP datagram is exactly one DNS message with no additional framing.
/// These helpers are trivial pass-throughs that make the intent explicit in
/// call sites.
pub mod udp {
    use bytes::Bytes;

    /// Return the DNS message bytes carried by a UDP datagram.
    ///
    /// A UDP datagram boundary is the message boundary, so no framing
    /// needs to be stripped — this function returns `datagram` unchanged.
    #[must_use]
    pub fn unwrap_datagram(datagram: Bytes) -> Bytes {
        datagram
    }

    /// Wrap a DNS message as a UDP datagram.
    ///
    /// UDP carries exactly one DNS message per datagram with no framing
    /// envelope — this function returns `message` unchanged.
    #[must_use]
    pub fn wrap_datagram(message: Bytes) -> Bytes {
        message
    }
}

// ── TCP ───────────────────────────────────────────────────────────────────────

/// TCP framing utilities.
///
/// DNS over TCP (RFC 1035 §4.2.2) uses a **2-byte big-endian length prefix**
/// that precedes each message.  The length value counts only the message
/// bytes, not the 2-byte prefix itself.
pub mod tcp {
    use super::*;

    /// The size of the TCP length-prefix field in bytes.
    pub const LENGTH_PREFIX_SIZE: usize = 2;

    /// Encode a DNS `message` for TCP transport by prepending the 2-byte
    /// big-endian length prefix.
    ///
    /// The returned [`Bytes`] is:
    /// `[high_byte_of_len, low_byte_of_len, ...message...]`
    ///
    /// # Panics
    ///
    /// Panics if `message.len() > u16::MAX` (65535 bytes) — DNS messages
    /// over TCP are bounded by the 16-bit length field.  In practice a valid
    /// DNS message is always far smaller.
    #[must_use]
    pub fn encode_length_prefix(message: &Bytes) -> Bytes {
        let msg_len = message.len();
        assert!(
            msg_len <= usize::from(u16::MAX),
            "DNS message too large for TCP framing: {msg_len} > 65535"
        );
        let mut buf = BytesMut::with_capacity(LENGTH_PREFIX_SIZE + msg_len);
        buf.put_u16(msg_len as u16);
        buf.put_slice(message);
        buf.freeze()
    }

    /// Decode the 2-byte TCP length-prefix from `frame_start`.
    ///
    /// Returns the message length as a `u16`.  The caller is responsible for
    /// then reading exactly that many subsequent bytes to obtain the DNS
    /// message body.
    ///
    /// This function only inspects the first 2 bytes of `frame_start`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TruncatedLengthPrefix`] when `frame_start` contains
    /// fewer than 2 bytes — never panics.
    pub fn decode_length_prefix(frame_start: &[u8]) -> Result<u16, Error> {
        if frame_start.len() < LENGTH_PREFIX_SIZE {
            return Err(Error::TruncatedLengthPrefix(frame_start.len()));
        }
        Ok(u16::from_be_bytes([frame_start[0], frame_start[1]]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── UDP ──────────────────────────────────────────────────────────────────

    #[test]
    fn udp_unwrap_is_identity() {
        let msg = Bytes::from_static(b"dns-message");
        assert_eq!(udp::unwrap_datagram(msg.clone()), msg);
    }

    #[test]
    fn udp_wrap_is_identity() {
        let msg = Bytes::from_static(b"dns-message");
        assert_eq!(udp::wrap_datagram(msg.clone()), msg);
    }

    // ── TCP encode ────────────────────────────────────────────────────────────

    #[test]
    fn tcp_encode_prepends_big_endian_length() {
        let msg = Bytes::from_static(b"hello");
        let framed = tcp::encode_length_prefix(&msg);
        // 5-byte message → prefix bytes [0x00, 0x05]
        assert_eq!(framed[0], 0x00);
        assert_eq!(framed[1], 0x05);
        assert_eq!(&framed[2..], b"hello");
    }

    #[test]
    fn tcp_encode_length_larger_than_255() {
        // 300-byte message needs a 2-byte prefix: [0x01, 0x2C]
        let msg = Bytes::from(vec![0u8; 300]);
        let framed = tcp::encode_length_prefix(&msg);
        assert_eq!(framed[0], 0x01); // high byte of 300
        assert_eq!(framed[1], 0x2C); // low byte of 300 (0x012C = 300)
        assert_eq!(framed.len(), 302);
    }

    #[test]
    fn tcp_encode_empty_message() {
        let msg = Bytes::new();
        let framed = tcp::encode_length_prefix(&msg);
        assert_eq!(&framed[..], &[0x00, 0x00]);
    }

    // ── TCP decode ────────────────────────────────────────────────────────────

    #[test]
    fn tcp_decode_reads_length() {
        let prefix = [0x00, 0x05u8];
        assert_eq!(tcp::decode_length_prefix(&prefix).unwrap(), 5u16);
    }

    #[test]
    fn tcp_decode_reads_larger_length() {
        let prefix = [0x01, 0x2Cu8]; // 300
        assert_eq!(tcp::decode_length_prefix(&prefix).unwrap(), 300u16);
    }

    #[test]
    fn tcp_decode_ignores_trailing_bytes() {
        // Extra bytes after the prefix are ignored
        let frame = [0x00, 0x03, 0xFF, 0xFF, 0xFF];
        assert_eq!(tcp::decode_length_prefix(&frame).unwrap(), 3u16);
    }

    #[test]
    fn tcp_decode_truncated_0_bytes_returns_error() {
        let err = tcp::decode_length_prefix(&[]).unwrap_err();
        assert!(
            matches!(err, Error::TruncatedLengthPrefix(0)),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn tcp_decode_truncated_1_byte_returns_error() {
        let err = tcp::decode_length_prefix(&[0x01]).unwrap_err();
        assert!(
            matches!(err, Error::TruncatedLengthPrefix(1)),
            "unexpected error: {err}"
        );
    }

    // ── TCP round-trip ────────────────────────────────────────────────────────

    #[test]
    fn tcp_round_trip() {
        let msg = Bytes::from_static(b"round-trip-test");
        let framed = tcp::encode_length_prefix(&msg);

        // decode the prefix
        let declared_len = tcp::decode_length_prefix(&framed).unwrap();
        assert_eq!(declared_len as usize, msg.len());

        // the message body follows the 2-byte prefix
        let body = &framed[tcp::LENGTH_PREFIX_SIZE..];
        assert_eq!(body, &msg[..]);
    }

    #[test]
    fn tcp_round_trip_via_reader() {
        use crate::codec::reader::Reader;

        let msg = Bytes::from_static(b"dns-test-message");
        let framed = tcp::encode_length_prefix(&msg);

        let mut r = Reader::new(framed);
        let len = r.read_u16().unwrap() as usize;
        let body = r.read_slice(len).unwrap();
        assert_eq!(&body[..], &msg[..]);
    }
}
