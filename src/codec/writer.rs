//! Append-only output buffer for DNS wire-format response synthesis.
//!
//! [`Writer`] wraps a [`bytes::BytesMut`] and exposes big-endian integer
//! appends, raw slice appends, and a "patch" mechanism for backfilling
//! length/offset fields written before the final value is known.  All
//! appends are infallible — the buffer grows as needed (backed by
//! `BytesMut`'s internal allocator).
//!
//! This type is used by the response-synthesis path (block answers, local
//! records) described in SPEC §2.1 and §5.

use bytes::{BufMut, Bytes, BytesMut};

/// Append-only writer over [`BytesMut`] for DNS response synthesis.
///
/// # Patch / backfill
///
/// Some DNS fields (e.g. a record-data length or a 2-byte RDLENGTH) are
/// written as placeholder `0` values and later overwritten with the correct
/// value once the content has been appended.  [`Writer::patch_u16`] supports
/// this pattern by writing a `u16` at a previously recorded offset.
///
/// # Example
///
/// ```rust
/// use sagittarius::codec::writer::Writer;
///
/// let mut w = Writer::new();
/// w.write_u16(0x0001);
/// w.write_u32(0x00000300);
/// let bytes = w.finish();
/// assert_eq!(&bytes[..], &[0x00, 0x01, 0x00, 0x00, 0x03, 0x00]);
/// ```
#[derive(Debug, Default)]
pub struct Writer {
    buf: BytesMut,
}

impl Writer {
    /// Create a new empty [`Writer`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            buf: BytesMut::new(),
        }
    }

    /// Create a new [`Writer`] with a pre-allocated capacity hint (bytes).
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: BytesMut::with_capacity(capacity),
        }
    }

    // ── Length / position ─────────────────────────────────────────────────────

    /// Number of bytes written so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Returns `true` if nothing has been written yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    // ── Append methods ────────────────────────────────────────────────────────

    /// Append a single byte.
    pub fn write_u8(&mut self, val: u8) {
        self.buf.put_u8(val);
    }

    /// Append a big-endian `u16` (2 bytes, network byte order).
    pub fn write_u16(&mut self, val: u16) {
        self.buf.put_u16(val);
    }

    /// Append a big-endian `u32` (4 bytes, network byte order).
    pub fn write_u32(&mut self, val: u32) {
        self.buf.put_u32(val);
    }

    /// Append the bytes in `data` verbatim.
    pub fn write_slice(&mut self, data: &[u8]) {
        self.buf.put_slice(data);
    }

    // ── Patch / backfill ──────────────────────────────────────────────────────

    /// Overwrite the big-endian `u16` at a previously recorded `offset`.
    ///
    /// Call [`Writer::len`] before writing the placeholder to capture the
    /// offset, then write a `0u16` placeholder with [`Writer::write_u16`].
    /// After appending the content whose size you need to backfill, call
    /// `patch_u16` with the saved offset.
    ///
    /// # Panics
    ///
    /// Panics if `offset + 2 > self.len()`.  The invariant is always
    /// satisfiable by callers who saved the offset from [`Writer::len`] at
    /// the right moment — this is an internal programming error, not an
    /// untrusted-input error.
    pub fn patch_u16(&mut self, offset: usize, val: u16) {
        let bytes = val.to_be_bytes();
        self.buf[offset] = bytes[0];
        self.buf[offset + 1] = bytes[1];
    }

    // ── Finish ────────────────────────────────────────────────────────────────

    /// Freeze the writer and return the finished buffer as a read-only
    /// [`Bytes`] (cheap reference-count bump, no copy).
    #[must_use]
    pub fn finish(self) -> Bytes {
        self.buf.freeze()
    }

    /// Freeze the writer and return the finished buffer as [`BytesMut`].
    ///
    /// Prefer [`Writer::finish`] unless the caller needs mutable access to
    /// patch bytes not covered by [`Writer::patch_u16`].
    #[must_use]
    pub fn finish_mut(self) -> BytesMut {
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── write_u8 ──────────────────────────────────────────────────────────────

    #[test]
    fn write_u8_single_byte() {
        let mut w = Writer::new();
        w.write_u8(0xAB);
        assert_eq!(&w.finish()[..], &[0xAB]);
    }

    // ── write_u16 ─────────────────────────────────────────────────────────────

    #[test]
    fn write_u16_big_endian() {
        let mut w = Writer::new();
        w.write_u16(0x0102);
        let b = w.finish();
        // Explicitly check big-endian wire layout
        assert_eq!(&b[..], &[0x01, 0x02]);
    }

    #[test]
    fn write_u16_byte_order_explicit() {
        let mut w = Writer::new();
        w.write_u16(0xFF00);
        let b = w.finish();
        assert_eq!(b[0], 0xFF);
        assert_eq!(b[1], 0x00);
    }

    // ── write_u32 ─────────────────────────────────────────────────────────────

    #[test]
    fn write_u32_big_endian() {
        let mut w = Writer::new();
        w.write_u32(0x01020304);
        let b = w.finish();
        assert_eq!(&b[..], &[0x01, 0x02, 0x03, 0x04]);
    }

    // ── write_slice ───────────────────────────────────────────────────────────

    #[test]
    fn write_slice_appends_verbatim() {
        let mut w = Writer::new();
        w.write_slice(b"hello");
        assert_eq!(&w.finish()[..], b"hello");
    }

    // ── round-trip: write then read back ─────────────────────────────────────

    #[test]
    fn round_trip_u8() {
        use crate::codec::reader::Reader;
        let mut w = Writer::new();
        w.write_u8(0x42);
        let mut r = Reader::new(w.finish());
        assert_eq!(r.read_u8().unwrap(), 0x42);
    }

    #[test]
    fn round_trip_u16() {
        use crate::codec::reader::Reader;
        let mut w = Writer::new();
        w.write_u16(0xDEAD);
        let mut r = Reader::new(w.finish());
        assert_eq!(r.read_u16().unwrap(), 0xDEAD);
    }

    #[test]
    fn round_trip_u32() {
        use crate::codec::reader::Reader;
        let mut w = Writer::new();
        w.write_u32(0xDEADBEEF);
        let mut r = Reader::new(w.finish());
        assert_eq!(r.read_u32().unwrap(), 0xDEADBEEF);
    }

    #[test]
    fn round_trip_slice() {
        use crate::codec::reader::Reader;
        let payload = b"dns-payload";
        let mut w = Writer::new();
        w.write_slice(payload);
        let mut r = Reader::new(w.finish());
        let out = r.read_slice(payload.len()).unwrap();
        assert_eq!(&out[..], payload);
    }

    // ── multi-field wire layout ───────────────────────────────────────────────

    #[test]
    fn multi_field_wire_layout() {
        let mut w = Writer::new();
        w.write_u8(0x01);
        w.write_u16(0x0203);
        w.write_u32(0x04050607);
        let b = w.finish();
        assert_eq!(&b[..], &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
    }

    // ── len / is_empty ────────────────────────────────────────────────────────

    #[test]
    fn len_tracks_writes() {
        let mut w = Writer::new();
        assert!(w.is_empty());
        assert_eq!(w.len(), 0);
        w.write_u8(0);
        assert_eq!(w.len(), 1);
        w.write_u16(0);
        assert_eq!(w.len(), 3);
        w.write_u32(0);
        assert_eq!(w.len(), 7);
        w.write_slice(b"abc");
        assert_eq!(w.len(), 10);
    }

    // ── patch_u16 (backfill) ──────────────────────────────────────────────────

    #[test]
    fn patch_u16_backfills_length() {
        let mut w = Writer::new();
        w.write_u8(0xAA); // some prefix byte

        let len_offset = w.len(); // save offset before placeholder
        w.write_u16(0x0000); // placeholder

        w.write_slice(b"payload"); // 7 bytes

        // backfill the length of "payload"
        let payload_len = (w.len() - len_offset - 2) as u16;
        w.patch_u16(len_offset, payload_len);

        let b = w.finish();
        // byte 0: 0xAA
        assert_eq!(b[0], 0xAA);
        // bytes 1-2: big-endian 7
        assert_eq!(b[1], 0x00);
        assert_eq!(b[2], 0x07);
        // bytes 3-9: "payload"
        assert_eq!(&b[3..], b"payload");
    }

    // ── finish_mut ────────────────────────────────────────────────────────────

    #[test]
    fn finish_mut_returns_bytes_mut() {
        let mut w = Writer::new();
        w.write_u16(0x1234);
        let bm = w.finish_mut();
        assert_eq!(&bm[..], &[0x12, 0x34]);
    }

    // ── with_capacity ─────────────────────────────────────────────────────────

    #[test]
    fn with_capacity_works() {
        let mut w = Writer::with_capacity(512);
        w.write_u8(0xFF);
        assert_eq!(w.len(), 1);
    }
}
