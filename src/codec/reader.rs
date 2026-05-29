//! Bounds-checked cursor over [`bytes::Bytes`] for DNS wire-format parsing.
//!
//! [`Reader`] wraps a [`bytes::Bytes`] buffer and exposes a positional cursor
//! with methods that consume big-endian integer types and raw byte slices.
//! Every read is bounds-checked via `get(..)` — the reader will **never**
//! panic with an index out-of-bounds; instead it returns
//! [`codec::Error::UnexpectedEof`] on any attempt to read past the end of the
//! buffer.
//!
//! Because the underlying buffer is a [`bytes::Bytes`] (reference-counted),
//! slices are zero-copy views into the same allocation — important for the
//! raw-passthrough hot path described in SPEC §2.1.

use bytes::Bytes;

use crate::codec::Error;

/// A bounds-checked, positional cursor over a [`Bytes`] buffer.
///
/// # Zero-copy slicing
///
/// [`Reader::read_slice`] and [`Reader::peek_slice`] both return a `Bytes`
/// clone, which is a cheap reference-counted view into the same allocation —
/// no data is copied.
///
/// # Example
///
/// ```rust
/// use sagittarius::codec::reader::Reader;
///
/// let data = bytes::Bytes::from_static(&[0x00, 0x01, 0x00, 0x02]);
/// let mut r = Reader::new(data);
/// assert_eq!(r.read_u16().unwrap(), 0x0001);
/// assert_eq!(r.read_u16().unwrap(), 0x0002);
/// assert!(r.read_u8().is_err()); // past end → error, not panic
/// ```
#[derive(Debug, Clone)]
pub struct Reader {
    buf: Bytes,
    pos: usize,
}

impl Reader {
    /// Create a new [`Reader`] positioned at offset 0.
    #[must_use]
    pub fn new(buf: Bytes) -> Self {
        Self { buf, pos: 0 }
    }

    /// Create a [`Reader`] from a static byte slice (useful in tests).
    #[cfg(test)]
    pub fn from_static(bytes: &'static [u8]) -> Self {
        Self::new(Bytes::from_static(bytes))
    }

    // ── Position / length ────────────────────────────────────────────────────

    /// Current byte offset within the buffer.
    #[must_use]
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Number of bytes remaining from the current position.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Total length of the underlying buffer (fixed at construction time).
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Returns `true` if there are no bytes remaining.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Borrow a reference to the full underlying [`Bytes`] buffer (independent
    /// of the current cursor position).  Useful for raw-passthrough paths that
    /// need the complete datagram after the shallow parse.
    #[must_use]
    pub fn as_bytes(&self) -> &Bytes {
        &self.buf
    }

    /// Consume the reader and return the underlying [`Bytes`] buffer.
    #[must_use]
    pub fn into_bytes(self) -> Bytes {
        self.buf
    }

    // ── Read helpers ─────────────────────────────────────────────────────────

    /// Build the canonical [`Error::UnexpectedEof`] for the current position.
    fn eof(&self, needed: usize) -> Error {
        Error::UnexpectedEof {
            offset: self.pos,
            needed,
            available: self.remaining(),
        }
    }

    /// Read a single byte and advance the cursor by 1.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedEof`] when the buffer is exhausted.
    pub fn read_u8(&mut self) -> Result<u8, Error> {
        let byte = self.buf.get(self.pos).copied().ok_or_else(|| self.eof(1))?;
        self.pos += 1;
        Ok(byte)
    }

    /// Read a big-endian `u16` and advance the cursor by 2.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedEof`] when fewer than 2 bytes remain.
    pub fn read_u16(&mut self) -> Result<u16, Error> {
        let slice = self
            .buf
            .get(self.pos..self.pos + 2)
            .ok_or_else(|| self.eof(2))?;
        let val = u16::from_be_bytes([slice[0], slice[1]]);
        self.pos += 2;
        Ok(val)
    }

    /// Read a big-endian `u32` and advance the cursor by 4.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedEof`] when fewer than 4 bytes remain.
    pub fn read_u32(&mut self) -> Result<u32, Error> {
        let slice = self
            .buf
            .get(self.pos..self.pos + 4)
            .ok_or_else(|| self.eof(4))?;
        let val = u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]);
        self.pos += 4;
        Ok(val)
    }

    /// Read exactly `n` bytes and advance the cursor by `n`.
    ///
    /// The returned [`Bytes`] is a zero-copy slice of the underlying buffer —
    /// no data is copied.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedEof`] when fewer than `n` bytes remain.
    pub fn read_slice(&mut self, n: usize) -> Result<Bytes, Error> {
        // `checked_add` guards against `pos + n` overflowing `usize` for a
        // hostile/huge `n` (which would otherwise wrap and bypass the bounds
        // check, then panic in `slice`).
        let end = self.pos.checked_add(n).ok_or_else(|| self.eof(n))?;
        if end > self.buf.len() {
            return Err(self.eof(n));
        }
        let slice = self.buf.slice(self.pos..end);
        self.pos = end;
        Ok(slice)
    }

    /// Peek at the next `n` bytes **without** advancing the cursor.
    ///
    /// The returned [`Bytes`] is a zero-copy view — no data is copied.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedEof`] when fewer than `n` bytes remain.
    pub fn peek_slice(&self, n: usize) -> Result<Bytes, Error> {
        // See `read_slice`: `checked_add` prevents a huge `n` from overflowing
        // and bypassing the bounds check.
        let end = self.pos.checked_add(n).ok_or_else(|| self.eof(n))?;
        if end > self.buf.len() {
            return Err(self.eof(n));
        }
        Ok(self.buf.slice(self.pos..end))
    }

    /// Peek at the next single byte without advancing the cursor.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedEof`] when the buffer is exhausted.
    pub fn peek_u8(&self) -> Result<u8, Error> {
        self.buf.get(self.pos).copied().ok_or_else(|| self.eof(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn reader(data: &'static [u8]) -> Reader {
        Reader::from_static(data)
    }

    // ── read_u8 ───────────────────────────────────────────────────────────────

    #[test]
    fn read_u8_basic() {
        let mut r = reader(&[0xAB, 0xCD]);
        assert_eq!(r.read_u8().unwrap(), 0xAB);
        assert_eq!(r.read_u8().unwrap(), 0xCD);
    }

    #[test]
    fn read_u8_truncated_returns_error_not_panic() {
        let mut r = reader(&[]);
        let err = r.read_u8().unwrap_err();
        assert!(
            matches!(
                err,
                Error::UnexpectedEof {
                    needed: 1,
                    available: 0,
                    ..
                }
            ),
            "unexpected error: {err}"
        );
    }

    // ── read_u16 ──────────────────────────────────────────────────────────────

    #[test]
    fn read_u16_big_endian() {
        let mut r = reader(&[0x01, 0x02]);
        assert_eq!(r.read_u16().unwrap(), 0x0102u16);
    }

    #[test]
    fn read_u16_byte_order_explicit() {
        // Write 0x0102 → expect wire bytes [0x01, 0x02]
        let mut r = reader(&[0x01, 0x02, 0xFF]);
        let val = r.read_u16().unwrap();
        assert_eq!(val, 0x0102);
        // cursor advanced by exactly 2
        assert_eq!(r.position(), 2);
    }

    #[test]
    fn read_u16_truncated_1_byte() {
        let mut r = reader(&[0x01]);
        let err = r.read_u16().unwrap_err();
        assert!(
            matches!(
                err,
                Error::UnexpectedEof {
                    needed: 2,
                    available: 1,
                    ..
                }
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn read_u16_truncated_empty() {
        let mut r = reader(&[]);
        let err = r.read_u16().unwrap_err();
        assert!(
            matches!(
                err,
                Error::UnexpectedEof {
                    needed: 2,
                    available: 0,
                    ..
                }
            ),
            "unexpected error: {err}"
        );
    }

    // ── read_u32 ──────────────────────────────────────────────────────────────

    #[test]
    fn read_u32_big_endian() {
        let mut r = reader(&[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(r.read_u32().unwrap(), 0x01020304u32);
    }

    #[test]
    fn read_u32_byte_order_explicit() {
        // Write 0x01020304 → expect wire bytes [0x01, 0x02, 0x03, 0x04]
        let mut r = reader(&[0x01, 0x02, 0x03, 0x04]);
        let val = r.read_u32().unwrap();
        assert_eq!(val, 0x01020304);
    }

    #[test]
    fn read_u32_truncated_3_bytes() {
        let mut r = reader(&[0x01, 0x02, 0x03]);
        let err = r.read_u32().unwrap_err();
        assert!(
            matches!(
                err,
                Error::UnexpectedEof {
                    needed: 4,
                    available: 3,
                    ..
                }
            ),
            "unexpected error: {err}"
        );
    }

    // ── read_slice ────────────────────────────────────────────────────────────

    #[test]
    fn read_slice_zero_copy() {
        let data = Bytes::from_static(b"hello");
        let mut r = Reader::new(data.clone());
        let slice = r.read_slice(5).unwrap();
        assert_eq!(slice, data);
    }

    #[test]
    fn read_slice_partial() {
        let mut r = reader(b"hello world");
        let first = r.read_slice(5).unwrap();
        assert_eq!(&first[..], b"hello");
        assert_eq!(r.position(), 5);
        let _ = r.read_u8().unwrap(); // space
        let rest = r.read_slice(5).unwrap();
        assert_eq!(&rest[..], b"world");
    }

    #[test]
    fn read_slice_truncated() {
        let mut r = reader(b"hi");
        let err = r.read_slice(10).unwrap_err();
        assert!(
            matches!(
                err,
                Error::UnexpectedEof {
                    needed: 10,
                    available: 2,
                    ..
                }
            ),
            "unexpected error: {err}"
        );
        // cursor must not advance on error
        assert_eq!(r.position(), 0);
    }

    #[test]
    fn read_slice_huge_n_does_not_overflow() {
        // A hostile, huge `n` must error cleanly rather than overflow `pos + n`
        // and panic in the slice. Cursor must not advance.
        let mut r = reader(b"hi");
        let err = r.read_slice(usize::MAX).unwrap_err();
        assert!(
            matches!(err, Error::UnexpectedEof { needed, .. } if needed == usize::MAX),
            "unexpected error: {err}"
        );
        assert_eq!(r.position(), 0);
    }

    #[test]
    fn peek_slice_huge_n_does_not_overflow() {
        let r = reader(b"hi");
        assert!(r.peek_slice(usize::MAX).is_err());
        assert_eq!(r.position(), 0);
    }

    // ── peek ──────────────────────────────────────────────────────────────────

    #[test]
    fn peek_does_not_advance() {
        let mut r = reader(&[0xAA, 0xBB]);
        assert_eq!(r.peek_u8().unwrap(), 0xAA);
        assert_eq!(r.position(), 0); // unchanged
        assert_eq!(r.read_u8().unwrap(), 0xAA); // first byte still there
    }

    #[test]
    fn peek_slice_does_not_advance() {
        let r = reader(b"abc");
        let p = r.peek_slice(2).unwrap();
        assert_eq!(&p[..], b"ab");
        assert_eq!(r.position(), 0);
    }

    #[test]
    fn peek_empty_returns_error() {
        let r = reader(&[]);
        assert!(r.peek_u8().is_err());
        assert!(r.peek_slice(1).is_err());
    }

    // ── position / remaining ──────────────────────────────────────────────────

    #[test]
    fn position_and_remaining_tracking() {
        let mut r = reader(&[1, 2, 3, 4, 5]);
        assert_eq!(r.position(), 0);
        assert_eq!(r.remaining(), 5);
        assert_eq!(r.len(), 5);

        let _ = r.read_u8().unwrap();
        assert_eq!(r.position(), 1);
        assert_eq!(r.remaining(), 4);

        let _ = r.read_u16().unwrap();
        assert_eq!(r.position(), 3);
        assert_eq!(r.remaining(), 2);

        let _ = r.read_u16().unwrap();
        assert_eq!(r.position(), 5);
        assert_eq!(r.remaining(), 0);
        assert!(r.is_empty());
    }

    // ── as_bytes / into_bytes ─────────────────────────────────────────────────

    #[test]
    fn as_bytes_returns_full_buffer() {
        let data = Bytes::from_static(b"full");
        let mut r = Reader::new(data.clone());
        let _ = r.read_u8().unwrap(); // advance cursor
        // as_bytes still returns the full underlying buffer
        assert_eq!(r.as_bytes(), &data);
    }

    #[test]
    fn into_bytes_returns_full_buffer() {
        let data = Bytes::from_static(b"full");
        let mut r = Reader::new(data.clone());
        let _ = r.read_u8().unwrap();
        let recovered = r.into_bytes();
        assert_eq!(recovered, data);
    }
}
