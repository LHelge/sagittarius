//! DNS domain name type, QNAME codec, and RR name-skip helper.
//!
//! # Design
//!
//! ## [`Name`]
//!
//! A normalized, validated domain name.  Normalization is:
//! - ASCII letters are lowercased (DNS names are case-insensitive, RFC 4343).
//! - A trailing dot (root label) is always present in the canonical form.
//! - Labels use Sagittarius' supported domain syntax: ASCII letters, digits,
//!   and interior hyphens.
//!
//! So `"Example.COM"` and `"example.com."` both normalize to `"example.com."`.
//! The [`Display`] representation is the fully-qualified form with trailing dot.
//! [`PartialEq`], [`Eq`], and [`Hash`] all operate on the normalized string, so
//! `"A.B"` and `"a.b."` compare equal and hash identically.
//!
//! ## QNAME reader (`Name::read_question`)
//!
//! Reads a wire-format name from the **question** section.  The question name
//! is always the first name in the message and therefore **can never be
//! compressed** in a well-formed packet (SPEC §2.1).  The reader enforces this
//! by rejecting any label byte with the top two bits set (`0xC0` pattern) —
//! returning [`Error::CompressionPointerInQuestion`] — rather than implementing
//! general decompression logic.
//!
//! ## QNAME writer (`Name::write`)
//!
//! Serializes a [`Name`] into a [`Writer`] as the standard length-prefixed
//! label sequence terminated by a zero byte.  Round-trips cleanly with
//! `read_question`.
//!
//! ## RR name-skip (`Name::skip_rr`)
//!
//! Advances a [`Reader`]'s cursor past a name in an **RR section**
//! (answer/authority/additional).  This is the **only** place in the codec that
//! handles compression pointers, and it does so defensively:
//!
//! - Pointers are followed only for *skipping*, never materialized.
//! - At most [`MAX_SKIP_HOPS`] pointer hops are followed, and the total label
//!   bytes visited are bounded by the RFC 1035 255-byte name limit
//!   ([`MAX_NAME_WIRE_LEN`]).  A crafted pointer loop therefore always
//!   terminates with an error rather than hanging.
//! - Forward pointers and out-of-range targets are rejected with
//!   [`Error::InvalidPointerTarget`].
//! - After a successful skip the caller's [`Reader`] cursor sits immediately
//!   after the name in the RR stream (after the 2-byte pointer if the name
//!   ended in a pointer, after the zero terminator otherwise) — ready for the
//!   next field in the sequential RR walk.

use std::{
    fmt,
    hash::{Hash, Hasher},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use crate::codec::{Error, reader::Reader, writer::Writer};

// ── Limits ────────────────────────────────────────────────────────────────────

/// Maximum length of a single DNS label in bytes (RFC 1035 §2.3.4).
const MAX_LABEL_LEN: usize = 63;

/// Maximum total wire-format length of a DNS name in bytes (RFC 1035 §2.3.4).
/// This includes all length bytes and the terminating zero but excludes any
/// 2-byte compression pointer.
const MAX_NAME_WIRE_LEN: usize = 255;

/// Maximum number of compression-pointer hops allowed during [`Name::skip_rr`].
/// This caps the work done when following pointer chains, bounding loop
/// detection to a constant regardless of message size.
///
/// Together with the [`MAX_NAME_WIRE_LEN`] cap on visited label bytes this
/// bounds a single skip to constant work.
const MAX_SKIP_HOPS: usize = 16;

// ── Name ─────────────────────────────────────────────────────────────────────

/// A validated, normalized DNS domain name.
///
/// The name is stored in its canonical (fully-qualified, lowercase) string
/// form, e.g. `"example.com."`.  The root zone is represented as `"."`.
///
/// # Normalization
///
/// - All ASCII letters are lowercased.
/// - A trailing dot is always present.
///
/// Therefore `"Example.COM"`, `"example.com"`, and `"example.com."` are all
/// equivalent and compare/hash identically.
///
/// # Limits (RFC 1035 §2.3.4)
///
/// - Each label must be at most 63 bytes.
/// - The total wire-format encoded length must be at most 255 bytes (including
///   length bytes and the root terminator).
#[derive(Clone, Debug)]
pub struct Name {
    /// Normalized (lowercase, trailing dot) fully-qualified name string.
    /// Invariant: always ends with `'.'`; always valid per RFC 1035 limits.
    inner: Box<str>,
}

impl Name {
    /// Return the normalized string representation (always ends with `'.'`).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.inner
    }

    // ── Internal constructor ──────────────────────────────────────────────────

    /// Construct from a pre-validated, already-normalized string.
    ///
    /// # Invariants
    ///
    /// The caller must ensure:
    /// - `s` is lowercase and ends with `'.'`.
    /// - All label and total-length invariants hold.
    fn from_normalized(s: String) -> Self {
        Self {
            inner: s.into_boxed_str(),
        }
    }

    // ── Wire-format I/O ───────────────────────────────────────────────────────

    /// Read a wire-format name from the **question section** of a DNS message.
    ///
    /// Reads length-prefixed labels terminated by a zero label from `reader`.
    /// Enforces RFC 1035 label (≤ 63 bytes) and total-name (≤ 255 wire bytes)
    /// limits, and **rejects any compression pointer** (`0xC0` high-bits pattern)
    /// with [`Error::CompressionPointerInQuestion`] — the question name is never
    /// compressed (SPEC §2.1).
    ///
    /// Returns a fully normalized [`Name`] (lowercase, trailing dot).
    ///
    /// # Errors
    ///
    /// - [`Error::CompressionPointerInQuestion`] — a label length byte has its
    ///   top two bits set, indicating a compression pointer.
    /// - [`Error::LabelTooLong`] — a label length byte exceeds 63.
    /// - [`Error::NameTooLong`] — the cumulative wire length exceeds 255 bytes.
    /// - [`Error::UnexpectedEof`] — the buffer is truncated mid-name.
    pub fn read_question(reader: &mut Reader) -> Result<Self, Error> {
        let mut normalized = String::with_capacity(64);
        // wire_len tracks the cumulative wire-format size:
        // each label contributes 1 (length byte) + label bytes, plus the
        // final 0x00 root terminator.  Start at 1 to account for the root.
        let mut wire_len: usize = 1;

        loop {
            let len_byte = reader.read_u8()?;

            // Compression pointer detection: top two bits 0b11 → reject.
            // RFC 1035 §4.1.4: a label length byte with top two bits both set
            // is a compression pointer.  The question name must never be
            // compressed (SPEC §2.1).
            if len_byte & 0xC0 == 0xC0 {
                return Err(Error::CompressionPointerInQuestion);
            }

            let label_len = len_byte as usize;

            if label_len == 0 {
                // Root label — end of name.
                break;
            }

            // Enforce label length limit.
            if label_len > MAX_LABEL_LEN {
                return Err(Error::LabelTooLong(label_len));
            }

            // Each label costs 1 length byte + its content bytes on the wire
            // (wire_len started at 1 to account for the root terminator).
            wire_len = wire_len
                .checked_add(1 + label_len)
                .ok_or(Error::NameTooLong(usize::MAX))?;
            if wire_len > MAX_NAME_WIRE_LEN {
                return Err(Error::NameTooLong(wire_len));
            }

            // Read the label bytes, validate supported domain syntax, and append
            // to the normalized string.
            let label_bytes = reader.read_slice(label_len)?;
            Self::validate_label(label_bytes.as_ref())?;
            for &b in label_bytes.iter() {
                normalized.push(b.to_ascii_lowercase() as char);
            }
            normalized.push('.');
        }

        // Root-only: just the trailing dot.
        if normalized.is_empty() {
            normalized.push('.');
        }

        Ok(Self::from_normalized(normalized))
    }

    /// Encode this name into `writer` in wire format.
    ///
    /// Writes length-prefixed labels terminated by a zero root label, suitable
    /// for the question section of a DNS message.  Round-trips cleanly with
    /// [`Name::read_question`].
    pub fn write(&self, writer: &mut Writer) {
        // self.inner always ends with '.'; split on '.' to get labels.
        // The trailing '.' produces a final empty string after split — skip it.
        for label in self.inner.split('.') {
            if label.is_empty() {
                // Trailing dot produces an empty final segment; root label.
                continue;
            }
            // label_len is always ≤ 63 (enforced on construction).
            writer.write_u8(label.len() as u8);
            writer.write_slice(label.as_bytes());
        }
        // Root terminator.
        writer.write_u8(0);
    }

    // ── Reverse-DNS (PTR) parsing ─────────────────────────────────────────────

    /// Interpret this name as a reverse-DNS (PTR) query name and recover the
    /// [`IpAddr`] it encodes, or `None` if it is not a well-formed reverse name.
    ///
    /// Two reverse zones are recognized (RFC 1035 §3.5, RFC 3596 §2.5):
    ///
    /// - **IPv4** — `<d>.<c>.<b>.<a>.in-addr.arpa` → `Ipv4Addr::new(a, b, c, d)`.
    ///   The four octets precede the zone in least-significant-first order, so
    ///   they are reversed here.
    /// - **IPv6** — 32 single-hex-digit nibble labels followed by `ip6.arpa` →
    ///   an [`Ipv6Addr`].  Nibbles are likewise least-significant-first.
    ///
    /// Returns `None` for anything that is not exactly one of these forms: the
    /// wrong label count, an octet > 255, a non-hexadecimal nibble, a multi-byte
    /// nibble label, or an ordinary forward name.  This is the recognition step
    /// that gates local PTR synthesis (E13.2) and reverse-zone forwarding.
    #[must_use]
    pub fn reverse_addr(&self) -> Option<IpAddr> {
        // `inner` is normalized: lowercase with a trailing root dot. Strip the
        // root so the zone suffixes match without a dangling dot.
        let body = self.inner.strip_suffix('.')?;

        if let Some(octets) = body.strip_suffix(".in-addr.arpa") {
            return Self::parse_in_addr_arpa(octets).map(IpAddr::V4);
        }
        if let Some(nibbles) = body.strip_suffix(".ip6.arpa") {
            return Self::parse_ip6_arpa(nibbles).map(IpAddr::V6);
        }
        None
    }

    /// Parse the octet labels of an `in-addr.arpa` name (the part *before*
    /// `.in-addr.arpa`) into an [`Ipv4Addr`].  Expects exactly four decimal
    /// octets in least-significant-first order.
    fn parse_in_addr_arpa(octets: &str) -> Option<Ipv4Addr> {
        let mut addr = [0u8; 4];
        let mut count = 0usize;
        for label in octets.split('.') {
            if count >= 4 {
                return None; // too many labels
            }
            // `u8::from_str` rejects empties, non-digits, and values > 255.
            addr[3 - count] = label.parse().ok()?;
            count += 1;
        }
        (count == 4).then(|| Ipv4Addr::from(addr))
    }

    /// Parse the nibble labels of an `ip6.arpa` name (the part *before*
    /// `.ip6.arpa`) into an [`Ipv6Addr`].  Expects exactly 32 single-hex-digit
    /// labels in least-significant-first order.
    fn parse_ip6_arpa(nibbles: &str) -> Option<Ipv6Addr> {
        let mut digits = [0u8; 32];
        let mut count = 0usize;
        for label in nibbles.split('.') {
            if count >= 32 {
                return None; // too many labels
            }
            // Each label must be exactly one hexadecimal digit.
            let [byte] = label.as_bytes() else {
                return None;
            };
            digits[31 - count] = (*byte as char).to_digit(16)? as u8;
            count += 1;
        }
        if count != 32 {
            return None;
        }
        // Pack the 32 nibbles (high-to-low) into 16 octets.
        let mut addr = [0u8; 16];
        for (i, octet) in addr.iter_mut().enumerate() {
            *octet = (digits[2 * i] << 4) | digits[2 * i + 1];
        }
        Some(Ipv6Addr::from(addr))
    }

    // ── RR name-skip ─────────────────────────────────────────────────────────

    /// Skip past a name in an **RR section** (answer/authority/additional),
    /// following compression pointers defensively.
    ///
    /// After a successful call the caller's `reader` cursor is positioned
    /// immediately **after** the name in the original stream — either after the
    /// 2-byte compression pointer (if the name ended in a pointer) or after the
    /// zero root label (if no trailing pointer).  This is the position needed
    /// for a sequential RR walk.
    ///
    /// # Pointer safety
    ///
    /// - Pointer targets must point *strictly before* the current read offset
    ///   in the message, and within the message bounds.  Forward and
    ///   out-of-range pointers are rejected with [`Error::InvalidPointerTarget`].
    /// - At most [`MAX_SKIP_HOPS`] pointer hops are followed.
    /// - The total label-content bytes visited are capped at the RFC 1035
    ///   255-byte name limit ([`MAX_NAME_WIRE_LEN`]).
    ///
    /// # Errors
    ///
    /// - [`Error::NameSkipLimitExceeded`] — pointer-hop cap exceeded.
    /// - [`Error::InvalidPointerTarget`] — pointer target is forward or OOB.
    /// - [`Error::LabelTooLong`] — a label length byte exceeds 63.
    /// - [`Error::NameTooLong`] — total label bytes processed exceed 255.
    /// - [`Error::UnexpectedEof`] — the buffer is truncated.
    pub fn skip_rr(reader: &mut Reader) -> Result<(), Error> {
        // We maintain two cursors:
        //  - `reader` — the original stream cursor; advanced to just after the
        //    name (after pointer or after zero label).  This is what the caller
        //    sees.
        //  - `follow_pos` — used when following pointer chains.  Once we take
        //    the first pointer, the original stream cursor has already been set
        //    (to after the 2-byte pointer), and we track the followed position
        //    separately so the original cursor is not disturbed.
        //
        // The `following` flag records whether we have already fixed the
        // original cursor's post-skip position (i.e. taken the first pointer).

        let msg = reader.as_bytes().clone();
        let msg_len = msg.len();

        // Current read position within the name (may diverge from reader.pos
        // once we follow a pointer).
        let mut cur_pos = reader.position();

        // Set to true once we consume the first pointer from the original stream
        // (reader cursor already advanced past the 2-byte pointer at that point).
        let mut fixed_reader = false;

        let mut hops: usize = 0;
        let mut total_label_bytes: usize = 0;

        loop {
            // Read length byte at cur_pos.
            let len_byte = msg.get(cur_pos).copied().ok_or(Error::UnexpectedEof {
                offset: cur_pos,
                needed: 1,
                available: msg_len.saturating_sub(cur_pos),
            })?;
            cur_pos += 1;

            if len_byte & 0xC0 == 0xC0 {
                // Compression pointer: high two bits are 0b11.
                // Need one more byte for the full 14-bit offset.
                let low_byte = msg.get(cur_pos).copied().ok_or(Error::UnexpectedEof {
                    offset: cur_pos,
                    needed: 1,
                    available: msg_len.saturating_sub(cur_pos),
                })?;
                cur_pos += 1;

                // If this is the first pointer we encounter, fix the original
                // stream cursor to just after these 2 bytes.
                if !fixed_reader {
                    reader.read_slice(cur_pos - reader.position())?;
                    fixed_reader = true;
                }

                let target = u16::from_be_bytes([len_byte & 0x3F, low_byte]) as usize;

                // A pointer target must lie within the message and strictly
                // before the pointer word itself.  Backwards-only pointers
                // make self-references and forward jumps impossible, so any
                // chain strictly decreases and cannot loop.
                if target >= msg_len {
                    return Err(Error::InvalidPointerTarget {
                        target: target as u16,
                        msg_len,
                    });
                }
                let pointer_start = cur_pos - 2;
                if target >= pointer_start {
                    return Err(Error::InvalidPointerTarget {
                        target: target as u16,
                        msg_len,
                    });
                }

                hops += 1;
                if hops > MAX_SKIP_HOPS {
                    return Err(Error::NameSkipLimitExceeded);
                }

                // Jump: continue from the pointer target.
                cur_pos = target;
                continue;
            }

            // Reserved high-bits patterns (0b10, 0b01) — reject.
            if len_byte & 0xC0 != 0 {
                return Err(Error::LabelTooLong(len_byte as usize));
            }

            let label_len = len_byte as usize;

            if label_len == 0 {
                // Root label: end of name.
                if !fixed_reader {
                    // No pointer was encountered; advance the original cursor
                    // to include this zero byte (cur_pos already past it).
                    reader.read_slice(cur_pos - reader.position())?;
                }
                return Ok(());
            }

            // Enforce limits.
            if label_len > MAX_LABEL_LEN {
                return Err(Error::LabelTooLong(label_len));
            }

            // Bound the total label bytes visited (across pointer-followed
            // segments) by the RFC 1035 255-byte name limit: no valid name can
            // exceed it, and it caps the work a crafted chain can demand.
            total_label_bytes = total_label_bytes.saturating_add(label_len);
            if total_label_bytes > MAX_NAME_WIRE_LEN {
                return Err(Error::NameTooLong(total_label_bytes));
            }

            // Skip the label bytes.
            cur_pos = cur_pos
                .checked_add(label_len)
                .ok_or(Error::NameSkipLimitExceeded)?;
            if cur_pos > msg_len {
                return Err(Error::UnexpectedEof {
                    offset: cur_pos - label_len,
                    needed: label_len,
                    available: msg_len.saturating_sub(cur_pos - label_len),
                });
            }

            // If we are still in the original (non-pointer-followed) stream,
            // advance the reader cursor to keep it in sync until we hit a
            // pointer or the root label.
            if !fixed_reader {
                reader.read_slice(1 + label_len)?;
            }
        }
    }
}

// ── Standard trait implementations ───────────────────────────────────────────

impl PartialEq for Name {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl Eq for Name {}

impl Hash for Name {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.inner.hash(state);
    }
}

impl fmt::Display for Name {
    /// Format the name in its normalized, fully-qualified form (trailing dot).
    ///
    /// # Example
    ///
    /// ```
    /// use sagittarius::codec::name::Name;
    /// let n: Name = "Example.COM".parse().unwrap();
    /// assert_eq!(n.to_string(), "example.com.");
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.inner)
    }
}

impl FromStr for Name {
    type Err = Error;

    /// Parse and normalize a domain name string.
    ///
    /// Accepts names with or without a trailing dot.  The root zone may be
    /// given as `"."` or `""` (empty string).
    ///
    /// # Normalization
    ///
    /// ASCII letters are lowercased; a trailing dot is appended if absent.
    ///
    /// # Errors
    ///
    /// - [`Error::LabelTooLong`] — a label exceeds 63 bytes.
    /// - [`Error::NameTooLong`] — the total wire length exceeds 255 bytes.
    /// - [`Error::EmptyLabel`] — an empty label appears in a non-root position
    ///   (e.g. `"foo..bar"`).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Normalize trailing dot: strip it for parsing, re-add it at the end.
        // Special case: "." is the root.
        if s == "." || s.is_empty() {
            return Ok(Self::from_normalized(".".to_string()));
        }

        // Strip optional trailing dot for label iteration.
        let s_stripped = s.strip_suffix('.').unwrap_or(s);

        let mut normalized = String::with_capacity(s.len() + 1);
        // wire_len: 1 for root terminator, plus for each label: 1 + len.
        let mut wire_len: usize = 1;

        for label in s_stripped.split('.') {
            // Empty label in a non-terminal position.
            if label.is_empty() {
                return Err(Error::EmptyLabel);
            }

            let label_len = label.len();
            if label_len > MAX_LABEL_LEN {
                return Err(Error::LabelTooLong(label_len));
            }
            Self::validate_label(label.as_bytes())?;

            wire_len = wire_len
                .checked_add(1 + label_len)
                .ok_or(Error::NameTooLong(usize::MAX))?;
            if wire_len > MAX_NAME_WIRE_LEN {
                return Err(Error::NameTooLong(wire_len));
            }

            for c in label.chars() {
                normalized.push(c.to_ascii_lowercase());
            }
            normalized.push('.');
        }

        Ok(Self::from_normalized(normalized))
    }
}

impl Name {
    fn validate_label(label: &[u8]) -> Result<(), Error> {
        if label.first() == Some(&b'-') || label.last() == Some(&b'-') {
            return Err(Error::InvalidLabelByte(b'-'));
        }

        for &b in label {
            if !(b.is_ascii_alphanumeric() || b == b'-') {
                return Err(Error::InvalidLabelByte(b));
            }
        }

        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use bytes::Bytes;

    use super::*;
    use crate::codec::{reader::Reader, writer::Writer};

    // ── Helper: encode a name to wire bytes ───────────────────────────────────

    fn wire_encode(name: &Name) -> Bytes {
        let mut w = Writer::new();
        name.write(&mut w);
        w.finish()
    }

    fn reader_from(bytes: &'static [u8]) -> Reader {
        Reader::new(Bytes::from_static(bytes))
    }

    // ── FromStr / Display ─────────────────────────────────────────────────────

    #[test]
    fn parse_simple() {
        let n: Name = "example.com".parse().unwrap();
        assert_eq!(n.to_string(), "example.com.");
    }

    #[test]
    fn parse_with_trailing_dot() {
        let n: Name = "example.com.".parse().unwrap();
        assert_eq!(n.to_string(), "example.com.");
    }

    #[test]
    fn parse_root_dot() {
        let n: Name = ".".parse().unwrap();
        assert_eq!(n.to_string(), ".");
    }

    #[test]
    fn parse_root_empty_str() {
        let n: Name = "".parse().unwrap();
        assert_eq!(n.to_string(), ".");
    }

    #[test]
    fn parse_single_label() {
        let n: Name = "localhost".parse().unwrap();
        assert_eq!(n.to_string(), "localhost.");
    }

    #[test]
    fn normalization_mixed_case() {
        let n: Name = "Example.COM".parse().unwrap();
        assert_eq!(n.to_string(), "example.com.");
    }

    #[test]
    fn normalization_uppercase_all() {
        let n: Name = "UPPER.CASE.LABELS".parse().unwrap();
        assert_eq!(n.to_string(), "upper.case.labels.");
    }

    // ── Equality / Hash on normalized form ────────────────────────────────────

    #[test]
    fn eq_case_insensitive() {
        let a: Name = "Example.COM".parse().unwrap();
        let b: Name = "example.com".parse().unwrap();
        let c: Name = "example.com.".parse().unwrap();
        assert_eq!(a, b);
        assert_eq!(b, c);
        assert_eq!(a, c);
    }

    #[test]
    fn hash_consistent_with_eq() {
        let a: Name = "Example.COM".parse().unwrap();
        let b: Name = "example.com.".parse().unwrap();
        let mut set = HashSet::new();
        set.insert(a.clone());
        // b is equal to a; inserting should not grow the set.
        assert!(!set.insert(b));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn hashset_lookup_case_insensitive() {
        let mut set: HashSet<Name> = HashSet::new();
        set.insert("blocked.example.com.".parse().unwrap());
        // Lookup with different casing should find the entry.
        let query: Name = "BLOCKED.EXAMPLE.COM".parse().unwrap();
        assert!(set.contains(&query));
    }

    // ── Label / name length limits ────────────────────────────────────────────

    #[test]
    fn label_too_long_from_str() {
        let long_label = "a".repeat(64);
        let err = Name::from_str(&long_label).unwrap_err();
        assert!(
            matches!(err, Error::LabelTooLong(64)),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn label_exactly_63_ok() {
        let label = "a".repeat(63);
        let n = Name::from_str(&label).unwrap();
        assert!(n.to_string().starts_with(&label));
    }

    #[test]
    fn name_too_long_from_str() {
        // Build a name that exceeds 255 wire bytes.
        // Each label of 63 chars costs 1+63 = 64 wire bytes.
        // 4 such labels = 256 wire bytes + 1 root = 257 > 255.
        let label = "a".repeat(63);
        let long_name = format!("{label}.{label}.{label}.{label}");
        let err = Name::from_str(&long_name).unwrap_err();
        assert!(
            matches!(err, Error::NameTooLong(_)),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn name_max_length_ok() {
        // 3 labels of 63 bytes = 3*(1+63) = 192, plus root = 193 — fits.
        let label = "a".repeat(63);
        let name = format!("{label}.{label}.{label}");
        assert!(Name::from_str(&name).is_ok());
    }

    #[test]
    fn empty_label_in_middle_is_error() {
        let err = Name::from_str("foo..bar").unwrap_err();
        assert!(matches!(err, Error::EmptyLabel), "unexpected error: {err}");
    }

    #[test]
    fn non_ascii_from_str_is_error() {
        let err = Name::from_str("münchen.example").unwrap_err();
        assert!(
            matches!(err, Error::InvalidLabelByte(_)),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn underscore_from_str_is_error() {
        let err = Name::from_str("_service.example").unwrap_err();
        assert!(
            matches!(err, Error::InvalidLabelByte(b'_')),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn edge_hyphen_from_str_is_error() {
        let leading = Name::from_str("-bad.example").unwrap_err();
        let trailing = Name::from_str("bad-.example").unwrap_err();

        assert!(matches!(leading, Error::InvalidLabelByte(b'-')));
        assert!(matches!(trailing, Error::InvalidLabelByte(b'-')));
    }

    // ── Wire round-trip ───────────────────────────────────────────────────────

    #[test]
    fn wire_round_trip_simple() {
        let original: Name = "example.com".parse().unwrap();
        let wire = wire_encode(&original);
        let mut r = Reader::new(wire);
        let decoded = Name::read_question(&mut r).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn wire_round_trip_root() {
        let original: Name = ".".parse().unwrap();
        let wire = wire_encode(&original);
        // Root encodes as a single zero byte.
        assert_eq!(&wire[..], &[0x00]);
        let mut r = Reader::new(wire);
        let decoded = Name::read_question(&mut r).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn wire_round_trip_single_label() {
        let original: Name = "localhost".parse().unwrap();
        let wire = wire_encode(&original);
        // \x09 localhost \x00
        assert_eq!(wire[0], 9);
        assert_eq!(&wire[1..10], b"localhost");
        assert_eq!(wire[10], 0);
        let mut r = Reader::new(wire);
        let decoded = Name::read_question(&mut r).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn wire_round_trip_multi_label() {
        let original: Name = "a.b.c.d".parse().unwrap();
        let wire = wire_encode(&original);
        let mut r = Reader::new(wire);
        let decoded = Name::read_question(&mut r).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn wire_round_trip_mixed_case_normalizes() {
        let original: Name = "UPPER.CASE".parse().unwrap();
        let wire = wire_encode(&original);
        let mut r = Reader::new(wire);
        let decoded = Name::read_question(&mut r).unwrap();
        assert_eq!(decoded.to_string(), "upper.case.");
    }

    #[test]
    fn wire_non_ascii_label_byte_is_error() {
        let mut r = reader_from(&[0x01, 0xFF, 0x00]);
        let err = Name::read_question(&mut r).unwrap_err();
        assert!(
            matches!(err, Error::InvalidLabelByte(0xFF)),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn wire_underscore_label_byte_is_error() {
        let mut r = reader_from(&[0x04, b'_', b's', b'v', b'c', 0x00]);
        let err = Name::read_question(&mut r).unwrap_err();
        assert!(
            matches!(err, Error::InvalidLabelByte(b'_')),
            "unexpected error: {err}"
        );
    }

    // ── Compression pointer in question → error ───────────────────────────────

    #[test]
    fn compression_pointer_in_question_rejected() {
        // Wire bytes: 0xC0 0x0C = compression pointer to offset 12.
        let mut r = reader_from(&[0xC0, 0x0C]);
        let err = Name::read_question(&mut r).unwrap_err();
        assert!(
            matches!(err, Error::CompressionPointerInQuestion),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn compression_pointer_mid_question_rejected() {
        // \x03 "foo" then pointer → pointer rejected.
        let mut r = reader_from(&[0x03, b'f', b'o', b'o', 0xC0, 0x0C]);
        let err = Name::read_question(&mut r).unwrap_err();
        assert!(
            matches!(err, Error::CompressionPointerInQuestion),
            "unexpected error: {err}"
        );
    }

    // ── Wire reader: label/name too long ──────────────────────────────────────

    #[test]
    fn wire_label_too_long_rejected() {
        // Label length byte = 64 (> 63).
        let mut data = vec![64u8];
        data.extend_from_slice(&[b'a'; 64]);
        data.push(0);
        let mut r = Reader::new(Bytes::from(data));
        let err = Name::read_question(&mut r).unwrap_err();
        assert!(
            matches!(err, Error::LabelTooLong(64)),
            "unexpected error: {err}"
        );
    }

    // ── skip_rr: normal names ─────────────────────────────────────────────────

    #[test]
    fn skip_rr_simple_name_no_pointer() {
        // \x03 "www" \x07 "example" \x03 "com" \x00
        let wire: &[u8] = &[
            0x03, b'w', b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c',
            b'o', b'm', 0x00, // sentinel byte at position 17
            0xFF,
        ];
        let mut r = Reader::new(Bytes::from_static(wire));
        Name::skip_rr(&mut r).unwrap();
        // Cursor should be at 17 (past the 0x00, before 0xFF).
        assert_eq!(r.position(), 17);
    }

    #[test]
    fn skip_rr_root_name() {
        // Just the zero byte.
        let wire: &[u8] = &[0x00, 0xFF];
        let mut r = Reader::new(Bytes::from_static(wire));
        Name::skip_rr(&mut r).unwrap();
        assert_eq!(r.position(), 1);
    }

    #[test]
    fn skip_rr_name_ending_in_pointer() {
        // Simulate a message where the name at position 20 ends with a pointer
        // to position 12.
        //
        // Layout:
        //   bytes 0..12  : padding (e.g. a DNS header)
        //   bytes 12..16 : \x03 "com" \x00  (the pointer target)
        //   bytes 16..20 : padding
        //   bytes 20..   : \x07 "example" \xC0 \x0C  (name with trailing pointer)
        //
        // We craft a flat byte array and position the reader at offset 20.
        let mut msg = vec![0u8; 12]; // header padding
        // offset 12: \x03 "com" \x00
        msg.extend_from_slice(&[0x03, b'c', b'o', b'm', 0x00]);
        // offset 17..20: padding
        msg.extend_from_slice(&[0x00, 0x00, 0x00]);
        // offset 20: \x07 "example" \xC0 \x0C
        msg.extend_from_slice(&[0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0xC0, 0x0C]);
        // sentinel
        msg.push(0xAB);

        let mut r = Reader::new(Bytes::from(msg));
        // Advance to offset 20 manually (the RR name start).
        r.read_slice(20).unwrap();
        assert_eq!(r.position(), 20);

        Name::skip_rr(&mut r).unwrap();
        // After skip: cursor should be at 30 (20 + 7 + 1 (len) + 2 (pointer) = 30).
        // 20 + [1 (len_byte) + 7 (example) + 2 (pointer)] = 30
        assert_eq!(r.position(), 30);
    }

    // ── skip_rr: pointer loop → error ─────────────────────────────────────────

    #[test]
    fn skip_rr_pointer_loop_self_terminates() {
        // Build a message where offset 12 contains a pointer to itself: \xC0\x0C.
        let mut msg = vec![0u8; 12]; // header
        msg.extend_from_slice(&[0xC0, 0x0C]); // pointer at offset 12 → 12 (self-loop)

        let mut r = Reader::new(Bytes::from(msg));
        r.read_slice(12).unwrap(); // position at 12

        let err = Name::skip_rr(&mut r).unwrap_err();
        assert!(
            matches!(
                err,
                Error::InvalidPointerTarget { .. } | Error::NameSkipLimitExceeded
            ),
            "expected pointer loop to return an error, got: {err}"
        );
    }

    #[test]
    fn skip_rr_pointer_two_cycle_terminates() {
        // Pointer at offset 12 → 14, pointer at offset 14 → 12.
        // offset 12: \xC0 \x0E  (pointer to 14)
        // offset 14: \xC0 \x0C  (pointer to 12)
        let mut msg = vec![0u8; 12];
        msg.extend_from_slice(&[0xC0, 0x0E]); // offset 12: → 14
        msg.extend_from_slice(&[0xC0, 0x0C]); // offset 14: → 12

        let mut r = Reader::new(Bytes::from(msg));
        r.read_slice(12).unwrap();

        let err = Name::skip_rr(&mut r).unwrap_err();
        assert!(
            matches!(
                err,
                Error::InvalidPointerTarget { .. } | Error::NameSkipLimitExceeded
            ),
            "expected two-cycle loop to error, got: {err}"
        );
    }

    #[test]
    fn skip_rr_forward_pointer_rejected() {
        // Pointer at offset 12 pointing to offset 20 (forward).
        let mut msg = vec![0u8; 12];
        msg.extend_from_slice(&[0xC0, 0x14]); // pointer to 20

        let mut r = Reader::new(Bytes::from(msg));
        r.read_slice(12).unwrap();

        let err = Name::skip_rr(&mut r).unwrap_err();
        assert!(
            matches!(err, Error::InvalidPointerTarget { target: 20, .. }),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn skip_rr_out_of_bounds_pointer_rejected() {
        // Pointer at offset 12 pointing to offset 9999 (beyond message).
        let mut msg = vec![0u8; 12];
        msg.extend_from_slice(&[0xC0 | 0x27, 0x0F]); // 0x270F = 9999
        let mut r = Reader::new(Bytes::from(msg));
        r.read_slice(12).unwrap();

        let err = Name::skip_rr(&mut r).unwrap_err();
        assert!(
            matches!(err, Error::InvalidPointerTarget { .. }),
            "unexpected error: {err}"
        );
    }

    // ── skip_rr: truncated input ───────────────────────────────────────────────

    #[test]
    fn skip_rr_truncated_label_content() {
        // Says label is 5 bytes but only 2 bytes follow.
        let wire: &[u8] = &[0x05, b'a', b'b'];
        let mut r = Reader::new(Bytes::from_static(wire));
        let err = Name::skip_rr(&mut r).unwrap_err();
        assert!(
            matches!(err, Error::UnexpectedEof { .. }),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn skip_rr_truncated_pointer() {
        // 0xC0 with no second byte.
        let wire: &[u8] = &[0xC0];
        let mut r = Reader::new(Bytes::from_static(wire));
        let err = Name::skip_rr(&mut r).unwrap_err();
        assert!(
            matches!(err, Error::UnexpectedEof { .. }),
            "unexpected error: {err}"
        );
    }

    // ── No panic on any malformed input ──────────────────────────────────────

    #[test]
    fn no_panic_empty_buffer() {
        let mut r = reader_from(&[]);
        assert!(Name::read_question(&mut r).is_err());
    }

    #[test]
    fn no_panic_skip_empty_buffer() {
        let mut r = reader_from(&[]);
        assert!(Name::skip_rr(&mut r).is_err());
    }

    #[test]
    fn no_panic_all_ones() {
        let data = vec![0xFFu8; 512];
        let mut r = Reader::new(Bytes::from(data));
        // Should error cleanly (label too long or pointer rejection), never panic.
        let _ = Name::read_question(&mut r);
    }

    #[test]
    fn no_panic_skip_all_ones() {
        // All-0xFF: first byte 0xFF has top two bits set → compression pointer
        // pattern, but the target will be out of bounds.
        let data = vec![0xFFu8; 512];
        let mut r = Reader::new(Bytes::from(data));
        let _ = Name::skip_rr(&mut r);
    }

    // ── Reverse-DNS (PTR) parsing ─────────────────────────────────────────────

    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    /// Build the canonical `in-addr.arpa` name for an IPv4 address.
    fn v4_arpa(addr: Ipv4Addr) -> Name {
        let [a, b, c, d] = addr.octets();
        format!("{d}.{c}.{b}.{a}.in-addr.arpa")
            .parse()
            .expect("valid in-addr.arpa name")
    }

    /// Build the canonical `ip6.arpa` name for an IPv6 address.
    fn v6_arpa(addr: Ipv6Addr) -> Name {
        // 32 reversed nibbles, dot-separated, then ip6.arpa.
        let mut s = String::with_capacity(72);
        for octet in addr.octets().iter().rev() {
            let lo = octet & 0x0F;
            let hi = octet >> 4;
            // Least-significant nibble of the least-significant octet comes first.
            s.push_str(&format!("{lo:x}.{hi:x}."));
        }
        s.push_str("ip6.arpa");
        s.parse().expect("valid ip6.arpa name")
    }

    #[test]
    fn reverse_v4_round_trips() {
        let addr: Ipv4Addr = "192.168.1.5".parse().unwrap();
        let name = v4_arpa(addr);
        assert_eq!(name.to_string(), "5.1.168.192.in-addr.arpa.");
        assert_eq!(name.reverse_addr(), Some(IpAddr::V4(addr)));
    }

    #[test]
    fn reverse_v4_boundaries() {
        for addr in [
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(255, 255, 255, 255),
            Ipv4Addr::new(10, 0, 0, 1),
        ] {
            assert_eq!(v4_arpa(addr).reverse_addr(), Some(IpAddr::V4(addr)));
        }
    }

    #[test]
    fn reverse_v6_round_trips() {
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let name = v6_arpa(addr);
        assert_eq!(name.reverse_addr(), Some(IpAddr::V6(addr)));
    }

    #[test]
    fn reverse_v6_full_nibble_name() {
        // A hand-written full ip6.arpa name: 32 zero nibbles → the unspecified
        // address `::`.  Independent of the `v6_arpa` helper's own reversal.
        let zeros = "0.".repeat(32);
        let n: Name = format!("{zeros}ip6.arpa").parse().unwrap();
        assert_eq!(n.reverse_addr(), Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
    }

    #[test]
    fn reverse_rejects_octet_over_255() {
        // 256 is not a valid octet; the name parses as a Name but not as reverse.
        let n: Name = "256.1.168.192.in-addr.arpa".parse().unwrap();
        assert_eq!(n.reverse_addr(), None);
    }

    #[test]
    fn reverse_rejects_wrong_v4_label_count() {
        let short: Name = "1.168.192.in-addr.arpa".parse().unwrap();
        let long: Name = "9.5.1.168.192.in-addr.arpa".parse().unwrap();
        assert_eq!(short.reverse_addr(), None);
        assert_eq!(long.reverse_addr(), None);
    }

    #[test]
    fn reverse_rejects_wrong_v6_nibble_count() {
        // 31 nibbles instead of 32.
        let n: Name = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.ip6.arpa"
            .parse()
            .unwrap();
        assert_eq!(n.reverse_addr(), None);
    }

    #[test]
    fn reverse_rejects_non_hex_nibble() {
        // 'g' is not a hex digit; replace the first nibble of an otherwise valid name.
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let valid = v6_arpa(addr).to_string();
        let bad = valid.replacen('1', "g", 1);
        let n: Name = bad.parse().unwrap();
        assert_eq!(n.reverse_addr(), None);
    }

    #[test]
    fn reverse_rejects_multi_digit_nibble() {
        // A two-character first nibble label "12" — must be a single hex digit.
        let n: Name = "12.b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.2.ip6.arpa"
            .parse()
            .unwrap();
        assert_eq!(n.reverse_addr(), None);
    }

    #[test]
    fn reverse_forward_name_is_none() {
        let n: Name = "www.example.com".parse().unwrap();
        assert_eq!(n.reverse_addr(), None);
    }

    #[test]
    fn reverse_bare_arpa_zones_are_none() {
        // The zone apexes themselves carry no address.
        assert_eq!("in-addr.arpa".parse::<Name>().unwrap().reverse_addr(), None);
        assert_eq!("ip6.arpa".parse::<Name>().unwrap().reverse_addr(), None);
        assert_eq!("arpa".parse::<Name>().unwrap().reverse_addr(), None);
    }
}
