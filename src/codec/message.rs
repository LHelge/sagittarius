//! Shallow DNS message parse: header + single question, no RR sections.
//!
//! This is the **only** parse on the routing hot path (SPEC §2.1, §5 step 2).
//! It reads exactly 12 bytes for the header and the single question section,
//! then stops — the answer, authority, and additional sections are never
//! touched.  The full original datagram is retained as a refcounted
//! [`bytes::Bytes`] for zero-copy passthrough and raw-bytes caching (SPEC §8).
//!
//! # Security properties
//!
//! - Never panics on untrusted/malformed input.
//! - Rejects messages longer than 65535 bytes before any parsing work.
//! - Rejects `QDCOUNT != 1`.
//! - Delegates pointer rejection and label/name limits to
//!   [`name::Name::read_question`].
//!
//! # Transaction-ID recovery
//!
//! When parsing fails *after* the 12-byte header was successfully read, the
//! error carries `id = Some(header.id)` so the pipeline can synthesize a
//! `FORMERR` addressed to the client (E6.5).  When the header itself could not
//! be read (message too short / too long), `id = None` and the caller drops
//! the packet.
//!
//! # Entry point
//!
//! ```rust
//! use bytes::Bytes;
//! use sagittarius::codec::message::Query;
//!
//! // Build a minimal A query for "example.com"
//! # fn build_example_query() -> Bytes {
//! #     use sagittarius::codec::{header::Header, name::Name, writer::Writer};
//! #     let mut w = Writer::with_capacity(64);
//! #     let hdr = Header::new(0x1234).with_qdcount(1).with_rd(true);
//! #     hdr.write(&mut w);
//! #     let name: Name = "example.com".parse().unwrap();
//! #     name.write(&mut w);
//! #     w.write_u16(1u16);  // QTYPE A
//! #     w.write_u16(1u16);  // QCLASS IN
//! #     w.finish()
//! # }
//! let raw: Bytes = build_example_query();
//! let query = Query::try_from(raw).expect("valid query");
//! assert_eq!(query.header().id, 0x1234);
//! assert_eq!(query.question().qtype, sagittarius::codec::message::Qtype::A);
//! ```

use bytes::Bytes;

use crate::codec::{Error, header::Header, name::Name, reader::Reader, writer::Writer};

// ── Maximum message length ────────────────────────────────────────────────────

/// Maximum DNS message length in bytes.
///
/// DNS over TCP uses a 2-byte length prefix (`u16`), so no well-formed message
/// can exceed 65535 bytes.  Inputs larger than this are rejected with
/// [`Error::MessageTooLong`] before any other parsing work is done — this also
/// means the transaction ID is **not** recoverable for oversized messages
/// (`ParseError::id == None`).
pub const MAX_MESSAGE_LEN: usize = 65535;

// ── Qtype ─────────────────────────────────────────────────────────────────────

/// DNS QTYPE field (RFC 1035 §3.2.3 / §3.2.2).
///
/// Known values are named variants; any other value is preserved via
/// `Other(u16)` for lossless round-tripping.
///
/// Used as part of the [`Question`] and as a cache key component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Qtype {
    /// A (host address, IPv4) — type value 1 (RFC 1035 §3.4.1).
    A,
    /// AAAA (IPv6 address) — type value 28 (RFC 3596).
    Aaaa,
    /// Any other QTYPE value, preserved for lossless round-tripping.
    Other(u16),
}

impl From<u16> for Qtype {
    fn from(v: u16) -> Self {
        match v {
            1 => Self::A,
            28 => Self::Aaaa,
            other => Self::Other(other),
        }
    }
}

impl From<Qtype> for u16 {
    fn from(qt: Qtype) -> u16 {
        match qt {
            Qtype::A => 1,
            Qtype::Aaaa => 28,
            Qtype::Other(v) => v,
        }
    }
}

impl Qtype {
    /// IANA mnemonic for a well-known QTYPE number, or `None` if unrecognized.
    ///
    /// Purely a presentation aid: the engine only answers `A`/`AAAA`
    /// authoritatively and forwards everything else as raw bytes, so these
    /// extra types are *not* enum variants — they're named here only so the
    /// query log shows `HTTPS` rather than `TYPE65` for the records modern
    /// clients query most. Anything not listed falls back to RFC 3597 `TYPE<n>`.
    fn well_known_name(value: u16) -> Option<&'static str> {
        Some(match value {
            2 => "NS",
            5 => "CNAME",
            6 => "SOA",
            12 => "PTR",
            15 => "MX",
            16 => "TXT",
            33 => "SRV",
            35 => "NAPTR",
            39 => "DNAME",
            43 => "DS",
            46 => "RRSIG",
            47 => "NSEC",
            48 => "DNSKEY",
            50 => "NSEC3",
            52 => "TLSA",
            64 => "SVCB",
            65 => "HTTPS",
            255 => "ANY",
            257 => "CAA",
            _ => return None,
        })
    }
}

impl std::fmt::Display for Qtype {
    /// Canonical presentation form: the mnemonic for known types, and the
    /// RFC 3597 generic `TYPE<n>` representation for unknown ones. This is the
    /// single rendering used by the query log and admin UI.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::A => f.write_str("A"),
            Self::Aaaa => f.write_str("AAAA"),
            Self::Other(v) => match Self::well_known_name(*v) {
                Some(name) => f.write_str(name),
                None => write!(f, "TYPE{v}"),
            },
        }
    }
}

// ── Qclass ────────────────────────────────────────────────────────────────────

/// DNS QCLASS field (RFC 1035 §3.2.5 / §3.2.4).
///
/// Known values are named variants; any other value is preserved via
/// `Other(u16)` for lossless round-tripping.
///
/// Used as part of the [`Question`] and as a cache key component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Qclass {
    /// IN (Internet) — class value 1 (RFC 1035 §3.2.4).
    In,
    /// Any other QCLASS value, preserved for lossless round-tripping.
    Other(u16),
}

impl From<u16> for Qclass {
    fn from(v: u16) -> Self {
        match v {
            1 => Self::In,
            other => Self::Other(other),
        }
    }
}

impl From<Qclass> for u16 {
    fn from(qc: Qclass) -> u16 {
        match qc {
            Qclass::In => 1,
            Qclass::Other(v) => v,
        }
    }
}

// ── Question ──────────────────────────────────────────────────────────────────

/// The single question entry from a DNS query message (RFC 1035 §4.1.2).
///
/// Holds the query name, type, and class.  Implements [`Eq`] and [`Hash`] so
/// it can be used directly as a cache key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Question {
    /// The query name (QNAME), normalized to lowercase with trailing dot.
    pub name: Name,
    /// The query type (QTYPE).
    pub qtype: Qtype,
    /// The query class (QCLASS).
    pub qclass: Qclass,
}

impl Question {
    /// Read a [`Question`] from `reader`.
    ///
    /// Reads the QNAME via [`Name::read_question`] (which enforces label/name
    /// limits and rejects compression pointers), then reads the 2-byte QTYPE
    /// and 2-byte QCLASS fields.
    ///
    /// # Errors
    ///
    /// Propagates any error returned by [`Name::read_question`] or by the
    /// subsequent `u16` reads (e.g. [`Error::UnexpectedEof`]).
    pub fn read(reader: &mut Reader) -> Result<Self, Error> {
        let name = Name::read_question(reader)?;
        let qtype = Qtype::from(reader.read_u16()?);
        let qclass = Qclass::from(reader.read_u16()?);
        Ok(Self {
            name,
            qtype,
            qclass,
        })
    }

    /// Encode this [`Question`] into `writer` in wire format.
    ///
    /// Writes: QNAME (length-prefixed labels + zero terminator), QTYPE (u16),
    /// QCLASS (u16).  Round-trips cleanly with [`Question::read`].
    pub fn write(&self, writer: &mut Writer) {
        self.name.write(writer);
        writer.write_u16(u16::from(self.qtype));
        writer.write_u16(u16::from(self.qclass));
    }
}

// ── ParseError ────────────────────────────────────────────────────────────────

/// Error returned by [`Query::parse`] / `TryFrom<Bytes>` for [`Query`].
///
/// Carries the optional transaction ID alongside the error kind so that the
/// pipeline can synthesize a `FORMERR` response addressed to the originating
/// client when the ID was recoverable.
///
/// # ID recovery rules
///
/// | Failure point | `id` |
/// |---|---|
/// | Message longer than 65535 bytes | `None` — size check before header read |
/// | Header shorter than 12 bytes | `None` — header unreadable |
/// | `QDCOUNT != 1` | `Some(header.id)` — header was read |
/// | Malformed question (name / qtype / qclass truncated) | `Some(header.id)` |
/// | Compression pointer in question | `Some(header.id)` |
/// | Label or name too long in question | `Some(header.id)` |
#[derive(Debug)]
pub struct ParseError {
    /// Transaction ID extracted from the header, if the header was readable.
    ///
    /// `None` when the message was too long or too short to read the header.
    /// `Some(id)` for all later validation failures.
    pub id: Option<u16>,

    /// The underlying codec error describing what went wrong.
    pub kind: Error,
}

impl ParseError {
    /// Construct a [`ParseError`] with no transaction ID.
    fn without_id(kind: Error) -> Self {
        Self { id: None, kind }
    }

    /// Construct a [`ParseError`] with a known transaction ID.
    fn with_id(id: u16, kind: Error) -> Self {
        Self { id: Some(id), kind }
    }
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.id {
            Some(id) => write!(f, "DNS parse error (id={id:#06x}): {}", self.kind),
            None => write!(f, "DNS parse error (id=unknown): {}", self.kind),
        }
    }
}

impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.kind)
    }
}

// ── Query ─────────────────────────────────────────────────────────────────────

/// A shallow, routing-critical view of a DNS query message.
///
/// Holds only what is needed to route the query:
/// - `raw` — the full original datagram as [`bytes::Bytes`] (refcounted,
///   zero-copy) for raw passthrough / caching (SPEC §8).
/// - `header` — the parsed 12-byte DNS header.
/// - `question` — the single parsed question (QNAME + QTYPE + QCLASS).
///
/// The answer, authority, and additional sections are **not** parsed; they are
/// entirely ignored by this type.  A query normally has those counts at zero,
/// but the parser does not fail if they are non-zero — routing needs only the
/// header and question.
///
/// # Construction
///
/// Use [`TryFrom<Bytes>`] (or [`TryFrom<&[u8]>`]) as the primary entry point.
/// The parse is available as an inherent method [`Query::parse`] that both
/// `TryFrom` impls delegate to.
#[derive(Debug, Clone)]
pub struct Query {
    /// The original datagram, refcounted.  Cheap to clone; no data is copied.
    raw: Bytes,
    /// The parsed 12-byte DNS header.
    header: Header,
    /// The single parsed question section entry.
    question: Question,
    /// Byte offset of the first byte *after* the question section in `raw`.
    ///
    /// This is `reader.position()` immediately after [`Question::read`]
    /// completes.  Used by [`Query::question_wire`] to raw-copy the question
    /// bytes into response synthesis output, preserving DNS 0x20
    /// case-randomization without re-encoding the normalized [`Name`].
    question_end: usize,
}

impl Query {
    /// Parse a DNS query from a [`Bytes`] datagram.
    ///
    /// This is the primary parse entry point.  Both [`TryFrom<Bytes>`] and
    /// [`TryFrom<&[u8]>`] delegate here.
    ///
    /// # Validation order
    ///
    /// 1. **Size guard**: reject messages longer than [`MAX_MESSAGE_LEN`]
    ///    (65535 bytes) — `id = None`.
    /// 2. **Header read**: attempt to read 12 bytes — on failure `id = None`.
    /// 3. **QDCOUNT check**: reject unless exactly 1 — `id = Some(header.id)`.
    /// 4. **Question read**: parse QNAME + QTYPE + QCLASS — `id = Some(header.id)`.
    ///
    /// The RR sections (answer/authority/additional) are not read or validated.
    ///
    /// # Errors
    ///
    /// Returns a [`ParseError`] whose `id` field is:
    /// - `None` — header was not readable (message too long or too short).
    /// - `Some(id)` — header was read; later step failed.
    pub fn parse(raw: Bytes) -> Result<Self, ParseError> {
        // ── 1. Size guard ──────────────────────────────────────────────────────
        // Check before any parsing work so absurd buffers are rejected cheaply.
        // id is None because we have not yet read the header.
        if raw.len() > MAX_MESSAGE_LEN {
            return Err(ParseError::without_id(Error::MessageTooLong(raw.len())));
        }

        let mut reader = Reader::new(raw.clone());

        // ── 2. Header ──────────────────────────────────────────────────────────
        // MessageTooShort is returned if < 12 bytes remain.  id stays None.
        let header = Header::read(&mut reader).map_err(ParseError::without_id)?;

        // ── 3. QDCOUNT check ───────────────────────────────────────────────────
        if header.qdcount != 1 {
            return Err(ParseError::with_id(
                header.id,
                Error::InvalidQuestionCount(header.qdcount),
            ));
        }

        // ── 4. Question ────────────────────────────────────────────────────────
        let question =
            Question::read(&mut reader).map_err(|e| ParseError::with_id(header.id, e))?;

        // Record the byte offset immediately after the question section.
        // This allows response synthesis to raw-copy the question bytes
        // verbatim (preserving DNS 0x20 case-randomization).
        let question_end = reader.position();

        Ok(Self {
            raw,
            header,
            question,
            question_end,
        })
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    /// The original datagram (refcounted; cheap to clone).
    #[must_use]
    pub fn raw(&self) -> &Bytes {
        &self.raw
    }

    /// The parsed DNS header.
    #[must_use]
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// The single parsed question entry.
    #[must_use]
    pub fn question(&self) -> &Question {
        &self.question
    }

    /// The byte offset immediately after the question section in the raw
    /// datagram (i.e. `reader.position()` after [`Question::read`] returns).
    ///
    /// Equal to the number of bytes consumed by the 12-byte header plus the
    /// question section (QNAME wire bytes + 2-byte QTYPE + 2-byte QCLASS).
    ///
    /// Used by [`crate::codec::synth`] to raw-copy the question section into
    /// synthesized responses.
    #[must_use]
    pub fn question_end(&self) -> usize {
        self.question_end
    }

    /// The raw question-section bytes from the original datagram
    /// (`raw[12..question_end]`), as a zero-copy [`Bytes`] slice.
    ///
    /// This slice contains the QNAME wire bytes (unmodified, including any
    /// DNS 0x20 case-randomization) plus the 2-byte QTYPE and 2-byte QCLASS
    /// fields.  Response synthesis raw-copies these bytes into the response
    /// question section rather than re-encoding the normalized [`Name`], so
    /// that the case of each label byte is preserved exactly as sent by the
    /// client.
    ///
    /// The slice always starts at offset 12 (immediately after the DNS header).
    #[must_use]
    pub fn question_wire(&self) -> Bytes {
        // Safety: question_end is set to reader.position() after Question::read,
        // which only advances the cursor within the bounds of `raw`.  The slice
        // [12..question_end] is therefore always valid.
        self.raw.slice(12..self.question_end)
    }
}

// ── TryFrom impls ─────────────────────────────────────────────────────────────

impl TryFrom<Bytes> for Query {
    type Error = ParseError;

    /// Parse a DNS query from an owned [`Bytes`] buffer.
    ///
    /// Delegates to [`Query::parse`].
    fn try_from(raw: Bytes) -> Result<Self, Self::Error> {
        Query::parse(raw)
    }
}

impl TryFrom<&[u8]> for Query {
    type Error = ParseError;

    /// Parse a DNS query from a byte slice.
    ///
    /// Copies `raw` into a new [`Bytes`] allocation (one copy), then delegates
    /// to [`Query::parse`].
    fn try_from(raw: &[u8]) -> Result<Self, Self::Error> {
        Query::parse(Bytes::copy_from_slice(raw))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{header::Header, name::Name, writer::Writer};

    // ── Test helpers ──────────────────────────────────────────────────────────

    /// Build a complete DNS query datagram for `name` with the given qtype and
    /// optional QDCOUNT override (default 1).  `id` and `rd` are configurable.
    fn build_query(
        id: u16,
        rd: bool,
        name: &str,
        qtype: u16,
        qclass: u16,
        qdcount_override: Option<u16>,
    ) -> Bytes {
        let mut w = Writer::with_capacity(64);
        let qdcount = qdcount_override.unwrap_or(1);
        let hdr = Header::new(id).with_rd(rd).with_qdcount(qdcount);
        hdr.write(&mut w);
        if qdcount_override.is_none() || qdcount_override == Some(1) {
            // Write the question
            let n: Name = name.parse().expect("valid name in test helper");
            n.write(&mut w);
            w.write_u16(qtype);
            w.write_u16(qclass);
        }
        w.finish()
    }

    /// Build a query for `name` with a QDCOUNT field set to `qdcount` but
    /// *always* writing the real question bytes (even if QDCOUNT is 0 or 2).
    fn build_query_with_bad_qdcount(id: u16, name: &str, qdcount: u16) -> Bytes {
        let mut w = Writer::with_capacity(64);
        let hdr = Header::new(id).with_qdcount(qdcount);
        hdr.write(&mut w);
        // Always write one real question
        let n: Name = name.parse().unwrap();
        n.write(&mut w);
        w.write_u16(1u16); // A
        w.write_u16(1u16); // IN
        w.finish()
    }

    // ── Qtype conversions ─────────────────────────────────────────────────────

    #[test]
    fn qtype_a_round_trips() {
        assert_eq!(Qtype::from(1u16), Qtype::A);
        assert_eq!(u16::from(Qtype::A), 1u16);
    }

    #[test]
    fn qtype_aaaa_round_trips() {
        assert_eq!(Qtype::from(28u16), Qtype::Aaaa);
        assert_eq!(u16::from(Qtype::Aaaa), 28u16);
    }

    #[test]
    fn qtype_other_preserved() {
        assert_eq!(Qtype::from(255u16), Qtype::Other(255));
        assert_eq!(u16::from(Qtype::Other(255)), 255u16);
        // MX = 15
        assert_eq!(Qtype::from(15u16), Qtype::Other(15));
        assert_eq!(u16::from(Qtype::Other(15)), 15u16);
    }

    #[test]
    fn qtype_display_uses_mnemonic_and_rfc3597_generic() {
        assert_eq!(Qtype::A.to_string(), "A");
        assert_eq!(Qtype::Aaaa.to_string(), "AAAA");
        // Well-known types render with their IANA mnemonic.
        assert_eq!(Qtype::Other(65).to_string(), "HTTPS");
        assert_eq!(Qtype::Other(64).to_string(), "SVCB");
        assert_eq!(Qtype::Other(5).to_string(), "CNAME");
        assert_eq!(Qtype::Other(15).to_string(), "MX");
        // Genuinely unknown types fall back to the RFC 3597 generic form.
        assert_eq!(Qtype::Other(1000).to_string(), "TYPE1000");
    }

    #[test]
    fn qtype_all_u16_round_trip() {
        for v in 0u16..=65535 {
            let qt = Qtype::from(v);
            let back = u16::from(qt);
            assert_eq!(back, v, "Qtype u16 round-trip failed for {v}");
        }
    }

    // ── Qclass conversions ────────────────────────────────────────────────────

    #[test]
    fn qclass_in_round_trips() {
        assert_eq!(Qclass::from(1u16), Qclass::In);
        assert_eq!(u16::from(Qclass::In), 1u16);
    }

    #[test]
    fn qclass_other_preserved() {
        assert_eq!(Qclass::from(3u16), Qclass::Other(3));
        assert_eq!(u16::from(Qclass::Other(3)), 3u16);
    }

    #[test]
    fn qclass_all_u16_round_trip() {
        for v in 0u16..=65535 {
            let qc = Qclass::from(v);
            let back = u16::from(qc);
            assert_eq!(back, v, "Qclass u16 round-trip failed for {v}");
        }
    }

    // ── Valid A query ─────────────────────────────────────────────────────────

    #[test]
    fn parse_valid_a_query() {
        let raw = build_query(0x1234, true, "example.com", 1, 1, None);
        let q = Query::try_from(raw).expect("valid A query should parse");

        assert_eq!(q.header().id, 0x1234, "id mismatch");
        assert!(!q.header().qr(), "QR should be 0 (query)");
        assert!(q.header().rd(), "RD should be set");
        assert_eq!(q.header().qdcount, 1);

        let question = q.question();
        assert_eq!(question.name.to_string(), "example.com.", "QNAME mismatch");
        assert_eq!(question.qtype, Qtype::A, "QTYPE should be A");
        assert_eq!(question.qclass, Qclass::In, "QCLASS should be IN");
    }

    // ── Valid AAAA query ──────────────────────────────────────────────────────

    #[test]
    fn parse_valid_aaaa_query() {
        let raw = build_query(0xABCD, true, "example.com", 28, 1, None);
        let q = Query::try_from(raw).expect("valid AAAA query should parse");

        assert_eq!(q.header().id, 0xABCD);
        assert!(!q.header().qr());
        assert!(q.header().rd());
        assert_eq!(q.question().qtype, Qtype::Aaaa, "QTYPE should be AAAA");
        assert_eq!(q.question().qclass, Qclass::In);
        assert_eq!(q.question().name.to_string(), "example.com.");
    }

    // ── Trailing bytes after question are accepted ─────────────────────────────

    #[test]
    fn parse_query_with_trailing_bytes_accepted() {
        // Append fake OPT-like bytes after the valid query; shallow parse
        // should succeed without erroring on the trailing bytes.
        let mut raw = build_query(0x0001, false, "example.com", 1, 1, None).to_vec();
        // Simulate an OPT record or any trailing bytes.
        raw.extend_from_slice(&[
            0x00, // root name (OPT)
            0x00, 0x29, // QTYPE=OPT (41)
            0x10, 0x00, // UDP payload size
            0x00, // extended RCODE
            0x00, // EDNS version
            0x00, 0x00, // Z flags
            0x00, 0x00, // RDLENGTH
        ]);
        let bytes = Bytes::from(raw);
        let q = Query::try_from(bytes.clone()).expect("trailing bytes must not cause error");

        // The raw field carries the full original datagram including trailing bytes.
        assert_eq!(
            q.raw().len(),
            bytes.len(),
            "raw must hold the full datagram"
        );
        assert_eq!(q.question().name.to_string(), "example.com.");
        assert_eq!(q.question().qtype, Qtype::A);
    }

    // ── raw field is the full original Bytes ──────────────────────────────────

    #[test]
    fn parse_raw_field_is_full_datagram() {
        let raw = build_query(0x5678, true, "test.example", 1, 1, None);
        let expected_len = raw.len();
        let q = Query::try_from(raw).unwrap();
        assert_eq!(q.raw().len(), expected_len);
    }

    // ── QDCOUNT != 1 ──────────────────────────────────────────────────────────

    #[test]
    fn qdcount_zero_rejected_with_id() {
        let raw = build_query_with_bad_qdcount(0x1111, "example.com", 0);
        let err = Query::try_from(raw).expect_err("QDCOUNT=0 must fail");
        assert!(
            matches!(err.kind, Error::InvalidQuestionCount(0)),
            "unexpected error kind: {:?}",
            err.kind
        );
        assert_eq!(err.id, Some(0x1111), "id must be Some when header was read");
    }

    #[test]
    fn qdcount_two_rejected_with_id() {
        let raw = build_query_with_bad_qdcount(0x2222, "example.com", 2);
        let err = Query::try_from(raw).expect_err("QDCOUNT=2 must fail");
        assert!(
            matches!(err.kind, Error::InvalidQuestionCount(2)),
            "unexpected error kind: {:?}",
            err.kind
        );
        assert_eq!(err.id, Some(0x2222));
    }

    // ── Compression pointer in question ───────────────────────────────────────

    #[test]
    fn compression_pointer_in_question_rejected_with_id() {
        // Build a header with QDCOUNT=1, then inject a compression pointer
        // as the first byte of the question QNAME.
        let mut w = Writer::with_capacity(16);
        Header::new(0x3333).with_qdcount(1).write(&mut w);
        // Compression pointer 0xC0 0x0C → points to offset 12 (itself).
        w.write_u8(0xC0);
        w.write_u8(0x0C);
        let raw = w.finish();

        let err = Query::try_from(raw).expect_err("compression pointer must fail");
        assert!(
            matches!(err.kind, Error::CompressionPointerInQuestion),
            "unexpected error kind: {:?}",
            err.kind
        );
        assert_eq!(err.id, Some(0x3333), "id must be Some");
    }

    // ── Truncated question ────────────────────────────────────────────────────

    #[test]
    fn truncated_question_name_rejected_with_id() {
        // Header is valid (QDCOUNT=1) but the question is cut off mid-name.
        let mut w = Writer::with_capacity(16);
        Header::new(0x4444).with_qdcount(1).write(&mut w);
        // Start writing a name but truncate it: length byte says 7, but no data.
        w.write_u8(7); // label length = 7, but no label bytes follow
        let raw = w.finish();

        let err = Query::try_from(raw).expect_err("truncated question must fail");
        assert!(
            matches!(err.kind, Error::UnexpectedEof { .. }),
            "unexpected error kind: {:?}",
            err.kind
        );
        assert_eq!(err.id, Some(0x4444), "id must be Some");
    }

    #[test]
    fn truncated_question_qtype_rejected_with_id() {
        // Header + valid QNAME, but only 1 byte of the 2-byte QTYPE.
        let mut w = Writer::with_capacity(32);
        Header::new(0x5555).with_qdcount(1).write(&mut w);
        let name: Name = "example.com".parse().unwrap();
        name.write(&mut w);
        w.write_u8(0x00); // only 1 byte of QTYPE instead of 2
        let raw = w.finish();

        let err = Query::try_from(raw).expect_err("truncated QTYPE must fail");
        assert!(
            matches!(err.kind, Error::UnexpectedEof { .. }),
            "unexpected error kind: {:?}",
            err.kind
        );
        assert_eq!(err.id, Some(0x5555));
    }

    #[test]
    fn truncated_question_qclass_rejected_with_id() {
        // Header + valid QNAME + valid QTYPE, but only 1 byte of QCLASS.
        let mut w = Writer::with_capacity(32);
        Header::new(0x6666).with_qdcount(1).write(&mut w);
        let name: Name = "example.com".parse().unwrap();
        name.write(&mut w);
        w.write_u16(1u16); // QTYPE = A (valid)
        w.write_u8(0x00); // only 1 byte of QCLASS instead of 2
        let raw = w.finish();

        let err = Query::try_from(raw).expect_err("truncated QCLASS must fail");
        assert!(
            matches!(err.kind, Error::UnexpectedEof { .. }),
            "unexpected error kind: {:?}",
            err.kind
        );
        assert_eq!(err.id, Some(0x6666));
    }

    // ── Label length violation ────────────────────────────────────────────────

    #[test]
    fn label_too_long_in_question_rejected_with_id() {
        // Header + a label length byte of 64 (> 63 max).
        let mut w = Writer::with_capacity(32);
        Header::new(0x7777).with_qdcount(1).write(&mut w);
        w.write_u8(64); // label length = 64 → exceeds MAX_LABEL_LEN
        // Provide the bytes the reader would try to consume (to avoid a
        // spurious EOF error masking the LabelTooLong error).
        let label_bytes = vec![b'a'; 64];
        w.write_slice(&label_bytes);
        w.write_u8(0); // root terminator
        let raw = w.finish();

        let err = Query::try_from(raw).expect_err("label too long must fail");
        assert!(
            matches!(err.kind, Error::LabelTooLong(64)),
            "unexpected error kind: {:?}",
            err.kind
        );
        assert_eq!(err.id, Some(0x7777));
    }

    // ── Header unreadable — id must be None ───────────────────────────────────

    #[test]
    fn buffer_shorter_than_12_bytes_id_is_none() {
        for n in 0..12usize {
            let raw = Bytes::from(vec![0xAAu8; n]);
            let err = Query::try_from(raw).expect_err("short buffer must fail");
            assert!(
                matches!(err.kind, Error::MessageTooShort(_)),
                "n={n}: unexpected error kind: {:?}",
                err.kind
            );
            assert_eq!(
                err.id, None,
                "n={n}: id must be None when header is unreadable"
            );
        }
    }

    // ── Oversized buffer — id must be None ────────────────────────────────────

    #[test]
    fn oversized_buffer_rejected_with_id_none() {
        // Build a syntactically valid message, then extend it past 65535 bytes.
        let base = build_query(0x9999, false, "example.com", 1, 1, None);
        let mut raw = base.to_vec();
        // Pad to 65536 bytes.
        raw.resize(65536, 0u8);
        let err = Query::try_from(raw.as_slice()).expect_err("oversized buffer must fail");
        assert!(
            matches!(err.kind, Error::MessageTooLong(65536)),
            "unexpected error kind: {:?}",
            err.kind
        );
        // Size is checked before header read → id is None.
        assert_eq!(err.id, None, "id must be None for oversized message");
    }

    #[test]
    fn message_at_max_len_accepted() {
        // A query exactly at 65535 bytes should not be rejected by the size guard
        // (though it will likely fail on malformed content — we only care that
        // the error is NOT MessageTooLong).
        let base = build_query(0x0001, false, "example.com", 1, 1, None);
        let mut raw = base.to_vec();
        raw.resize(65535, 0u8);
        let result = Query::try_from(raw.as_slice());
        // Could succeed or fail on the trailing zeros (they are ignored by the
        // shallow parser), but must not fail with MessageTooLong.
        if let Err(e) = &result {
            assert!(
                !matches!(e.kind, Error::MessageTooLong(_)),
                "65535-byte message should not be rejected as too long"
            );
        }
    }

    // ── No panic on arbitrary bytes ───────────────────────────────────────────

    #[test]
    fn no_panic_empty_input() {
        let _ = Query::try_from(Bytes::new());
    }

    #[test]
    fn no_panic_all_zeros_12_bytes() {
        // 12 bytes of zeros: valid header parse (QDCOUNT=0 → InvalidQuestionCount).
        let raw = Bytes::from(vec![0u8; 12]);
        let result = Query::try_from(raw);
        assert!(result.is_err());
        // Must not panic.
    }

    #[test]
    fn no_panic_all_zeros_100_bytes() {
        let raw = Bytes::from(vec![0u8; 100]);
        let _ = Query::try_from(raw);
    }

    #[test]
    fn no_panic_all_ones_100_bytes() {
        let data = vec![0xFFu8; 100];
        let _ = Query::try_from(data.as_slice());
    }

    #[test]
    fn no_panic_random_ish_bytes() {
        // A pseudo-random-looking byte pattern — should error cleanly, not panic.
        let data: Vec<u8> = (0u8..=255).cycle().take(512).collect();
        let _ = Query::try_from(data.as_slice());
    }

    // ── Round-trip: write header+question, parse back ─────────────────────────

    #[test]
    fn round_trip_a_query() {
        let id = 0xBEEF;
        let name_str = "www.example.com";
        let qtype_val = 1u16; // A
        let qclass_val = 1u16; // IN

        // Build using writer primitives.
        let mut w = Writer::with_capacity(64);
        let hdr = Header::new(id).with_qdcount(1).with_rd(true);
        hdr.write(&mut w);
        let name: Name = name_str.parse().unwrap();
        name.write(&mut w);
        w.write_u16(qtype_val);
        w.write_u16(qclass_val);
        let raw = w.finish();

        // Parse back.
        let q = Query::try_from(raw).expect("round-trip must succeed");

        assert_eq!(q.header().id, id);
        assert_eq!(q.header().qdcount, 1);
        assert!(q.header().rd());
        assert!(!q.header().qr());
        assert_eq!(q.question().name.to_string(), "www.example.com.");
        assert_eq!(q.question().qtype, Qtype::A);
        assert_eq!(q.question().qclass, Qclass::In);
    }

    #[test]
    fn round_trip_aaaa_query() {
        let mut w = Writer::with_capacity(64);
        let hdr = Header::new(0x1111).with_qdcount(1).with_rd(true);
        hdr.write(&mut w);
        let name: Name = "ipv6.example.com".parse().unwrap();
        name.write(&mut w);
        w.write_u16(28u16); // AAAA
        w.write_u16(1u16); // IN
        let raw = w.finish();

        let q = Query::try_from(raw).unwrap();
        assert_eq!(q.header().id, 0x1111);
        assert_eq!(q.question().qtype, Qtype::Aaaa);
        assert_eq!(q.question().name.to_string(), "ipv6.example.com.");
    }

    // ── Question::write / Question::read round-trip ───────────────────────────

    #[test]
    fn question_write_read_round_trip() {
        let original = Question {
            name: "sub.domain.test".parse().unwrap(),
            qtype: Qtype::Aaaa,
            qclass: Qclass::In,
        };

        let mut w = Writer::new();
        original.write(&mut w);
        let bytes = w.finish();

        let mut reader = Reader::new(bytes);
        let decoded = Question::read(&mut reader).unwrap();

        assert_eq!(decoded.name, original.name);
        assert_eq!(decoded.qtype, original.qtype);
        assert_eq!(decoded.qclass, original.qclass);
    }

    // ── ParseError Display ────────────────────────────────────────────────────

    #[test]
    fn parse_error_display_with_id() {
        let e = ParseError::with_id(0xABCD, Error::InvalidQuestionCount(0));
        let s = e.to_string();
        assert!(
            s.contains("0xabcd") || s.contains("0xABCD") || s.contains("abcd"),
            "display should include id: {s}"
        );
    }

    #[test]
    fn parse_error_display_without_id() {
        let e = ParseError::without_id(Error::MessageTooShort(5));
        let s = e.to_string();
        assert!(
            s.contains("unknown"),
            "display should indicate unknown id: {s}"
        );
    }

    // ── TryFrom<&[u8]> ───────────────────────────────────────────────────────

    #[test]
    fn try_from_slice_copies_and_parses() {
        let raw = build_query(0x1234, true, "slice.test", 1, 1, None);
        let slice: &[u8] = &raw[..];
        let q = Query::try_from(slice).expect("TryFrom<&[u8]> must work");
        assert_eq!(q.header().id, 0x1234);
        assert_eq!(q.question().name.to_string(), "slice.test.");
    }
}
