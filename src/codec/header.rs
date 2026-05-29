//! DNS message header — 12-byte wire format codec (RFC 1035 §4.1.1).
//!
//! # Wire layout (big-endian)
//!
//! ```text
//!  0-1   ID
//!  2-3   Flags:  QR(1) Opcode(4) AA(1) TC(1) RD(1) | RA(1) Z(3) RCODE(4)
//!  4-5   QDCOUNT
//!  6-7   ANCOUNT
//!  8-9   NSCOUNT
//! 10-11  ARCOUNT
//! ```
//!
//! Byte 2 bits (MSB→LSB): QR, Opcode[3..0], AA, TC, RD.
//! Byte 3 bits (MSB→LSB): RA, Z[2..0], RCODE[3..0].
//!
//! # Design
//!
//! Flags are stored as a raw `u16` bitfield.  Named bit-mask and shift
//! constants are defined as associated constants on [`Header`]; no magic
//! numbers appear at call sites.  Typed accessors surface [`Opcode`] and
//! [`Rcode`] enum values.  Builder-style `with_*` methods return `Self` for
//! ergonomic header construction, and in-place `set_*` methods are also
//! provided for mutation.
//!
//! The representation is allocation-free and `Copy`.

use crate::codec::{Error, reader::Reader, writer::Writer};

// ── Opcode ────────────────────────────────────────────────────────────────────

/// DNS opcode field (4 bits, RFC 1035 §4.1.1 and RFC 2136 / RFC 1996).
///
/// All 16 representable values round-trip losslessly through [`From`]
/// conversions.  Unknown values are preserved via the `Other(u8)` variant
/// rather than being rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Opcode {
    /// Standard query (0).
    Query,
    /// Inverse query (1) — obsoleted by RFC 3425 but wire-value preserved.
    IQuery,
    /// Server status request (2).
    Status,
    /// Notify (4, RFC 1996).
    Notify,
    /// Dynamic update (5, RFC 2136).
    Update,
    /// Any other (reserved / future) opcode value.
    Other(u8),
}

impl From<u8> for Opcode {
    fn from(v: u8) -> Self {
        match v & 0x0F {
            0 => Self::Query,
            1 => Self::IQuery,
            2 => Self::Status,
            4 => Self::Notify,
            5 => Self::Update,
            n => Self::Other(n),
        }
    }
}

impl From<Opcode> for u8 {
    fn from(op: Opcode) -> u8 {
        match op {
            Opcode::Query => 0,
            Opcode::IQuery => 1,
            Opcode::Status => 2,
            Opcode::Notify => 4,
            Opcode::Update => 5,
            Opcode::Other(n) => n & 0x0F,
        }
    }
}

// ── Rcode ─────────────────────────────────────────────────────────────────────

/// DNS response code field (4 bits, RFC 1035 §4.1.1 and RFC 2136).
///
/// All 16 representable values round-trip losslessly through [`From`]
/// conversions.  Unknown values are preserved via the `Other(u8)` variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rcode {
    /// No error (0).
    NoError,
    /// Format error (1) — the name server was unable to interpret the query.
    FormErr,
    /// Server failure (2) — the name server was unable to process this query.
    ServFail,
    /// Non-existent domain (3) — the domain name referenced does not exist.
    NxDomain,
    /// Not implemented (4) — the name server does not support the query type.
    NotImpl,
    /// Refused (5) — the name server refuses to perform the requested operation.
    Refused,
    /// Any other (reserved / extended) rcode value.
    Other(u8),
}

impl From<u8> for Rcode {
    fn from(v: u8) -> Self {
        match v & 0x0F {
            0 => Self::NoError,
            1 => Self::FormErr,
            2 => Self::ServFail,
            3 => Self::NxDomain,
            4 => Self::NotImpl,
            5 => Self::Refused,
            n => Self::Other(n),
        }
    }
}

impl From<Rcode> for u8 {
    fn from(rc: Rcode) -> u8 {
        match rc {
            Rcode::NoError => 0,
            Rcode::FormErr => 1,
            Rcode::ServFail => 2,
            Rcode::NxDomain => 3,
            Rcode::NotImpl => 4,
            Rcode::Refused => 5,
            Rcode::Other(n) => n & 0x0F,
        }
    }
}

// ── Header ────────────────────────────────────────────────────────────────────

/// The 12-byte DNS message header (RFC 1035 §4.1.1).
///
/// Flags are stored as a raw `u16` bitfield so that reserved/unknown bits are
/// preserved on round-trip without any information loss.  All public accessors
/// are typed — no raw bit manipulation is needed at call sites.
///
/// # Builder pattern
///
/// ```rust
/// use sagittarius::codec::header::{Header, Opcode, Rcode};
///
/// let hdr = Header::new(0x1234)
///     .with_qr(true)
///     .with_opcode(Opcode::Query)
///     .with_rd(true)
///     .with_ra(true)
///     .with_rcode(Rcode::NoError)
///     .with_qdcount(1);
/// assert!(hdr.qr());
/// assert_eq!(hdr.opcode(), Opcode::Query);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Transaction ID.
    pub id: u16,
    /// Raw 16-bit flags word (bytes 2-3 of the wire header).
    flags: u16,
    /// Question count (QDCOUNT).
    pub qdcount: u16,
    /// Answer record count (ANCOUNT).
    pub ancount: u16,
    /// Authority record count (NSCOUNT).
    pub nscount: u16,
    /// Additional record count (ARCOUNT).
    pub arcount: u16,
}

impl Header {
    // ── Bit-mask and shift constants (associated) ─────────────────────────────

    /// Bit mask for the QR flag (bit 15, MSB of the flags word).
    pub const FLAG_QR: u16 = 0x8000;
    /// Shift for the Opcode field (bits 14–11).
    pub const OPCODE_SHIFT: u16 = 11;
    /// Bit mask for the Opcode field (4 bits at positions 14–11).
    pub const FLAG_OPCODE: u16 = 0x7800;
    /// Bit mask for the AA (Authoritative Answer) flag (bit 10).
    pub const FLAG_AA: u16 = 0x0400;
    /// Bit mask for the TC (Truncated) flag (bit 9).
    pub const FLAG_TC: u16 = 0x0200;
    /// Bit mask for the RD (Recursion Desired) flag (bit 8).
    pub const FLAG_RD: u16 = 0x0100;
    /// Bit mask for the RA (Recursion Available) flag (bit 7).
    pub const FLAG_RA: u16 = 0x0080;
    /// Bit mask for the Z (reserved) bits (bits 6–4).
    pub const FLAG_Z: u16 = 0x0070;
    /// Shift for the Z reserved bits (bits 6–4).
    pub const Z_SHIFT: u16 = 4;
    /// Bit mask for the RCODE field (4 bits at positions 3–0).
    pub const FLAG_RCODE: u16 = 0x000F;

    // ── Constructors ──────────────────────────────────────────────────────────

    /// Create a new header with the given `id` and all flags/counts zeroed.
    #[must_use]
    pub fn new(id: u16) -> Self {
        Self {
            id,
            flags: 0,
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }

    /// Create a header from raw field values.  Useful when you already have
    /// the flags word from the wire.
    #[must_use]
    pub fn from_parts(
        id: u16,
        flags: u16,
        qdcount: u16,
        ancount: u16,
        nscount: u16,
        arcount: u16,
    ) -> Self {
        Self {
            id,
            flags,
            qdcount,
            ancount,
            nscount,
            arcount,
        }
    }

    /// Return the raw flags word (bytes 2–3 of the wire header).
    #[must_use]
    pub fn flags(&self) -> u16 {
        self.flags
    }

    // ── Flag accessors ────────────────────────────────────────────────────────

    /// Returns `true` if the QR bit is set (i.e. this is a response).
    #[must_use]
    pub fn qr(&self) -> bool {
        self.flags & Self::FLAG_QR != 0
    }

    /// Returns the [`Opcode`] decoded from the flags word.
    #[must_use]
    pub fn opcode(&self) -> Opcode {
        let raw = ((self.flags & Self::FLAG_OPCODE) >> Self::OPCODE_SHIFT) as u8;
        Opcode::from(raw)
    }

    /// Returns `true` if the AA (Authoritative Answer) bit is set.
    #[must_use]
    pub fn aa(&self) -> bool {
        self.flags & Self::FLAG_AA != 0
    }

    /// Returns `true` if the TC (Truncated) bit is set.
    #[must_use]
    pub fn tc(&self) -> bool {
        self.flags & Self::FLAG_TC != 0
    }

    /// Returns `true` if the RD (Recursion Desired) bit is set.
    #[must_use]
    pub fn rd(&self) -> bool {
        self.flags & Self::FLAG_RD != 0
    }

    /// Returns `true` if the RA (Recursion Available) bit is set.
    #[must_use]
    pub fn ra(&self) -> bool {
        self.flags & Self::FLAG_RA != 0
    }

    /// Returns the value of the reserved Z bits (bits 6–4 of the flags word).
    ///
    /// RFC 1035 mandates these are zero; we preserve them on round-trip.
    #[must_use]
    pub fn z(&self) -> u8 {
        ((self.flags & Self::FLAG_Z) >> Self::Z_SHIFT) as u8
    }

    /// Returns the [`Rcode`] decoded from the flags word.
    #[must_use]
    pub fn rcode(&self) -> Rcode {
        let raw = (self.flags & Self::FLAG_RCODE) as u8;
        Rcode::from(raw)
    }

    // ── In-place setters ──────────────────────────────────────────────────────

    /// Set or clear the QR bit.
    pub fn set_qr(&mut self, v: bool) {
        if v {
            self.flags |= Self::FLAG_QR;
        } else {
            self.flags &= !Self::FLAG_QR;
        }
    }

    /// Set the Opcode field.
    pub fn set_opcode(&mut self, op: Opcode) {
        let raw = u8::from(op) as u16;
        self.flags = (self.flags & !Self::FLAG_OPCODE) | (raw << Self::OPCODE_SHIFT);
    }

    /// Set or clear the AA (Authoritative Answer) bit.
    pub fn set_aa(&mut self, v: bool) {
        if v {
            self.flags |= Self::FLAG_AA;
        } else {
            self.flags &= !Self::FLAG_AA;
        }
    }

    /// Set or clear the TC (Truncated) bit.
    pub fn set_tc(&mut self, v: bool) {
        if v {
            self.flags |= Self::FLAG_TC;
        } else {
            self.flags &= !Self::FLAG_TC;
        }
    }

    /// Set or clear the RD (Recursion Desired) bit.
    pub fn set_rd(&mut self, v: bool) {
        if v {
            self.flags |= Self::FLAG_RD;
        } else {
            self.flags &= !Self::FLAG_RD;
        }
    }

    /// Set or clear the RA (Recursion Available) bit.
    pub fn set_ra(&mut self, v: bool) {
        if v {
            self.flags |= Self::FLAG_RA;
        } else {
            self.flags &= !Self::FLAG_RA;
        }
    }

    /// Set the reserved Z bits (3 bits; only the low 3 bits of `v` are used).
    pub fn set_z(&mut self, v: u8) {
        let raw = (v as u16 & 0x07) << Self::Z_SHIFT;
        self.flags = (self.flags & !Self::FLAG_Z) | raw;
    }

    /// Set the Rcode field.
    pub fn set_rcode(&mut self, rc: Rcode) {
        let raw = u8::from(rc) as u16;
        self.flags = (self.flags & !Self::FLAG_RCODE) | raw;
    }

    // ── Builder-style setters (consume and return Self) ───────────────────────

    /// Builder: set the QR bit.
    #[must_use]
    pub fn with_qr(mut self, v: bool) -> Self {
        self.set_qr(v);
        self
    }

    /// Builder: set the Opcode field.
    #[must_use]
    pub fn with_opcode(mut self, op: Opcode) -> Self {
        self.set_opcode(op);
        self
    }

    /// Builder: set the AA bit.
    #[must_use]
    pub fn with_aa(mut self, v: bool) -> Self {
        self.set_aa(v);
        self
    }

    /// Builder: set the TC bit.
    #[must_use]
    pub fn with_tc(mut self, v: bool) -> Self {
        self.set_tc(v);
        self
    }

    /// Builder: set the RD bit.
    #[must_use]
    pub fn with_rd(mut self, v: bool) -> Self {
        self.set_rd(v);
        self
    }

    /// Builder: set the RA bit.
    #[must_use]
    pub fn with_ra(mut self, v: bool) -> Self {
        self.set_ra(v);
        self
    }

    /// Builder: set the reserved Z bits.
    #[must_use]
    pub fn with_z(mut self, v: u8) -> Self {
        self.set_z(v);
        self
    }

    /// Builder: set the Rcode field.
    #[must_use]
    pub fn with_rcode(mut self, rc: Rcode) -> Self {
        self.set_rcode(rc);
        self
    }

    /// Builder: set QDCOUNT.
    #[must_use]
    pub fn with_qdcount(mut self, v: u16) -> Self {
        self.qdcount = v;
        self
    }

    /// Builder: set ANCOUNT.
    #[must_use]
    pub fn with_ancount(mut self, v: u16) -> Self {
        self.ancount = v;
        self
    }

    /// Builder: set NSCOUNT.
    #[must_use]
    pub fn with_nscount(mut self, v: u16) -> Self {
        self.nscount = v;
        self
    }

    /// Builder: set ARCOUNT.
    #[must_use]
    pub fn with_arcount(mut self, v: u16) -> Self {
        self.arcount = v;
        self
    }

    // ── Wire I/O ──────────────────────────────────────────────────────────────

    /// Read a [`Header`] from the next 12 bytes in `reader`.
    ///
    /// Consumes exactly 12 bytes.  If fewer than 12 bytes remain in the buffer
    /// the read is aborted and [`Error::MessageTooShort`] is returned; the
    /// reader's cursor is **not** advanced in that case.
    ///
    /// # Errors
    ///
    /// - [`Error::MessageTooShort`] — fewer than 12 bytes are available.
    pub fn read(reader: &mut Reader) -> Result<Self, Error> {
        if reader.remaining() < 12 {
            return Err(Error::MessageTooShort(reader.remaining()));
        }

        let id = reader.read_u16()?;
        let flags = reader.read_u16()?;
        let qdcount = reader.read_u16()?;
        let ancount = reader.read_u16()?;
        let nscount = reader.read_u16()?;
        let arcount = reader.read_u16()?;

        Ok(Self {
            id,
            flags,
            qdcount,
            ancount,
            nscount,
            arcount,
        })
    }

    /// Write this [`Header`] into `writer` as exactly 12 big-endian bytes.
    pub fn write(&self, writer: &mut Writer) {
        writer.write_u16(self.id);
        writer.write_u16(self.flags);
        writer.write_u16(self.qdcount);
        writer.write_u16(self.ancount);
        writer.write_u16(self.nscount);
        writer.write_u16(self.arcount);
    }
}

impl Default for Header {
    /// A zeroed header with `id = 0` and all flags and counts set to 0.
    fn default() -> Self {
        Self::new(0)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::codec::{reader::Reader, writer::Writer};

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Serialize `hdr` to bytes.
    fn serialize(hdr: &Header) -> Bytes {
        let mut w = Writer::with_capacity(12);
        hdr.write(&mut w);
        w.finish()
    }

    /// Deserialize a `Header` from a static byte slice.
    fn deserialize(bytes: &'static [u8]) -> Header {
        let mut r = Reader::from_static(bytes);
        Header::read(&mut r).unwrap()
    }

    // ── Opcode conversions ────────────────────────────────────────────────────

    #[test]
    fn opcode_known_round_trips() {
        for (op, expected) in [
            (Opcode::Query, 0u8),
            (Opcode::IQuery, 1),
            (Opcode::Status, 2),
            (Opcode::Notify, 4),
            (Opcode::Update, 5),
        ] {
            let raw: u8 = op.into();
            assert_eq!(raw, expected, "Opcode::{op:?} → u8 mismatch");
            let back = Opcode::from(raw);
            assert_eq!(back, op, "u8({expected}) → Opcode mismatch");
        }
    }

    #[test]
    fn opcode_unknown_preserved() {
        for n in [3u8, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15] {
            let op = Opcode::from(n);
            assert_eq!(op, Opcode::Other(n), "opcode {n} should be Other");
            let back: u8 = op.into();
            assert_eq!(back, n, "Other({n}) should round-trip to {n}");
        }
    }

    #[test]
    fn opcode_all_4bit_values_round_trip() {
        for n in 0u8..=15 {
            let op = Opcode::from(n);
            let back: u8 = op.into();
            assert_eq!(back, n, "opcode {n} did not round-trip");
        }
    }

    // ── Rcode conversions ─────────────────────────────────────────────────────

    #[test]
    fn rcode_known_round_trips() {
        for (rc, expected) in [
            (Rcode::NoError, 0u8),
            (Rcode::FormErr, 1),
            (Rcode::ServFail, 2),
            (Rcode::NxDomain, 3),
            (Rcode::NotImpl, 4),
            (Rcode::Refused, 5),
        ] {
            let raw: u8 = rc.into();
            assert_eq!(raw, expected, "Rcode::{rc:?} → u8 mismatch");
            let back = Rcode::from(raw);
            assert_eq!(back, rc, "u8({expected}) → Rcode mismatch");
        }
    }

    #[test]
    fn rcode_unknown_preserved() {
        for n in [6u8, 7, 8, 9, 10, 11, 12, 13, 14, 15] {
            let rc = Rcode::from(n);
            assert_eq!(rc, Rcode::Other(n), "rcode {n} should be Other");
            let back: u8 = rc.into();
            assert_eq!(back, n, "Other({n}) should round-trip to {n}");
        }
    }

    #[test]
    fn rcode_all_4bit_values_round_trip() {
        for n in 0u8..=15 {
            let rc = Rcode::from(n);
            let back: u8 = rc.into();
            assert_eq!(back, n, "rcode {n} did not round-trip");
        }
    }

    // ── Header construction ───────────────────────────────────────────────────

    #[test]
    fn default_header_is_zeroed() {
        let hdr = Header::default();
        assert_eq!(hdr.id, 0);
        assert_eq!(hdr.flags(), 0);
        assert_eq!(hdr.qdcount, 0);
        assert_eq!(hdr.ancount, 0);
        assert_eq!(hdr.nscount, 0);
        assert_eq!(hdr.arcount, 0);
    }

    #[test]
    fn new_header_zeroes_flags_and_counts() {
        let hdr = Header::new(0xABCD);
        assert_eq!(hdr.id, 0xABCD);
        assert!(!hdr.qr());
        assert!(!hdr.aa());
        assert!(!hdr.tc());
        assert!(!hdr.rd());
        assert!(!hdr.ra());
        assert_eq!(hdr.z(), 0);
        assert_eq!(hdr.opcode(), Opcode::Query);
        assert_eq!(hdr.rcode(), Rcode::NoError);
    }

    // ── Flag get/set correctness ──────────────────────────────────────────────

    #[test]
    fn qr_flag_set_and_clear() {
        let mut hdr = Header::new(1);
        assert!(!hdr.qr());
        hdr.set_qr(true);
        assert!(hdr.qr());
        hdr.set_qr(false);
        assert!(!hdr.qr());
    }

    #[test]
    fn aa_flag_set_and_clear() {
        let mut hdr = Header::new(1);
        hdr.set_aa(true);
        assert!(hdr.aa());
        hdr.set_aa(false);
        assert!(!hdr.aa());
    }

    #[test]
    fn tc_flag_set_and_clear() {
        let mut hdr = Header::new(1);
        hdr.set_tc(true);
        assert!(hdr.tc());
        hdr.set_tc(false);
        assert!(!hdr.tc());
    }

    #[test]
    fn rd_flag_set_and_clear() {
        let mut hdr = Header::new(1);
        hdr.set_rd(true);
        assert!(hdr.rd());
        hdr.set_rd(false);
        assert!(!hdr.rd());
    }

    #[test]
    fn ra_flag_set_and_clear() {
        let mut hdr = Header::new(1);
        hdr.set_ra(true);
        assert!(hdr.ra());
        hdr.set_ra(false);
        assert!(!hdr.ra());
    }

    #[test]
    fn opcode_field_set_and_get() {
        let mut hdr = Header::new(1);
        for op in [
            Opcode::Query,
            Opcode::IQuery,
            Opcode::Status,
            Opcode::Notify,
            Opcode::Update,
        ] {
            hdr.set_opcode(op);
            assert_eq!(hdr.opcode(), op, "opcode {op:?} not round-tripped via set");
        }
    }

    #[test]
    fn rcode_field_set_and_get() {
        let mut hdr = Header::new(1);
        for rc in [
            Rcode::NoError,
            Rcode::FormErr,
            Rcode::ServFail,
            Rcode::NxDomain,
            Rcode::NotImpl,
            Rcode::Refused,
        ] {
            hdr.set_rcode(rc);
            assert_eq!(hdr.rcode(), rc, "rcode {rc:?} not round-tripped via set");
        }
    }

    #[test]
    fn z_bits_set_and_get() {
        let mut hdr = Header::new(1);
        for z in 0u8..=7 {
            hdr.set_z(z);
            assert_eq!(hdr.z(), z, "z={z} not round-tripped");
        }
    }

    #[test]
    fn flags_are_independent() {
        // Setting one flag must not disturb another.
        let mut hdr = Header::new(0);
        hdr.set_qr(true);
        hdr.set_rd(true);
        hdr.set_ra(true);
        hdr.set_opcode(Opcode::Query);
        hdr.set_rcode(Rcode::NxDomain);

        assert!(hdr.qr(), "QR should be set");
        assert!(hdr.rd(), "RD should be set");
        assert!(hdr.ra(), "RA should be set");
        assert!(!hdr.aa(), "AA should be clear");
        assert!(!hdr.tc(), "TC should be clear");
        assert_eq!(hdr.opcode(), Opcode::Query);
        assert_eq!(hdr.rcode(), Rcode::NxDomain);
    }

    // ── Exact flag byte values (hand-computed) ────────────────────────────────

    /// Build a standard response header and verify exact byte values for the
    /// flags word.
    ///
    /// Setup: QR=1, Opcode=Query(0), AA=0, TC=0, RD=1 → byte 2 = 0b1_0000_0_0_1 = 0x81
    ///        RA=1, Z=0, RCODE=NxDomain(3)            → byte 3 = 0b1_000_0011    = 0x83
    ///        flags word = 0x8183
    #[test]
    fn exact_flag_bytes_response_nxdomain() {
        let hdr = Header::new(0x1234)
            .with_qr(true)
            .with_opcode(Opcode::Query)
            .with_rd(true)
            .with_ra(true)
            .with_rcode(Rcode::NxDomain);

        let flags = hdr.flags();
        // Byte 2 (high byte of flags): QR=1, Opcode=0000, AA=0, TC=0, RD=1 → 0x81
        assert_eq!(
            (flags >> 8) as u8,
            0x81,
            "flags byte 2 (high byte) mismatch: got {:#04x}",
            (flags >> 8) as u8
        );
        // Byte 3 (low byte of flags): RA=1, Z=000, RCODE=0011 → 0x83
        assert_eq!(
            (flags & 0xFF) as u8,
            0x83,
            "flags byte 3 (low byte) mismatch: got {:#04x}",
            (flags & 0xFF) as u8
        );
        assert_eq!(flags, 0x8183);
    }

    /// QR=1, Opcode=Update(5), AA=1, TC=0, RD=0 → byte 2 = 0b1_0101_1_0_0 = 0xAC
    /// RA=0, Z=0, RCODE=Refused(5)              → byte 3 = 0b0_000_0101 = 0x05
    /// flags word = 0xAC05
    #[test]
    fn exact_flag_bytes_update_refused() {
        let hdr = Header::new(0)
            .with_qr(true)
            .with_opcode(Opcode::Update)
            .with_aa(true)
            .with_rcode(Rcode::Refused);

        let flags = hdr.flags();
        assert_eq!(
            (flags >> 8) as u8,
            0xAC,
            "byte 2 mismatch: got {:#04x}",
            (flags >> 8) as u8
        );
        assert_eq!(
            (flags & 0xFF) as u8,
            0x05,
            "byte 3 mismatch: got {:#04x}",
            (flags & 0xFF) as u8
        );
        assert_eq!(flags, 0xAC05);
    }

    // ── Wire read/write ───────────────────────────────────────────────────────

    #[test]
    fn write_produces_exactly_12_bytes() {
        let hdr = Header::new(0);
        assert_eq!(serialize(&hdr).len(), 12);
    }

    #[test]
    fn write_id_at_bytes_0_1() {
        let hdr = Header::new(0xBEEF);
        let b = serialize(&hdr);
        assert_eq!(b[0], 0xBE);
        assert_eq!(b[1], 0xEF);
    }

    #[test]
    fn write_qdcount_at_bytes_4_5() {
        let hdr = Header::new(0).with_qdcount(1);
        let b = serialize(&hdr);
        assert_eq!(b[4], 0x00);
        assert_eq!(b[5], 0x01);
    }

    #[test]
    fn write_ancount_at_bytes_6_7() {
        let hdr = Header::new(0).with_ancount(2);
        let b = serialize(&hdr);
        assert_eq!(b[6], 0x00);
        assert_eq!(b[7], 0x02);
    }

    #[test]
    fn write_nscount_at_bytes_8_9() {
        let hdr = Header::new(0).with_nscount(3);
        let b = serialize(&hdr);
        assert_eq!(b[8], 0x00);
        assert_eq!(b[9], 0x03);
    }

    #[test]
    fn write_arcount_at_bytes_10_11() {
        let hdr = Header::new(0).with_arcount(4);
        let b = serialize(&hdr);
        assert_eq!(b[10], 0x00);
        assert_eq!(b[11], 0x04);
    }

    #[test]
    fn count_fields_correct_offsets() {
        let hdr = Header::new(0)
            .with_qdcount(1)
            .with_ancount(2)
            .with_nscount(3)
            .with_arcount(4);
        let b = serialize(&hdr);
        assert_eq!(u16::from_be_bytes([b[4], b[5]]), 1, "QDCOUNT");
        assert_eq!(u16::from_be_bytes([b[6], b[7]]), 2, "ANCOUNT");
        assert_eq!(u16::from_be_bytes([b[8], b[9]]), 3, "NSCOUNT");
        assert_eq!(u16::from_be_bytes([b[10], b[11]]), 4, "ARCOUNT");
    }

    // ── Round-trip tests ──────────────────────────────────────────────────────

    #[test]
    fn bit_exact_round_trip_from_raw_bytes() {
        // Hand-crafted 12-byte DNS response.
        // ID=0xABCD, flags=0x8180 (QR=1,RD=1,RA=1),
        // QDCOUNT=1, ANCOUNT=1, NSCOUNT=0, ARCOUNT=0
        let raw: &'static [u8] = &[
            0xAB, 0xCD, // ID
            0x81, 0x80, // flags: QR=1, Opcode=0, AA=0, TC=0, RD=1, RA=1, Z=0, RCODE=0
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x01, // ANCOUNT=1
            0x00, 0x00, // NSCOUNT=0
            0x00, 0x00, // ARCOUNT=0
        ];
        let hdr = deserialize(raw);
        let written = serialize(&hdr);
        assert_eq!(
            &written[..],
            raw,
            "read→write did not reproduce original bytes"
        );
    }

    #[test]
    fn build_write_read_round_trip() {
        let original = Header::new(0x5555)
            .with_qr(true)
            .with_opcode(Opcode::Query)
            .with_rd(true)
            .with_ra(true)
            .with_rcode(Rcode::NoError)
            .with_qdcount(1)
            .with_ancount(3)
            .with_nscount(0)
            .with_arcount(1);

        let bytes = serialize(&original);
        let mut r = Reader::new(bytes);
        let decoded = Header::read(&mut r).unwrap();

        assert_eq!(decoded.id, original.id);
        assert_eq!(decoded.qr(), original.qr());
        assert_eq!(decoded.opcode(), original.opcode());
        assert_eq!(decoded.rd(), original.rd());
        assert_eq!(decoded.ra(), original.ra());
        assert_eq!(decoded.rcode(), original.rcode());
        assert_eq!(decoded.qdcount, original.qdcount);
        assert_eq!(decoded.ancount, original.ancount);
        assert_eq!(decoded.nscount, original.nscount);
        assert_eq!(decoded.arcount, original.arcount);
    }

    #[test]
    fn round_trip_response_nxdomain() {
        let original = Header::new(0x1234)
            .with_qr(true)
            .with_opcode(Opcode::Query)
            .with_rd(true)
            .with_ra(true)
            .with_rcode(Rcode::NxDomain)
            .with_qdcount(1);

        let bytes = serialize(&original);
        let mut r = Reader::new(bytes);
        let decoded = Header::read(&mut r).unwrap();

        assert!(decoded.qr(), "QR");
        assert_eq!(decoded.opcode(), Opcode::Query, "Opcode");
        assert!(decoded.rd(), "RD");
        assert!(decoded.ra(), "RA");
        assert_eq!(decoded.rcode(), Rcode::NxDomain, "RCODE");
        assert_eq!(decoded.qdcount, 1, "QDCOUNT");
    }

    // ── Z bits and unknown opcode/rcode round-trip ────────────────────────────

    #[test]
    fn z_bits_preserved_on_round_trip() {
        // Build a flags word with Z=0b101 (5) and verify round-trip.
        let hdr = Header::new(42).with_z(0b101);
        assert_eq!(hdr.z(), 5);
        let bytes = serialize(&hdr);
        let mut r = Reader::new(bytes);
        let decoded = Header::read(&mut r).unwrap();
        assert_eq!(
            decoded.z(),
            5,
            "Z bits not preserved through wire round-trip"
        );
    }

    #[test]
    fn unknown_opcode_round_trips_through_wire() {
        // Opcode=13 is currently unassigned; must survive the round-trip.
        let hdr = Header::new(1).with_opcode(Opcode::Other(13));
        assert_eq!(hdr.opcode(), Opcode::Other(13));
        let bytes = serialize(&hdr);
        let mut r = Reader::new(bytes);
        let decoded = Header::read(&mut r).unwrap();
        assert_eq!(decoded.opcode(), Opcode::Other(13));
    }

    #[test]
    fn unknown_rcode_round_trips_through_wire() {
        // RCODE=9 is unassigned; must survive.
        let hdr = Header::new(2).with_rcode(Rcode::Other(9));
        assert_eq!(hdr.rcode(), Rcode::Other(9));
        let bytes = serialize(&hdr);
        let mut r = Reader::new(bytes);
        let decoded = Header::read(&mut r).unwrap();
        assert_eq!(decoded.rcode(), Rcode::Other(9));
    }

    #[test]
    fn raw_flags_word_with_all_z_bits_set_round_trips() {
        // Construct flags word with Z=0b111 (all three reserved bits set).
        let hdr = Header::from_parts(0, 0x0070, 0, 0, 0, 0);
        assert_eq!(hdr.z(), 7);
        let bytes = serialize(&hdr);
        let mut r = Reader::new(bytes);
        let decoded = Header::read(&mut r).unwrap();
        assert_eq!(decoded.flags(), 0x0070, "raw flags not preserved");
        assert_eq!(decoded.z(), 7);
    }

    // ── Short-buffer error ────────────────────────────────────────────────────

    #[test]
    fn short_buffer_returns_message_too_short() {
        for n in 0..12usize {
            let buf: Vec<u8> = vec![0xFF; n];
            let mut r = Reader::new(Bytes::from(buf));
            let err = Header::read(&mut r).unwrap_err();
            assert!(
                matches!(err, Error::MessageTooShort(avail) if avail == n),
                "expected MessageTooShort({n}), got: {err}"
            );
        }
    }

    #[test]
    fn short_buffer_does_not_panic() {
        let mut r = Reader::new(Bytes::from_static(&[]));
        assert!(Header::read(&mut r).is_err());
    }

    #[test]
    fn short_buffer_cursor_not_advanced_on_error() {
        let buf = Bytes::from(vec![0u8; 5]);
        let mut r = Reader::new(buf);
        let _ = Header::read(&mut r);
        // The reader's cursor must remain at 0 (no partial advance).
        assert_eq!(r.position(), 0, "cursor advanced on error");
    }

    // ── Reader cursor position after successful read ───────────────────────────

    #[test]
    fn read_advances_cursor_by_12() {
        let mut data = vec![0u8; 12];
        data.push(0xAB); // sentinel byte after header
        let mut r = Reader::new(Bytes::from(data));
        Header::read(&mut r).unwrap();
        assert_eq!(r.position(), 12);
        // Sentinel is still readable.
        assert_eq!(r.read_u8().unwrap(), 0xAB);
    }

    // ── Builder pattern ───────────────────────────────────────────────────────

    #[test]
    fn builder_chain_sets_all_fields() {
        let hdr = Header::new(0x9999)
            .with_qr(true)
            .with_opcode(Opcode::Status)
            .with_aa(true)
            .with_tc(true)
            .with_rd(true)
            .with_ra(true)
            .with_z(3)
            .with_rcode(Rcode::ServFail)
            .with_qdcount(1)
            .with_ancount(2)
            .with_nscount(3)
            .with_arcount(4);

        assert_eq!(hdr.id, 0x9999);
        assert!(hdr.qr());
        assert_eq!(hdr.opcode(), Opcode::Status);
        assert!(hdr.aa());
        assert!(hdr.tc());
        assert!(hdr.rd());
        assert!(hdr.ra());
        assert_eq!(hdr.z(), 3);
        assert_eq!(hdr.rcode(), Rcode::ServFail);
        assert_eq!(hdr.qdcount, 1);
        assert_eq!(hdr.ancount, 2);
        assert_eq!(hdr.nscount, 3);
        assert_eq!(hdr.arcount, 4);
    }
}
