//! Bounded TTL scan for DNS response messages.
//!
//! This module implements a forward-only single walk of the RR sections of a
//! DNS response to find the **minimum TTL** and record each real (non-OPT) RR's
//! TTL field byte offset, enabling in-place TTL patching when serving from the
//! raw-bytes cache (SPEC §8).
//!
//! # Walk overview
//!
//! 1. Read the 12-byte [`Header`] (QDCOUNT / ANCOUNT / NSCOUNT / ARCOUNT).
//! 2. Skip `QDCOUNT` questions — each is an owner name + 2-byte QTYPE +
//!    2-byte QCLASS.  [`Name::skip_rr`] handles the name safely.
//! 3. Walk `ANCOUNT + NSCOUNT + ARCOUNT` resource records in order:
//!    - Skip the owner name with [`Name::skip_rr`].
//!    - Read TYPE (u16) and CLASS (u16).  The cursor position **here** is the
//!      absolute offset of this RR's TTL field.
//!    - Read TTL (u32) and RDLENGTH (u16), then skip RDLENGTH bytes of RDATA.
//!    - OPT pseudo-RRs (TYPE == 41, RFC 6891) are parsed/skipped but excluded
//!      from both `min_ttl` and `ttl_offsets`.
//!
//! # Bounding / safety
//!
//! - [`Name::skip_rr`] is internally capped (hop count + total label bytes);
//!   any malformed name terminates with an error.
//! - A truncated RDLENGTH (`read_slice` past end) returns [`Error::UnexpectedEof`].
//! - Progress is strictly monotonic: each RR advances the cursor by at least
//!   10 bytes (TYPE + CLASS + TTL + RDLENGTH) plus any RDATA, so the walk
//!   cannot hang even on adversarially large counts.
//! - For any input the scan returns either a [`TtlScan`] or a [`codec::Error`]
//!   in bounded time; it **never panics**.
//!
//! # OPT exclusion
//!
//! OPT records (TYPE 41) carry EDNS metadata — extended RCODE, version, and
//! flags — in the field that looks like a TTL.  They are excluded from the
//! minimum-TTL computation and from `ttl_offsets` by checking the type value
//! against [`OPT_TYPE`] before recording or comparing the TTL.

use bytes::Bytes;

use crate::codec::{Error, header::Header, name::Name, reader::Reader};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Wire-format type code for the OPT pseudo-RR (RFC 6891 §6.1.1).
///
/// OPT records carry EDNS metadata; their "TTL" field is not a cache TTL and
/// must be excluded from [`TtlScan`] results.
pub const OPT_TYPE: u16 = 41;

// ── TtlScan ───────────────────────────────────────────────────────────────────

/// Result of scanning all RR sections of a DNS response for TTL fields.
///
/// Used by the raw-bytes cache (SPEC §8) to decrement TTLs in-place before
/// serving a cached response.
///
/// # OPT exclusion
///
/// OPT pseudo-RRs (TYPE 41, RFC 6891) are parsed and skipped during the walk
/// but are **not** included in `min_ttl` or `ttl_offsets`.
///
/// # No-RR case
///
/// When the message contains no real (non-OPT) TTL-bearing RRs (e.g. a response
/// with only an OPT record, or one with `ANCOUNT = NSCOUNT = ARCOUNT = 0`),
/// `min_ttl` is `None` and `ttl_offsets` is empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TtlScan {
    /// Minimum TTL across all real (non-OPT) RRs in the answer, authority,
    /// and additional sections.  `None` if there were no such records.
    pub min_ttl: Option<u32>,

    /// Absolute byte offsets (into the original message `Bytes`) of each real
    /// (non-OPT) RR's TTL field.  Each offset is the position of the first
    /// (most-significant) byte of the 4-byte big-endian TTL field.
    ///
    /// The cache patches these bytes in-place to decrement the TTL by the time
    /// elapsed since the response was stored.
    pub ttl_offsets: Vec<usize>,
}

impl TtlScan {
    /// Scan a DNS response `message` and return a [`TtlScan`].
    ///
    /// Constructs an internal [`Reader`] over the full message (required so
    /// that [`Name::skip_rr`] can follow compression pointers back into the
    /// header and question section) and walks all three RR sections.
    ///
    /// # Errors
    ///
    /// Returns a [`codec::Error`] if the message is malformed for scanning
    /// (truncated header, truncated question, truncated RR fixed fields, or
    /// truncated RDATA).  The caller — typically the cache-store path — should
    /// treat an error as "do not cache this response".
    ///
    /// # Never panics
    ///
    /// The scan is fully bounds-checked; all reads go through the [`Reader`]
    /// or [`Name::skip_rr`] helpers which return errors rather than panicking.
    pub fn scan(message: &Bytes) -> Result<Self, Error> {
        let mut reader = Reader::new(message.clone());

        // ── 1. Header ─────────────────────────────────────────────────────────
        let header = Header::read(&mut reader)?;

        // ── 2. Skip question section ─────────────────────────────────────────
        // Each question: owner name + 2-byte QTYPE + 2-byte QCLASS.
        for _ in 0..header.qdcount {
            Name::skip_rr(&mut reader)?;
            reader.read_u16()?; // QTYPE
            reader.read_u16()?; // QCLASS
        }

        // ── 3. Walk answer + authority + additional sections ──────────────────
        // Sum as usize to avoid u16 overflow (max: 3 * 65535 = 196605 RRs).
        let rr_count = header.ancount as usize + header.nscount as usize + header.arcount as usize;

        let mut min_ttl: Option<u32> = None;
        let mut ttl_offsets: Vec<usize> = Vec::with_capacity(rr_count.min(64));

        for _ in 0..rr_count {
            // Owner name (may be a compression pointer back into the message).
            Name::skip_rr(&mut reader)?;

            // TYPE and CLASS (2 bytes each).
            let rr_type = reader.read_u16()?;
            let _class = reader.read_u16()?;

            // Record the absolute offset of the TTL field (just here).
            let ttl_offset = reader.position();

            // TTL (4 bytes).
            let ttl = reader.read_u32()?;

            // RDLENGTH (2 bytes) + RDATA (RDLENGTH bytes).
            let rdlength = reader.read_u16()? as usize;
            reader.read_slice(rdlength)?;

            // OPT records carry EDNS metadata, not a cache TTL — exclude them.
            if rr_type == OPT_TYPE {
                continue;
            }

            // Record TTL offset and update minimum.
            ttl_offsets.push(ttl_offset);
            min_ttl = Some(match min_ttl {
                None => ttl,
                Some(prev) => prev.min(ttl),
            });
        }

        Ok(Self {
            min_ttl,
            ttl_offsets,
        })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use bytes::{Bytes, BytesMut};

    use super::*;
    use crate::codec::{
        header::{Header, Rcode},
        name::Name,
        reader::Reader,
        writer::Writer,
    };

    // ── Test helpers ──────────────────────────────────────────────────────────

    /// Write a DNS name into a [`Writer`] using wire format.
    fn write_name(w: &mut Writer, name: &str) {
        let n: Name = name.parse().expect("test helper: valid name");
        n.write(w);
    }

    /// Write a compression pointer (2 bytes) into a [`Writer`].
    ///
    /// `target` is the absolute byte offset in the message the pointer points to.
    fn write_ptr(w: &mut Writer, target: u16) {
        w.write_u8(0xC0 | ((target >> 8) as u8));
        w.write_u8((target & 0xFF) as u8);
    }

    /// Write a complete A-record RR into `w`.
    ///
    /// - Owner name: written inline (no compression).
    /// - TYPE A (1), CLASS IN (1), TTL as given, RDLENGTH = 4.
    /// - RDATA: 4 bytes of `rdata_byte` repeated.
    ///
    /// Returns the absolute offset (within the full buffer at time of call, i.e.
    /// `w.len()` *before* the TYPE field is written) of the TTL field.  The
    /// caller must add the offset of the start of this RR within the final
    /// message to get the absolute TTL offset in the final `Bytes`; this helper
    /// just indicates the relative distance from the start of the RR's name.
    ///
    /// Because computing absolute offsets during construction is cleaner, we
    /// capture `w.len()` at the right moment and return it.
    fn write_a_record(w: &mut Writer, owner: &str, ttl: u32, rdata_byte: u8) -> usize {
        write_name(w, owner);
        w.write_u16(1); // TYPE A
        w.write_u16(1); // CLASS IN
        let ttl_offset = w.len(); // absolute TTL offset
        w.write_u32(ttl);
        w.write_u16(4); // RDLENGTH
        w.write_slice(&[rdata_byte; 4]);
        ttl_offset
    }

    /// Write a complete SOA-record RR into `w`.
    ///
    /// Returns the absolute TTL offset within the writer's buffer at write time.
    fn write_soa_record(w: &mut Writer, owner: &str, ttl: u32) -> usize {
        write_name(w, owner);
        w.write_u16(6); // TYPE SOA
        w.write_u16(1); // CLASS IN
        let ttl_offset = w.len();
        w.write_u32(ttl);
        // Minimal SOA RDATA: mname + rname + serial + refresh + retry + expire + minimum
        // Use root names (0x00) for mname and rname to keep the fixture small.
        let mut rdata = Vec::new();
        rdata.push(0x00); // mname = root
        rdata.push(0x00); // rname = root
        rdata.extend_from_slice(&[0, 0, 0, 1]); // serial  = 1
        rdata.extend_from_slice(&[0, 0, 0, 2]); // refresh = 2
        rdata.extend_from_slice(&[0, 0, 0, 3]); // retry   = 3
        rdata.extend_from_slice(&[0, 0, 0, 4]); // expire  = 4
        rdata.extend_from_slice(&[0, 0, 0, 5]); // minimum = 5
        w.write_u16(rdata.len() as u16);
        w.write_slice(&rdata);
        ttl_offset
    }

    /// Write an OPT pseudo-RR (RFC 6891).
    ///
    /// - Owner name: root (single 0x00 byte).
    /// - TYPE OPT (41), CLASS = udp_payload_size.
    /// - "TTL" = extended RCODE / version / flags (all zeros here).
    /// - RDLENGTH = 0 (no EDNS options).
    fn write_opt_record(w: &mut Writer, udp_payload_size: u16) {
        w.write_u8(0x00); // root name
        w.write_u16(OPT_TYPE); // TYPE OPT = 41
        w.write_u16(udp_payload_size); // CLASS = UDP payload size
        w.write_u32(0); // extended RCODE / version / flags
        w.write_u16(0); // RDLENGTH
    }

    /// Build a complete response datagram: header + question + RR sections.
    ///
    /// The closure `build_rrs` receives a mutable [`Writer`] positioned after
    /// the question section and should append all desired RRs.  It also
    /// receives a reference to the absolute length of the question section's
    /// end (= header length) to help callers compute absolute TTL offsets.
    fn build_response<F>(
        ancount: u16,
        nscount: u16,
        arcount: u16,
        question_name: &str,
        build_rrs: F,
    ) -> Bytes
    where
        F: FnOnce(&mut Writer),
    {
        let mut w = Writer::with_capacity(256);
        Header::new(0xABCD)
            .with_qr(true)
            .with_rcode(Rcode::NoError)
            .with_qdcount(1)
            .with_ancount(ancount)
            .with_nscount(nscount)
            .with_arcount(arcount)
            .write(&mut w);
        // Question: name + QTYPE A (1) + QCLASS IN (1).
        write_name(&mut w, question_name);
        w.write_u16(1); // QTYPE A
        w.write_u16(1); // QCLASS IN
        build_rrs(&mut w);
        w.finish()
    }

    /// Read a big-endian u32 at an absolute offset from a `Bytes` buffer.
    fn read_u32_at(msg: &Bytes, offset: usize) -> u32 {
        let mut r = Reader::new(msg.clone());
        r.read_slice(offset).unwrap();
        r.read_u32().unwrap()
    }

    // ── Basic scan: multi-RR response ─────────────────────────────────────────

    /// A response with 3 A records at TTLs 300, 60, 180; expected min = 60.
    #[test]
    fn multi_rr_min_ttl_and_offset_count() {
        let msg = build_response(3, 0, 0, "example.com", |w| {
            write_a_record(w, "example.com", 300, 0x01);
            write_a_record(w, "example.com", 60, 0x02);
            write_a_record(w, "example.com", 180, 0x03);
        });

        let scan = TtlScan::scan(&msg).expect("scan must succeed");

        assert_eq!(scan.min_ttl, Some(60), "min_ttl should be 60");
        assert_eq!(scan.ttl_offsets.len(), 3, "should have 3 TTL offsets");
    }

    /// For each recorded offset, confirm the u32 at that offset is the RR's TTL.
    #[test]
    fn offsets_point_at_correct_ttl_bytes() {
        let ttls = [300u32, 60, 180];
        let msg = build_response(3, 0, 0, "example.com", |w| {
            write_a_record(w, "example.com", ttls[0], 0x01);
            write_a_record(w, "example.com", ttls[1], 0x02);
            write_a_record(w, "example.com", ttls[2], 0x03);
        });

        let scan = TtlScan::scan(&msg).expect("scan must succeed");

        assert_eq!(scan.ttl_offsets.len(), 3);
        for (i, (&offset, &expected_ttl)) in scan.ttl_offsets.iter().zip(ttls.iter()).enumerate() {
            let actual = read_u32_at(&msg, offset);
            assert_eq!(
                actual, expected_ttl,
                "offset[{i}]={offset}: expected TTL {expected_ttl}, got {actual}"
            );
        }
    }

    /// Mix: 2 A records in answer + 1 SOA in authority; min across all three.
    #[test]
    fn answer_and_authority_sections_scanned() {
        let msg = build_response(2, 1, 0, "example.com", |w| {
            write_a_record(w, "example.com", 120, 0x01);
            write_a_record(w, "example.com", 240, 0x02);
            write_soa_record(w, "example.com", 30);
        });

        let scan = TtlScan::scan(&msg).expect("scan must succeed");

        assert_eq!(scan.min_ttl, Some(30), "SOA TTL should be the minimum");
        assert_eq!(scan.ttl_offsets.len(), 3);

        // Verify all offsets.
        let expected_ttls = [120u32, 240, 30];
        for (&offset, &exp) in scan.ttl_offsets.iter().zip(expected_ttls.iter()) {
            assert_eq!(read_u32_at(&msg, offset), exp);
        }
    }

    // ── Patch test ────────────────────────────────────────────────────────────

    /// Decrement each TTL in-place, re-read, confirm values and structural validity.
    #[test]
    fn patch_decrements_ttls_in_place() {
        let ttls = [300u32, 60, 180];
        let msg = build_response(3, 0, 0, "example.com", |w| {
            write_a_record(w, "example.com", ttls[0], 0x01);
            write_a_record(w, "example.com", ttls[1], 0x02);
            write_a_record(w, "example.com", ttls[2], 0x03);
        });

        let scan = TtlScan::scan(&msg).expect("scan must succeed");

        // Make a mutable copy.
        let mut patched: BytesMut = BytesMut::from(msg.as_ref());

        const ELAPSED: u32 = 30;

        for &offset in &scan.ttl_offsets {
            let old = u32::from_be_bytes([
                patched[offset],
                patched[offset + 1],
                patched[offset + 2],
                patched[offset + 3],
            ]);
            let new_ttl = old.saturating_sub(ELAPSED);
            let bytes = new_ttl.to_be_bytes();
            patched[offset] = bytes[0];
            patched[offset + 1] = bytes[1];
            patched[offset + 2] = bytes[2];
            patched[offset + 3] = bytes[3];
        }

        // Re-scan the patched message — must still succeed.
        let patched_bytes = patched.freeze();
        let patched_scan = TtlScan::scan(&patched_bytes).expect("patched scan must succeed");

        // Verify decremented values.
        for (&offset, &original_ttl) in scan.ttl_offsets.iter().zip(ttls.iter()) {
            let expected = original_ttl.saturating_sub(ELAPSED);
            let actual = read_u32_at(&patched_bytes, offset);
            assert_eq!(
                actual, expected,
                "offset {offset}: expected {expected}, got {actual}"
            );
        }

        // min_ttl of patched should be min(270, 30, 150) = 30.
        assert_eq!(patched_scan.min_ttl, Some(30));
        assert_eq!(patched_scan.ttl_offsets.len(), 3);
    }

    // ── OPT-only response ─────────────────────────────────────────────────────

    #[test]
    fn opt_only_response_gives_none_min_ttl() {
        // Response with no answers, only an OPT in additional.
        let msg = build_response(0, 0, 1, "example.com", |w| {
            write_opt_record(w, 4096);
        });

        let scan = TtlScan::scan(&msg).expect("scan must succeed");

        assert_eq!(scan.min_ttl, None, "OPT-only: min_ttl must be None");
        assert!(
            scan.ttl_offsets.is_empty(),
            "OPT-only: ttl_offsets must be empty"
        );
    }

    #[test]
    fn zero_rr_sections_gives_none_min_ttl() {
        // Response with ANCOUNT=NSCOUNT=ARCOUNT=0.
        let msg = build_response(0, 0, 0, "example.com", |_| {});

        let scan = TtlScan::scan(&msg).expect("scan must succeed");

        assert_eq!(scan.min_ttl, None);
        assert!(scan.ttl_offsets.is_empty());
    }

    // ── A record + OPT in additional ─────────────────────────────────────────

    #[test]
    fn a_record_plus_opt_excludes_opt_from_offsets() {
        let a_ttl = 120u32;
        let msg = build_response(1, 0, 1, "example.com", |w| {
            write_a_record(w, "example.com", a_ttl, 0x7F);
            write_opt_record(w, 4096);
        });

        let scan = TtlScan::scan(&msg).expect("scan must succeed");

        // Only the A record's TTL should be recorded.
        assert_eq!(
            scan.min_ttl,
            Some(a_ttl),
            "min_ttl should equal A record TTL"
        );
        assert_eq!(
            scan.ttl_offsets.len(),
            1,
            "exactly one offset (the A record)"
        );

        // Confirm the single offset actually points at the A record's TTL.
        let actual = read_u32_at(&msg, scan.ttl_offsets[0]);
        assert_eq!(actual, a_ttl);
    }

    // ── Compression pointer in owner name ────────────────────────────────────

    /// The owner name of the answer RR is a pointer back to the question name.
    #[test]
    fn compression_pointer_owner_name_ttl_offset_correct() {
        // We build the message manually so we can insert a compression pointer.
        let mut w = Writer::with_capacity(128);
        // Header: 1 question, 1 answer.
        Header::new(0x1234)
            .with_qr(true)
            .with_qdcount(1)
            .with_ancount(1)
            .write(&mut w);
        // Question at offset 12: "example.com" + QTYPE A + QCLASS IN.
        write_name(&mut w, "example.com");
        w.write_u16(1); // QTYPE A
        w.write_u16(1); // QCLASS IN
        // Answer: owner = pointer to offset 12 (the question name).
        let question_name_offset: u16 = 12;
        write_ptr(&mut w, question_name_offset);
        w.write_u16(1); // TYPE A
        w.write_u16(1); // CLASS IN
        let ttl_offset = w.len(); // absolute TTL offset in the final message
        let expected_ttl: u32 = 300;
        w.write_u32(expected_ttl);
        w.write_u16(4); // RDLENGTH
        w.write_slice(&[1, 2, 3, 4]); // RDATA
        let msg = w.finish();

        let scan = TtlScan::scan(&msg).expect("scan must succeed");

        assert_eq!(scan.min_ttl, Some(expected_ttl));
        assert_eq!(scan.ttl_offsets.len(), 1);
        assert_eq!(
            scan.ttl_offsets[0], ttl_offset,
            "TTL offset must match the manually computed offset"
        );
        // Cross-check: reading at the recorded offset yields the correct TTL.
        assert_eq!(read_u32_at(&msg, scan.ttl_offsets[0]), expected_ttl);
    }

    // ── Error / safety cases ──────────────────────────────────────────────────

    /// A crafted pointer loop in an owner name → returns Error, never hangs.
    #[test]
    fn pointer_loop_in_owner_name_returns_error() {
        // Build a response where the answer RR's owner name points to a
        // location that itself is a pointer pointing back to the first pointer
        // (a two-pointer cycle).
        //
        // Layout:
        //   0..12  — header (ANCOUNT=1)
        //   12..   — question: "\x07example\x03com\x00" + QTYPE + QCLASS
        //   after question — answer owner: \xC0\xYY (pointer to loop_start)
        //
        // We place a self-referential pointer at a known offset by writing
        // a pointer from the answer owner to a byte within the answer itself.
        // Specifically: answer starts at byte A; owner = \xC0 A (points to A
        // itself), which the skip-rr code must reject as a forward/self pointer.
        let mut w = Writer::with_capacity(128);
        Header::new(0xBEEF)
            .with_qr(true)
            .with_qdcount(1)
            .with_ancount(1)
            .write(&mut w);
        // Question at offset 12.
        write_name(&mut w, "example.com");
        w.write_u16(1);
        w.write_u16(1);
        // Answer owner: self-pointer (forward pointer to current position → rejected).
        let self_offset = w.len() as u16;
        write_ptr(&mut w, self_offset);
        // Rest of the RR (will not be reached).
        w.write_u16(1);
        w.write_u16(1);
        w.write_u32(300);
        w.write_u16(0);
        let msg = w.finish();

        let result = TtlScan::scan(&msg);
        assert!(
            result.is_err(),
            "pointer loop / forward pointer must return an error"
        );
    }

    /// Truncated RDLENGTH (says 100 bytes but only a few follow) → Error.
    #[test]
    fn truncated_rdata_returns_error() {
        let mut w = Writer::with_capacity(64);
        Header::new(0x1234)
            .with_qr(true)
            .with_qdcount(1)
            .with_ancount(1)
            .write(&mut w);
        write_name(&mut w, "example.com");
        w.write_u16(1); // QTYPE A
        w.write_u16(1); // QCLASS IN
        // Answer RR: valid name, valid TYPE/CLASS/TTL, but RDLENGTH claims 100 bytes.
        write_name(&mut w, "example.com");
        w.write_u16(1); // TYPE A
        w.write_u16(1); // CLASS IN
        w.write_u32(300); // TTL
        w.write_u16(100); // RDLENGTH = 100 (truncated — only 4 bytes follow)
        w.write_slice(&[1, 2, 3, 4]); // only 4 bytes of RDATA
        let msg = w.finish();

        let result = TtlScan::scan(&msg);
        assert!(
            result.is_err(),
            "truncated RDATA must return an error, not silently succeed"
        );
    }

    /// Truncated fixed RR fields (message ends before reading TTL) → Error.
    #[test]
    fn truncated_rr_fixed_fields_returns_error() {
        let mut w = Writer::with_capacity(64);
        Header::new(0x1234)
            .with_qr(true)
            .with_qdcount(1)
            .with_ancount(1)
            .write(&mut w);
        write_name(&mut w, "example.com");
        w.write_u16(1); // QTYPE A
        w.write_u16(1); // QCLASS IN
        // Answer RR: owner name only, then TYPE but truncated before CLASS.
        write_name(&mut w, "example.com");
        w.write_u16(1); // TYPE A only — no CLASS, no TTL, no RDLENGTH
        let msg = w.finish();

        let result = TtlScan::scan(&msg);
        assert!(
            result.is_err(),
            "truncated RR fixed fields must return an error"
        );
    }

    /// Malformed (random) bytes → returns Error (or Ok), never panics.
    #[test]
    fn no_panic_on_random_bytes() {
        let data: Vec<u8> = (0u8..=255).cycle().take(512).collect();
        let msg = Bytes::from(data);
        let _ = TtlScan::scan(&msg); // must not panic
    }

    /// All-zeros buffer → returns Error (or degenerate Ok), never panics.
    #[test]
    fn no_panic_on_all_zeros() {
        let msg = Bytes::from(vec![0u8; 64]);
        let _ = TtlScan::scan(&msg);
    }

    /// All-0xFF buffer → returns Error (never panics).
    #[test]
    fn no_panic_on_all_ones() {
        let msg = Bytes::from(vec![0xFFu8; 256]);
        let _ = TtlScan::scan(&msg);
    }

    /// Empty buffer → returns MessageTooShort, never panics.
    #[test]
    fn no_panic_on_empty() {
        let msg = Bytes::new();
        let result = TtlScan::scan(&msg);
        assert!(
            matches!(result, Err(Error::MessageTooShort(_))),
            "empty buffer must return MessageTooShort"
        );
    }

    // ── min_ttl correctness with a single record ──────────────────────────────

    #[test]
    fn single_rr_min_ttl_equals_that_ttl() {
        let msg = build_response(1, 0, 0, "example.com", |w| {
            write_a_record(w, "example.com", 42, 0x10);
        });

        let scan = TtlScan::scan(&msg).expect("scan must succeed");

        assert_eq!(scan.min_ttl, Some(42));
        assert_eq!(scan.ttl_offsets.len(), 1);
        assert_eq!(read_u32_at(&msg, scan.ttl_offsets[0]), 42);
    }

    // ── OPT record with multiple real records ─────────────────────────────────

    #[test]
    fn opt_among_real_rrs_excluded_from_min_and_offsets() {
        // 2 A records (TTLs 500 and 200) + 1 OPT (EDNS "TTL" = 0).
        // min_ttl should be 200; 2 offsets recorded (not 3).
        let msg = build_response(2, 0, 1, "example.com", |w| {
            write_a_record(w, "example.com", 500, 0x01);
            write_a_record(w, "example.com", 200, 0x02);
            write_opt_record(w, 4096);
        });

        let scan = TtlScan::scan(&msg).expect("scan must succeed");

        assert_eq!(scan.min_ttl, Some(200));
        assert_eq!(scan.ttl_offsets.len(), 2);

        // Verify the two offsets point at the right TTLs.
        let expected = [500u32, 200];
        for (&off, &exp) in scan.ttl_offsets.iter().zip(expected.iter()) {
            assert_eq!(read_u32_at(&msg, off), exp);
        }
    }

    // ── TTL = 0 edge case ────────────────────────────────────────────────────

    #[test]
    fn ttl_zero_is_recorded_and_is_minimum() {
        let msg = build_response(2, 0, 0, "example.com", |w| {
            write_a_record(w, "example.com", 300, 0x01);
            write_a_record(w, "example.com", 0, 0x02);
        });

        let scan = TtlScan::scan(&msg).expect("scan must succeed");

        assert_eq!(scan.min_ttl, Some(0));
        assert_eq!(scan.ttl_offsets.len(), 2);
    }

    // ── u32::MAX TTL ─────────────────────────────────────────────────────────

    #[test]
    fn ttl_max_u32_recorded() {
        let msg = build_response(1, 0, 0, "example.com", |w| {
            write_a_record(w, "example.com", u32::MAX, 0x01);
        });

        let scan = TtlScan::scan(&msg).expect("scan must succeed");

        assert_eq!(scan.min_ttl, Some(u32::MAX));
        assert_eq!(read_u32_at(&msg, scan.ttl_offsets[0]), u32::MAX);
    }
}
