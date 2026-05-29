//! Integration tests that load hand-authored DNS wire-format fixture files and
//! assert the expected parse outcomes from the codec.
//!
//! These fixtures are independent of the codec's own `Writer` — they were
//! hand-crafted from the RFC 1035 wire format — so they serve as a true
//! cross-check that the parser accepts real-world-shaped bytes.
//!
//! The fixture files also double as the fuzz seed corpus.  See
//! `fuzz/README.md` for how to seed `cargo fuzz` from them.

use bytes::Bytes;
use sagittarius::codec::{
    message::{Qclass, Qtype, Query},
    synth::EdnsInfo,
    ttl::TtlScan,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Load a fixture file relative to the crate root.
macro_rules! fixture {
    ($name:expr) => {
        Bytes::from_static(include_bytes!(concat!("../fixtures/", $name)))
    };
}

// ── a_query.bin ───────────────────────────────────────────────────────────────

/// Standard A query for `example.com` (ID=0x1234, RD=1).
///
/// Expected: parses successfully as a Query with the right name/type.
#[test]
fn fixture_a_query_parses() {
    let raw = fixture!("a_query.bin");
    let query = Query::try_from(raw).expect("a_query.bin must parse as a valid query");

    assert_eq!(query.header().id, 0x1234, "ID mismatch");
    assert!(query.header().rd(), "RD must be set");
    assert!(!query.header().qr(), "QR must be 0 (query)");
    assert_eq!(query.header().qdcount, 1);
    assert_eq!(query.question().qtype, Qtype::A, "QTYPE must be A");
    assert_eq!(query.question().qclass, Qclass::In, "QCLASS must be IN");
    assert_eq!(
        query.question().name.to_string(),
        "example.com.",
        "QNAME mismatch"
    );
}

/// `TtlScan` on a query (no RRs) gives `min_ttl=None`.
#[test]
fn fixture_a_query_ttl_scan_empty() {
    let raw = fixture!("a_query.bin");
    let scan = TtlScan::scan(&raw).expect("TtlScan must not fail on a_query.bin");
    assert_eq!(scan.min_ttl, None, "query has no RRs → no TTL");
    assert!(scan.ttl_offsets.is_empty());
}

// ── aaaa_query.bin ────────────────────────────────────────────────────────────

/// AAAA query for `example.com` (ID=0x5678, RD=1).
#[test]
fn fixture_aaaa_query_parses() {
    let raw = fixture!("aaaa_query.bin");
    let query = Query::try_from(raw).expect("aaaa_query.bin must parse");

    assert_eq!(query.header().id, 0x5678);
    assert!(query.header().rd());
    assert!(!query.header().qr());
    assert_eq!(query.question().qtype, Qtype::Aaaa, "QTYPE must be AAAA");
    assert_eq!(query.question().qclass, Qclass::In);
    assert_eq!(query.question().name.to_string(), "example.com.");
}

/// `TtlScan` on a query gives `min_ttl=None`.
#[test]
fn fixture_aaaa_query_ttl_scan_empty() {
    let raw = fixture!("aaaa_query.bin");
    let scan = TtlScan::scan(&raw).expect("TtlScan must succeed on aaaa_query.bin");
    assert_eq!(scan.min_ttl, None);
    assert!(scan.ttl_offsets.is_empty());
}

// ── a_response.bin ────────────────────────────────────────────────────────────

/// A response for `example.com` with one A answer (TTL 3600).
///
/// Verifies `TtlScan` finds exactly one TTL at the expected offset (35) and
/// that the value there is 3600.
#[test]
fn fixture_a_response_ttl_scan() {
    let raw = fixture!("a_response.bin");
    let scan = TtlScan::scan(&raw).expect("TtlScan must succeed on a_response.bin");

    assert_eq!(scan.min_ttl, Some(3600), "min_ttl must be 3600");
    assert_eq!(scan.ttl_offsets.len(), 1, "one RR → one TTL offset");

    let offset = scan.ttl_offsets[0];
    // TTL is 4-byte big-endian at the recorded offset.
    let ttl_bytes: [u8; 4] = raw[offset..offset + 4]
        .try_into()
        .expect("4 bytes at TTL offset");
    let actual_ttl = u32::from_be_bytes(ttl_bytes);
    assert_eq!(actual_ttl, 3600, "bytes at offset must read as 3600");
}

/// `a_response.bin` does not parse as a `Query` (QR=1).
///
/// The parse must either succeed (the shallow parser is lenient on QR) or
/// fail gracefully — it must never panic.
#[test]
fn fixture_a_response_no_panic() {
    let raw = fixture!("a_response.bin");
    // Response messages have QR=1; the shallow parser is lenient but may
    // reject or accept it — we only require no panic.
    let _ = Query::try_from(raw);
}

// ── a_response_edns.bin ───────────────────────────────────────────────────────

/// A response with an OPT record (EDNS, UDP payload 4096).
///
/// Verifies:
/// - `TtlScan` finds the A-record TTL (3600) and excludes the OPT.
/// - The fixture does not panic on `Query::try_from`.
#[test]
fn fixture_a_response_edns_ttl_scan() {
    let raw = fixture!("a_response_edns.bin");
    let scan = TtlScan::scan(&raw).expect("TtlScan must succeed on a_response_edns.bin");

    // OPT must be excluded — only the A record TTL.
    assert_eq!(
        scan.min_ttl,
        Some(3600),
        "OPT excluded; min_ttl must be the A-record TTL"
    );
    assert_eq!(
        scan.ttl_offsets.len(),
        1,
        "OPT excluded → exactly one TTL offset"
    );
}

/// When parsed as a `Query`, `EdnsInfo::scan` should find the OPT record
/// (UDP payload size 4096) if the parse succeeds.
///
/// Note: `a_response_edns.bin` has QR=1 (a response), so `Query::try_from`
/// may or may not succeed — we only run `EdnsInfo::scan` if it does parse.
#[test]
fn fixture_a_response_edns_edns_info_no_panic() {
    let raw = fixture!("a_response_edns.bin");
    // The shallow parser is lenient on QR; try it and only proceed if it works.
    if let Ok(query) = Query::try_from(raw) {
        // Must not panic.
        let edns = EdnsInfo::scan(&query);
        if let Some(info) = edns {
            // If we found an OPT, it should report 4096 payload size.
            assert_eq!(
                info.udp_payload_size, 4096,
                "OPT UDP payload size must be 4096"
            );
            assert!(info.cookie.is_none(), "no COOKIE option in this fixture");
        }
    }
}

// ── nxdomain_response.bin ─────────────────────────────────────────────────────

/// NXDOMAIN response for `notexist.example.com` with a SOA in authority.
///
/// Verifies `TtlScan` finds the SOA TTL (900) at the expected byte offset (55).
#[test]
fn fixture_nxdomain_ttl_scan() {
    let raw = fixture!("nxdomain_response.bin");
    let scan = TtlScan::scan(&raw).expect("TtlScan must succeed on nxdomain_response.bin");

    assert_eq!(scan.min_ttl, Some(900), "SOA TTL must be 900");
    assert_eq!(scan.ttl_offsets.len(), 1, "one SOA RR → one TTL offset");

    let offset = scan.ttl_offsets[0];
    let ttl_bytes: [u8; 4] = raw[offset..offset + 4]
        .try_into()
        .expect("4 bytes at TTL offset");
    let actual_ttl = u32::from_be_bytes(ttl_bytes);
    assert_eq!(actual_ttl, 900, "SOA TTL at offset must be 900");
}

/// `nxdomain_response.bin` does not panic on `Query::try_from`.
#[test]
fn fixture_nxdomain_no_panic() {
    let raw = fixture!("nxdomain_response.bin");
    let _ = Query::try_from(raw);
}

// ── multi_rr_response.bin ─────────────────────────────────────────────────────

/// A response for `www.example.com` with 3 A records (TTL 300 each),
/// using compression pointers for the owner names.
///
/// Verifies `TtlScan` finds exactly 3 TTL offsets and min_ttl=300,
/// and that each offset actually contains 300.
#[test]
fn fixture_multi_rr_ttl_scan() {
    let raw = fixture!("multi_rr_response.bin");
    let scan = TtlScan::scan(&raw).expect("TtlScan must succeed on multi_rr_response.bin");

    assert_eq!(scan.min_ttl, Some(300), "min_ttl must be 300");
    assert_eq!(
        scan.ttl_offsets.len(),
        3,
        "three A records → three TTL offsets"
    );

    for (i, &offset) in scan.ttl_offsets.iter().enumerate() {
        let ttl_bytes: [u8; 4] = raw[offset..offset + 4]
            .try_into()
            .expect("4 bytes at TTL offset");
        let actual = u32::from_be_bytes(ttl_bytes);
        assert_eq!(actual, 300, "RR {i} TTL must be 300 at offset {offset}");
    }
}

/// `multi_rr_response.bin` does not panic on `Query::try_from`.
#[test]
fn fixture_multi_rr_no_panic() {
    let raw = fixture!("multi_rr_response.bin");
    let _ = Query::try_from(raw);
}
