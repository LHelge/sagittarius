//! Fuzz target: structured DNS-shaped input.
//!
//! Uses `arbitrary` to derive a structured input type that assembles a
//! semi-valid DNS message from random components — random ID/flags/counts, a
//! generated QNAME, and optional trailing bytes.  This reaches deeper parser
//! states than the raw-bytes target (`parse.rs`) by ensuring the first 12
//! bytes are always a syntactically plausible header.
//!
//! # Running
//!
//! ```sh
//! cargo +nightly fuzz run parse_structured
//! # Seed from committed fixtures (copy into the corpus dir; see fuzz/README.md):
//! mkdir -p fuzz/corpus/parse_structured && cp fixtures/*.bin fuzz/corpus/parse_structured/
//! cargo +nightly fuzz run parse_structured
//! ```
#![no_main]

use arbitrary::Arbitrary;
use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use sagittarius::codec::{message::Query, synth::EdnsInfo, ttl::TtlScan};

/// A semi-structured DNS message input.
///
/// The fuzzer generates these fields independently; we assemble them into a
/// byte buffer that looks like a real DNS message, increasing the chance of
/// reaching the question-parsing and RR-walking code paths.
#[derive(Arbitrary, Debug)]
struct DnsInput {
    /// Transaction ID (2 bytes).
    id: u16,
    /// DNS flags word (2 bytes) — QR, opcode, AA, TC, RD, RA, Z, RCODE.
    flags: u16,
    /// QDCOUNT (we force it to 1 in the assembled message to maximize
    /// question-section parsing coverage).
    #[allow(dead_code)]
    qdcount_hint: u8, // unused directly; we always emit QDCOUNT=1
    /// ANCOUNT for the response RR sections.
    ancount: u8,
    /// NSCOUNT for the authority section.
    nscount: u8,
    /// ARCOUNT for the additional section.
    arcount: u8,
    /// Label bytes for the QNAME.  We take up to 8 labels of up to 8 bytes
    /// each, keeping the message small.
    labels: Vec<SmallLabel>,
    /// QTYPE (2 bytes).
    qtype: u16,
    /// QCLASS (2 bytes).
    qclass: u16,
    /// Optional trailing bytes appended after the question section — simulates
    /// partial or full RR section data.
    trailing: Vec<u8>,
}

/// A single DNS label — up to 8 bytes of ASCII-ish content.
#[derive(Arbitrary, Debug)]
struct SmallLabel(
    #[arbitrary(with = |u: &mut arbitrary::Unstructured| {
        let len: u8 = u.int_in_range(1..=8)?;
        let mut buf = vec![0u8; len as usize];
        u.fill_buffer(&mut buf)?;
        Ok(buf)
    })]
    Vec<u8>,
);

fuzz_target!(|input: DnsInput| {
    let mut msg = Vec::with_capacity(256);

    // Header (12 bytes).
    msg.extend_from_slice(&input.id.to_be_bytes());
    msg.extend_from_slice(&input.flags.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    msg.extend_from_slice(&(input.ancount as u16).to_be_bytes());
    msg.extend_from_slice(&(input.nscount as u16).to_be_bytes());
    msg.extend_from_slice(&(input.arcount as u16).to_be_bytes());

    // QNAME: write up to 4 labels (cap to stay under name length limits).
    let labels: Vec<&[u8]> = input
        .labels
        .iter()
        .take(4)
        .map(|l| l.0.as_slice())
        .collect();
    for label in &labels {
        // Clamp each label to 63 bytes.
        let len = label.len().min(63) as u8;
        msg.push(len);
        msg.extend_from_slice(&label[..len as usize]);
    }
    msg.push(0x00); // root terminator

    // QTYPE + QCLASS.
    msg.extend_from_slice(&input.qtype.to_be_bytes());
    msg.extend_from_slice(&input.qclass.to_be_bytes());

    // Optional trailing RR section bytes.
    let trailing = if input.trailing.len() > 512 {
        &input.trailing[..512]
    } else {
        &input.trailing
    };
    msg.extend_from_slice(trailing);

    // ── Drive the codec entry points ──────────────────────────────────────────
    let query_result = Query::try_from(msg.as_slice());

    let bytes = Bytes::from(msg);
    let _ = TtlScan::scan(&bytes);

    if let Ok(query) = query_result {
        let _ = EdnsInfo::scan(&query);
    }
});
