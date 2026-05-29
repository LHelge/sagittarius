//! Fuzz target: raw-bytes entry points.
//!
//! Feeds arbitrary byte slices directly into the three untrusted-input entry
//! points of the DNS codec and asserts:
//! - No panic occurs (the codec must always return `Ok` or `Err`, never
//!   unwind).
//! - If `Query::try_from` succeeds, `EdnsInfo::scan` also runs without
//!   panicking.
//!
//! This covers the shallow-parse hot path (`message.rs`), the TTL walk
//! (`ttl.rs`), and the EDNS scan (`synth.rs`).
//!
//! # Running
//!
//! ```sh
//! cargo +nightly fuzz run parse
//! # Seed from the committed fixtures (copy, don't pass fixtures/ as the
//! # writable corpus dir — see fuzz/README.md):
//! mkdir -p fuzz/corpus/parse && cp fixtures/*.bin fuzz/corpus/parse/
//! cargo +nightly fuzz run parse
//! ```
#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use sagittarius::codec::{message::Query, synth::EdnsInfo, ttl::TtlScan};

fuzz_target!(|data: &[u8]| {
    // ── Entry point 1: shallow query parse ───────────────────────────────────
    let query_result = Query::try_from(data);

    // ── Entry point 2: TTL scan ───────────────────────────────────────────────
    let bytes = Bytes::copy_from_slice(data);
    let _ = TtlScan::scan(&bytes);

    // ── Entry point 3: EDNS scan (only when query parse succeeds) ─────────────
    if let Ok(query) = query_result {
        let _ = EdnsInfo::scan(&query);
    }
});
