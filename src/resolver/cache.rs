//! Raw-bytes DNS response cache with per-entry TTL expiry.
//!
//! Implements the raw-bytes cache described in SPEC §8: each cached entry stores
//! the upstream response exactly as received (`bytes::Bytes`) together with the
//! byte offsets of every real (non-OPT) RR TTL field, recorded by
//! [`codec::ttl::TtlScan`].
//!
//! On a cache hit, [`DnsCache::get`] synthesises a fresh response by copying the
//! cached bytes and patching two things in-place — no parse, no re-serialisation:
//!
//! 1. **Transaction ID** (bytes 0–1): overwritten with the client's query ID.
//! 2. **TTL fields**: each offset from [`TtlScan`] is decremented by the time
//!    elapsed since the entry was stored, saturating at 0.
//!
//! # Design notes
//!
//! - The cache is a **mechanism** only.  It does not classify responses as
//!   positive or negative, and it does not decide whether a response should be
//!   cached.  All policy (which TTL to use, whether to store a `NXDOMAIN`, etc.)
//!   lives in the caller (E6.3).
//! - [`DnsCache`] wraps a [`moka::future::Cache`] which is internally concurrent
//!   and cheaply cloneable.  Shared via [`std::sync::Arc`] in E4.4.
//! - Expiry is driven by a real (`quanta`) clock, not Tokio's virtual clock, so
//!   the one real-sleep expiry test in this module uses `std::thread::sleep`.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::{BufMut, Bytes, BytesMut};
use moka::future::Cache;

use crate::codec::message::Question;

// ── CachedResponse ────────────────────────────────────────────────────────────

/// A single entry stored in the [`DnsCache`].
///
/// Cheap to clone: `bytes` and `ttl_offsets` are reference-counted, and the
/// remaining fields are plain `Copy` scalars.
#[derive(Clone, Debug)]
struct CachedResponse {
    /// The full upstream response, as received on the wire.
    bytes: Bytes,

    /// Absolute byte offsets of each real (non-OPT) TTL field in `bytes`.
    ///
    /// Stored as an `Arc<[usize]>` so cloning the entry is always O(1)
    /// regardless of how many RRs are present.
    ttl_offsets: Arc<[usize]>,

    /// Wall-clock time at which this entry was stored, used to compute the
    /// elapsed time when serving the entry.
    stored_at: Instant,

    /// The clamped per-entry lifetime.  Read by the [`moka::Expiry`] impl.
    expiry: Duration,
}

// ── Expiry impl ───────────────────────────────────────────────────────────────

/// Per-entry expiry policy for [`moka`].
///
/// `expire_after_create` returns the pre-computed `expiry` field so that
/// `moka` evicts each entry at exactly the right wall-clock time.  The other
/// two methods are not overridden (`None` → no change on read/update).
#[derive(Debug, Clone)]
struct DnsCacheExpiry;

impl moka::Expiry<Question, CachedResponse> for DnsCacheExpiry {
    fn expire_after_create(
        &self,
        _key: &Question,
        value: &CachedResponse,
        _current_time: Instant,
    ) -> Option<Duration> {
        Some(value.expiry)
    }
}

// ── TTL clamp helper ──────────────────────────────────────────────────────────

/// Clamp `secs` to `[min, max]` (both inclusive).
///
/// # Panics
///
/// Does not panic; relies on `u32::clamp` which requires `min <= max`.
/// Callers must ensure `min <= max`, which is enforced in [`DnsCache::new`].
#[inline]
fn clamp_ttl(secs: u32, min: u32, max: u32) -> u32 {
    secs.clamp(min, max)
}

// ── Patch helper ─────────────────────────────────────────────────────────────

/// Produce a patched copy of a cached DNS response ready to send to a client.
///
/// Two in-place mutations are applied to a byte-for-byte copy of `bytes`:
///
/// 1. **Transaction ID** — if the buffer is at least 2 bytes, the first two
///    bytes are overwritten with `client_txn_id` in big-endian order.
/// 2. **TTL decrement** — for each offset in `ttl_offsets`, if `offset + 4 <=
///    len`, the big-endian `u32` at that offset is decremented by
///    `elapsed_secs` (saturating at 0).
///
/// The patching is fully bounds-guarded and never panics on bad input.
fn patch_response(
    bytes: &[u8],
    ttl_offsets: &[usize],
    client_txn_id: u16,
    elapsed_secs: u32,
) -> Bytes {
    let len = bytes.len();
    let mut buf = BytesMut::with_capacity(len);
    buf.put_slice(bytes);

    // 1. Patch transaction ID (bytes 0–1, big-endian).
    if len >= 2 {
        let id_bytes = client_txn_id.to_be_bytes();
        buf[0] = id_bytes[0];
        buf[1] = id_bytes[1];
    }

    // 2. Decrement each TTL field in-place (bounds-guarded).
    for &offset in ttl_offsets {
        if offset + 4 <= len {
            let old = u32::from_be_bytes([
                buf[offset],
                buf[offset + 1],
                buf[offset + 2],
                buf[offset + 3],
            ]);
            let new_ttl = old.saturating_sub(elapsed_secs);
            let new_bytes = new_ttl.to_be_bytes();
            buf[offset] = new_bytes[0];
            buf[offset + 1] = new_bytes[1];
            buf[offset + 2] = new_bytes[2];
            buf[offset + 3] = new_bytes[3];
        }
    }

    buf.freeze()
}

// ── DnsCache ──────────────────────────────────────────────────────────────────

/// A TTL-expiring raw-bytes cache for DNS responses.
///
/// Wraps a [`moka::future::Cache`] keyed by [`Question`]
/// (`(qname, qtype, qclass)`).  Each entry carries the full upstream response
/// bytes, the recorded TTL-field offsets, and a clamped per-entry lifetime.
///
/// On a hit [`DnsCache::get`] patches the transaction ID and decrements all TTL
/// fields in-place without any DNS parse or re-serialisation (SPEC §8).
///
/// # Sharing
///
/// `moka::future::Cache` is cheaply cloneable and internally concurrent.
/// `DnsCache` itself is `Clone + Send + Sync` and should be shared via
/// [`std::sync::Arc`] (or cloned directly) across tasks (E4.4).
#[derive(Clone, Debug)]
pub struct DnsCache {
    inner: Cache<Question, CachedResponse>,
    min_ttl: u32,
    max_ttl: u32,
}

impl DnsCache {
    /// Build a new [`DnsCache`] with the given capacity and TTL bounds.
    ///
    /// - `capacity` — maximum number of entries (moka handles eviction).
    /// - `min_ttl` — entries with a shorter TTL are clamped up to this value
    ///   (seconds).
    /// - `max_ttl` — entries with a longer TTL are clamped down to this value
    ///   (seconds).
    ///
    /// # Panics
    ///
    /// Panics in debug builds if `min_ttl > max_ttl`.
    #[must_use]
    pub fn new(capacity: u64, min_ttl: u32, max_ttl: u32) -> Self {
        debug_assert!(min_ttl <= max_ttl, "min_ttl must not exceed max_ttl");

        let inner = Cache::builder()
            .max_capacity(capacity)
            .expire_after(DnsCacheExpiry)
            .build();

        Self {
            inner,
            min_ttl,
            max_ttl,
        }
    }

    /// Insert a response into the cache.
    ///
    /// The **caller supplies `expiry_ttl_secs`** — the TTL that should govern
    /// how long this entry lives.  For positive responses this is typically the
    /// minimum real-RR TTL; for negative responses (`NXDOMAIN`/`NODATA`) the
    /// caller passes the SOA-derived negative TTL.  The cache clamps the
    /// supplied value to `[min_ttl, max_ttl]` and stores it as the per-entry
    /// expiry.
    ///
    /// `ttl_offsets` is the `Vec<usize>` from [`codec::ttl::TtlScan`]; it is
    /// converted to an `Arc<[usize]>` once at insert time so that future clones
    /// of the entry are O(1).
    pub async fn insert(
        &self,
        key: Question,
        bytes: Bytes,
        ttl_offsets: Vec<usize>,
        expiry_ttl_secs: u32,
    ) {
        let clamped = clamp_ttl(expiry_ttl_secs, self.min_ttl, self.max_ttl);
        let entry = CachedResponse {
            bytes,
            ttl_offsets: Arc::from(ttl_offsets),
            stored_at: Instant::now(),
            expiry: Duration::from_secs(u64::from(clamped)),
        };
        self.inner.insert(key, entry).await;
    }

    /// Serve a cached response for `key`, patching it for the given client.
    ///
    /// On a hit, returns `Some(Bytes)` containing the cached response with:
    /// - The transaction ID (bytes 0–1) replaced with `client_txn_id`.
    /// - Each recorded TTL field decremented by the seconds elapsed since the
    ///   entry was stored (saturating at 0).
    ///
    /// Returns `None` if the key is not in the cache (cache miss).
    pub async fn get(&self, key: &Question, client_txn_id: u16) -> Option<Bytes> {
        let entry = self.inner.get(key).await?;

        let elapsed_secs = entry
            .stored_at
            .elapsed()
            .as_secs()
            .try_into()
            .unwrap_or(u32::MAX);

        Some(patch_response(
            &entry.bytes,
            &entry.ttl_offsets,
            client_txn_id,
            elapsed_secs,
        ))
    }

    /// Run any pending maintenance tasks (e.g. expire stale entries).
    ///
    /// Useful in tests to synchronously flush expiry without relying on moka's
    /// background maintenance thread.
    pub async fn run_pending_tasks(&self) {
        self.inner.run_pending_tasks().await;
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{
        header::{Header, Rcode},
        message::{Qclass, Qtype, Question},
        name::Name,
        reader::Reader,
        ttl::TtlScan,
        writer::Writer,
    };

    // ── Test helpers ──────────────────────────────────────────────────────────

    /// Build a minimal DNS A-record response:
    /// - Header: QR=1, QDCOUNT=1, ANCOUNT=1
    /// - Question: `name` / A / IN
    /// - Answer: `name` / A / IN / `ttl` / 4 bytes of 127.0.0.1
    fn build_a_response(id: u16, name: &str, ttl: u32) -> Bytes {
        let mut w = Writer::with_capacity(128);
        Header::new(id)
            .with_qr(true)
            .with_rcode(Rcode::NoError)
            .with_qdcount(1)
            .with_ancount(1)
            .write(&mut w);

        let n: Name = name.parse().expect("valid name");
        // Question section.
        n.write(&mut w);
        w.write_u16(1); // QTYPE A
        w.write_u16(1); // QCLASS IN

        // Answer section: owner + TYPE + CLASS + TTL + RDLENGTH + RDATA.
        n.write(&mut w);
        w.write_u16(1); // TYPE A
        w.write_u16(1); // CLASS IN
        w.write_u32(ttl);
        w.write_u16(4); // RDLENGTH
        w.write_slice(&[127, 0, 0, 1]); // RDATA

        w.finish()
    }

    /// Parse the 16-bit transaction ID from a DNS message (bytes 0–1, big-endian).
    fn read_txn_id(bytes: &[u8]) -> u16 {
        u16::from_be_bytes([bytes[0], bytes[1]])
    }

    /// Read the big-endian u32 at an absolute byte offset.
    fn read_u32_at(bytes: &[u8], offset: usize) -> u32 {
        u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ])
    }

    /// Build a [`Question`] for `name` / A / IN.
    fn make_question(name: &str) -> Question {
        Question {
            name: name.parse().expect("valid name"),
            qtype: Qtype::A,
            qclass: Qclass::In,
        }
    }

    // ── clamp_ttl ─────────────────────────────────────────────────────────────

    #[test]
    fn clamp_ttl_below_min_returns_min() {
        assert_eq!(clamp_ttl(0, 5, 3600), 5);
        assert_eq!(clamp_ttl(4, 5, 3600), 5);
    }

    #[test]
    fn clamp_ttl_above_max_returns_max() {
        assert_eq!(clamp_ttl(7200, 5, 3600), 3600);
        assert_eq!(clamp_ttl(u32::MAX, 5, 3600), 3600);
    }

    #[test]
    fn clamp_ttl_in_range_unchanged() {
        assert_eq!(clamp_ttl(300, 5, 3600), 300);
        assert_eq!(clamp_ttl(5, 5, 3600), 5);
        assert_eq!(clamp_ttl(3600, 5, 3600), 3600);
    }

    // ── patch_response ────────────────────────────────────────────────────────

    /// Build a small but structurally complete A-record response, run TtlScan
    /// to get real offsets, then call patch_response and verify via re-parse.
    #[test]
    fn patch_response_txn_id_and_ttl_decrement() {
        let original_ttl: u32 = 300;
        let original_id: u16 = 0x1234;
        let msg = build_a_response(original_id, "example.com", original_ttl);

        let bytes_ref: Bytes = msg.clone();
        let scan = TtlScan::scan(&bytes_ref).expect("scan must succeed");
        assert_eq!(scan.ttl_offsets.len(), 1, "expected exactly one TTL offset");

        let elapsed: u32 = 30;
        let client_id: u16 = 0xBEEF;

        let patched = patch_response(&msg, &scan.ttl_offsets, client_id, elapsed);

        // Transaction ID must equal client_id.
        assert_eq!(
            read_txn_id(&patched),
            client_id,
            "patched txn-id must match client_id"
        );

        // TTL must be decremented by elapsed.
        let expected_ttl = original_ttl.saturating_sub(elapsed);
        let actual_ttl = read_u32_at(&patched, scan.ttl_offsets[0]);
        assert_eq!(
            actual_ttl, expected_ttl,
            "TTL must be decremented by elapsed"
        );
    }

    /// Verify the transaction ID is also patchable independently.
    #[test]
    fn patch_response_txn_id_only() {
        let msg = build_a_response(0xAAAA, "a.example.com", 60);
        let scan = TtlScan::scan(&msg.clone()).expect("scan");

        // elapsed = 0 → TTLs unchanged; only txn-id changes.
        let patched = patch_response(&msg, &scan.ttl_offsets, 0xBBBB, 0);

        assert_eq!(read_txn_id(&patched), 0xBBBB);
        // TTL should be unchanged (elapsed = 0).
        assert_eq!(read_u32_at(&patched, scan.ttl_offsets[0]), 60);
    }

    /// When elapsed exceeds the TTL, the result must saturate at 0 (no wrap).
    #[test]
    fn patch_response_ttl_saturates_at_zero() {
        let ttl: u32 = 10;
        let msg = build_a_response(0x0001, "sat.example.com", ttl);
        let scan = TtlScan::scan(&msg.clone()).expect("scan");

        let patched = patch_response(&msg, &scan.ttl_offsets, 0x0001, ttl + 50);

        // Must saturate at 0, not wrap around.
        assert_eq!(
            read_u32_at(&patched, scan.ttl_offsets[0]),
            0,
            "TTL must saturate at 0"
        );
    }

    /// TTL already at 0 — must stay 0 after decrement.
    #[test]
    fn patch_response_zero_ttl_stays_zero() {
        let msg = build_a_response(0x0001, "zero.example.com", 0);
        let scan = TtlScan::scan(&msg.clone()).expect("scan");

        let patched = patch_response(&msg, &scan.ttl_offsets, 0x0001, 100);
        assert_eq!(read_u32_at(&patched, scan.ttl_offsets[0]), 0);
    }

    /// Out-of-bounds offsets must be silently skipped (no panic).
    #[test]
    fn patch_response_out_of_bounds_offset_skipped() {
        let msg = build_a_response(0x0001, "oob.example.com", 100);
        let bad_offsets: Vec<usize> = vec![msg.len() - 1, msg.len(), msg.len() + 100];

        // Must not panic.
        let _ = patch_response(&msg, &bad_offsets, 0x0001, 10);
    }

    /// Buffer shorter than 2 bytes — no txn-id patch, no panic.
    #[test]
    fn patch_response_short_buffer_no_panic() {
        let buf = &[0xAAu8]; // 1 byte — too short to hold a txn-id
        let patched = patch_response(buf, &[], 0xBEEF, 0);
        // Must not panic and must return the unchanged single byte.
        assert_eq!(&patched[..], &[0xAAu8]);
    }

    /// Empty buffer — no panic and empty output.
    #[test]
    fn patch_response_empty_buffer_no_panic() {
        let patched = patch_response(&[], &[], 0x1234, 10);
        assert_eq!(patched.len(), 0);
    }

    // ── DnsCache: insert + get ────────────────────────────────────────────────

    #[tokio::test]
    async fn cache_hit_returns_patched_bytes() {
        let cache = DnsCache::new(100, 1, 3600);
        let question = make_question("hit.example.com");
        let ttl: u32 = 300;
        let msg = build_a_response(0xAAAA, "hit.example.com", ttl);
        let bytes_ref: Bytes = msg.clone();
        let scan = TtlScan::scan(&bytes_ref).expect("scan");

        cache
            .insert(question.clone(), msg, scan.ttl_offsets.clone(), ttl)
            .await;

        let client_id: u16 = 0xBEEF;
        let result = cache.get(&question, client_id).await;
        assert!(result.is_some(), "expected a cache hit");

        let patched = result.unwrap();
        assert_eq!(
            read_txn_id(&patched),
            client_id,
            "transaction ID must be patched to client_id"
        );
    }

    #[tokio::test]
    async fn cache_miss_returns_none() {
        let cache = DnsCache::new(100, 1, 3600);
        let question = make_question("miss.example.com");
        let result = cache.get(&question, 0x1234).await;
        assert!(result.is_none(), "expected a cache miss");
    }

    /// Two distinct questions must not collide in the cache.
    #[tokio::test]
    async fn different_questions_do_not_collide() {
        let cache = DnsCache::new(100, 1, 3600);

        let q1 = make_question("a.example.com");
        let q2 = make_question("b.example.com");

        let msg1 = build_a_response(0x0001, "a.example.com", 100);
        let msg2 = build_a_response(0x0002, "b.example.com", 200);

        let bytes1: Bytes = msg1.clone();
        let scan1 = TtlScan::scan(&bytes1).unwrap();
        let bytes2: Bytes = msg2.clone();
        let scan2 = TtlScan::scan(&bytes2).unwrap();

        cache.insert(q1.clone(), msg1, scan1.ttl_offsets, 100).await;
        cache.insert(q2.clone(), msg2, scan2.ttl_offsets, 200).await;

        assert!(cache.get(&q1, 0xAAAA).await.is_some(), "q1 should hit");
        assert!(cache.get(&q2, 0xBBBB).await.is_some(), "q2 should hit");

        // A completely absent key must miss.
        let q3 = make_question("c.example.com");
        assert!(cache.get(&q3, 0xCCCC).await.is_none(), "q3 should miss");
    }

    // ── DnsCache: expiry (real sleep, one test) ───────────────────────────────

    /// Insert with expiry_ttl_secs = 1 (min_ttl = 1); get immediately → hit;
    /// wait 1.1 s; get again → miss.
    ///
    /// This test uses a real ~1.1 s sleep because moka uses a real (quanta)
    /// clock, not Tokio's virtual clock.  It is the only test in this module
    /// that sleeps.
    #[tokio::test]
    async fn cache_entry_expires_after_ttl() {
        let cache = DnsCache::new(100, 1, 3600);
        let question = make_question("expire.example.com");
        let msg = build_a_response(0x0001, "expire.example.com", 1);
        let bytes_ref: Bytes = msg.clone();
        let scan = TtlScan::scan(&bytes_ref).expect("scan");

        // Insert with 1-second TTL.
        cache
            .insert(question.clone(), msg, scan.ttl_offsets, 1)
            .await;

        // Immediate get → should hit.
        assert!(
            cache.get(&question, 0x0001).await.is_some(),
            "entry should be present immediately after insert"
        );

        // Wait for the entry to expire.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        cache.run_pending_tasks().await;

        // After expiry → should miss.
        assert!(
            cache.get(&question, 0x0001).await.is_none(),
            "entry should have expired after 1.1 s"
        );
    }

    // ── DnsCache: TTL clamping at insert ──────────────────────────────────────

    /// Verify the TTL clamp by observing that an entry stored with a very small
    /// supplied TTL gets bumped to min_ttl (entry survives a short wait that
    /// would have expired the raw supplied TTL).
    ///
    /// Specifically: min_ttl = 5, supply expiry_ttl_secs = 0.  The clamped TTL
    /// is 5 s.  After 100 ms the entry must still be present.
    #[tokio::test]
    async fn insert_clamps_ttl_to_min() {
        let cache = DnsCache::new(100, 5, 3600);
        let question = make_question("clamp.example.com");
        let msg = build_a_response(0x0001, "clamp.example.com", 1);
        let bytes_ref: Bytes = msg.clone();
        let scan = TtlScan::scan(&bytes_ref).expect("scan");

        // Supply ttl=0 (below min_ttl=5) — should be clamped to 5 s.
        cache
            .insert(question.clone(), msg, scan.ttl_offsets, 0)
            .await;

        // 100 ms later the entry must still be present (it would be gone if 0 s
        // were honoured verbatim).
        tokio::time::sleep(Duration::from_millis(100)).await;
        cache.run_pending_tasks().await;

        assert!(
            cache.get(&question, 0x0001).await.is_some(),
            "entry clamped to min_ttl=5 should still be present after 100 ms"
        );
    }

    // ── Re-parse patched bytes ────────────────────────────────────────────────

    /// Build a response, scan TTLs, call patch_response, then re-parse the
    /// patched bytes with Header::read and TtlScan to confirm structural validity.
    #[test]
    fn patch_response_patched_bytes_are_re_parseable() {
        let original_ttl: u32 = 120;
        let msg = build_a_response(0xFFFF, "reparse.example.com", original_ttl);
        let bytes_ref: Bytes = msg.clone();
        let scan = TtlScan::scan(&bytes_ref).expect("scan");

        let elapsed: u32 = 20;
        let client_id: u16 = 0x4242;

        let patched_bytes = patch_response(&msg, &scan.ttl_offsets, client_id, elapsed);

        // The patched message must still be parseable by TtlScan.
        let patched_scan = TtlScan::scan(&patched_bytes).expect("patched message must scan");
        assert_eq!(patched_scan.ttl_offsets.len(), 1);

        // The header ID must match client_id.
        let mut reader = Reader::new(patched_bytes.clone());
        let header = Header::read(&mut reader).expect("header must parse");
        assert_eq!(
            header.id, client_id,
            "patched header.id must match client_id"
        );

        // The TTL at the recorded offset must equal original − elapsed.
        let expected = original_ttl.saturating_sub(elapsed);
        assert_eq!(
            read_u32_at(&patched_bytes, scan.ttl_offsets[0]),
            expected,
            "TTL at offset must be decremented"
        );
    }
}
