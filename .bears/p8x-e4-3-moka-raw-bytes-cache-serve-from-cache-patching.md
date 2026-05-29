---
id: p8x
title: E4.3 · moka raw-bytes cache + serve-from-cache patching
status: done
priority: P1
created: 2026-05-29T07:11:18.305171135Z
updated: 2026-05-29T13:43:15.607634180Z
tags:
- dns
- cache
depends_on:
- gmv
parent: rbn
---

A `moka` cache of raw response bytes with per-entry TTL expiry and cheap in-place serving. The cache is a **mechanism** — a TTL'd byte store; the positive/negative TTL *policy* lives at the cache-store seam (E6). See SPEC §8, §5 steps 7 & 9.

## Deliverables
- `cargo add moka` (async `future::Cache`).
- Cache keyed by `(qname, qtype, qclass)`; value = the raw response `Bytes` (as received) + the TTL-field byte offsets from E2.6's `TtlScan` (real RR TTLs only; OPT pseudo-RRs are excluded).
- `insert(key, bytes, offsets, expiry_ttl)`: the **caller supplies the expiry TTL** (positive = E6.3's chosen TTL from `TtlScan.min_ttl` when present; negative = hickory `DnsResponse::negative_ttl()`, already negative-capped by the caller — see E6.3). The cache clamps to the configured min/max bounds (supplied by E4.4) and sets per-entry expiration via the `Expiry` trait (`expire_after_create` returns the clamped TTL).
- **Serve-from-cache:** clone the bytes, patch the **transaction ID** to the client's query ID, and **decrement each TTL field** in place by elapsed time — no parse, no re-serialization.

## Design notes
- Cache shared via `Arc`; `moka` is already concurrent (SPEC §3.2).
- The TTL *source* (positive vs negative, RFC 2308 `min(SOA.ttl, SOA.minimum)`, the negative-TTL cap, and "don't cache SOA-less negatives") is decided by the caller at store time (E6.3). The cache only stores bytes + offsets with the supplied, clamped expiry — it does not classify responses.
- `moka` `max_capacity` is fixed at build time (relevant to E8.9 — a capacity change means rebuilding the cache).

## Validation
- Insert + hit returns the bytes.
- Entry expires per its supplied TTL; clamp to min/max honoured.
- Serve patches the txn-id and decrements TTL fields correctly (re-parse confirms a valid, reduced TTL).
- An entry inserted with a short (negative-style) TTL is served and expires accordingly.
