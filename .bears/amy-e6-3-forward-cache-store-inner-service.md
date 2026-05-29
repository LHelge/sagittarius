---
id: amy
title: E6.3 · Forward + cache-store inner service
status: open
priority: P1
created: 2026-05-29T07:41:44.518141902Z
updated: 2026-05-29T09:29:29.674599424Z
tags:
- pipeline
- dns
depends_on:
- 5m2
- jcz
- gmv
- p8x
- zcf
parent: 4k2
---

The innermost service: forward cache misses upstream and store the result under the correct TTL policy. See SPEC §5 steps 8–9, §8.

## Deliverables
- On cache miss, forward the query via the E5.3 `Upstreams` pool and receive its **`ForwardResult`** (raw bytes + `negative_ttl` + `is_negative`); all-fail → SERVFAIL reply.
- **Cache-store TTL policy** (the seam between E5 and E4):
  - clone/patch the forwarded response transaction ID to the client's query ID before replying; cache storage keeps the upstream raw bytes unchanged, since cache hits patch the ID on serve,
  - run E2.6's scan on the raw bytes → `TtlScan` (real RR TTL-field offsets + positive min TTL; OPT pseudo-RRs excluded),
  - if `is_negative`: expiry = `negative_ttl` (RFC 2308); if `None` (no SOA) → **do not cache**; otherwise cap at the configured **negative-TTL cap** (default 3600 s),
  - else (positive): expiry = `TtlScan.min_ttl` when it is `Some(ttl)`; if there are no real TTL-bearing RRs (`None`), reply but **do not cache**,
  - clamp to the configured min/max bounds, then `insert` into the E4.3 cache (bytes + offsets + expiry).
- Build the reply bytes for the client; set Outcome=Forwarded.
- **State access:** obtain the cache instance and the cache-TTL policy values (min/max bounds + **negative-TTL cap**) from `ResolverState`'s `RuntimeSettings` snapshot (E4.4), the same `Arc<ResolverState>` the decision layers (E6.2) hold — so positive/negative TTL policy reads the live settings. (Min/max clamping may also be applied inside the cache per E4.3; the negative cap is applied here.)

## Design notes
- The cache is a dumb byte store (E4.3); the positive/negative decision + negative cap live here.
- Raw bytes are not re-serialized (the upstream wire bytes are stored as received). The client reply is patched for transaction ID; the cache stores the upstream raw bytes plus TTL offsets.

## Validation
- Miss → forward → reply returned and (if cacheable) stored.
- Forwarded reply uses the client's transaction ID, even if the upstream response carried a different ID.
- Positive answer cached with min-TTL expiry; a repeat query hits cache.
- Negative-with-SOA cached using `negative_ttl()` (capped); SOA-less negative is **not** cached.
- All upstreams fail → SERVFAIL.
