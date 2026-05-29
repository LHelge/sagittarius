---
id: h3u
title: E6.2 · Decision layers (precedence stack)
status: open
priority: P1
created: 2026-05-29T07:41:36.542631618Z
updated: 2026-05-29T07:41:36.542631618Z
tags:
- pipeline
- dns
depends_on:
- 5m2
- zcf
- x5f
- p8x
parent: 4k2
---

The early-return `tower` layers that implement SPEC §5 match precedence by their ordering. **E6 owns the precedence**; E4 only provides the per-set lookup primitives.

## Deliverables
- Early-return `tower` layers, in order:
  1. **Local records** (E4.4 matcher) → synthesize an authoritative answer (E2.5) and return; if the local name/wildcard exists but the requested qtype has no record, synthesize authoritative NODATA and return.
  2. **Admin blacklist** (exact) → synthesize the configured sinkhole response (E2.5) and return; mark Outcome=BlockedByAdmin.
  3. **Allowlist** (exact) → set `allow_bypass` and **continue** (never answers).
  4. **Blocklist set** (exact) → if `!allow_bypass`, synthesize sinkhole and return; Outcome=BlockedByBlocklist.
  5. **Cache** (E4.3) → on hit, serve the patched bytes (txn-id + TTL decrement); Outcome=Cached.
- Each layer routes on `Question` only and either short-circuits or calls the next.

## Design notes
- The allowlist suppresses **only** the bulk blocklist, never the admin blacklist; local wins over all blocking.
- Tested against a **stub inner service** so precedence is verified without sockets/upstream.

## Validation (per-branch precedence — moved here from E4)
- blacklisted + allowlisted → still **blocked**.
- allowlisted + blocklisted → bypass works, request continues (forwarded).
- local record present → wins over all blocking.
- local name exists but qtype does not → authoritative NODATA, no blocking/cache/upstream.
- plain blocklist hit → blocked; plain non-match → continues to cache/forward.
- cache hit → served with correct txn-id + decremented TTLs.
