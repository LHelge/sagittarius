---
id: rbn
title: E4 · Resolver state & cache
type: epic
status: open
priority: P1
created: 2026-05-28T22:38:11.988738775Z
updated: 2026-05-28T22:44:02.492064481Z
tags:
- dns
- cache
depends_on:
- rjw
- hga
---

The in-memory hot-path data — match sets, local records, and the answer cache — designed for lock-free reads while admin/refresh paths swap fresh snapshots. See SPEC §3.1, §3.2, §8.

**Scope**
- `arc-swap`-held immutable snapshots for the admin **blacklist**, **allowlist**, and aggregated **blocklist set** (`HashSet` of normalized names): atomic read, rebuild-and-swap on write.
- Match-precedence engine implementing the SPEC §5 order: local records → admin blacklist → allowlist (sets `allow-bypass`) → blocklist set. **Exact match only** for v0.1.
- Local-record matcher: exact and wildcard maps keyed by `(Name, QType)` with wildcard suffix-probe (strip leftmost labels, probe `*.<suffix>`), most-specific match wins; A/AAAA values + TTL (CNAME TBD when planned). It also reports local-name qtype mismatches so the pipeline can return authoritative NODATA instead of forwarding private names upstream.
- `moka` cache keyed by `(qname, qtype, qclass)`: stores the raw response `Bytes` + recorded TTL-field offsets; per-entry expiry from the min TTL (clamped to configured bounds); positive + negative caching.
- Serve-from-cache: clone bytes, patch the transaction ID, decrement TTLs in place by elapsed time.
- A cohesive resolver-state type bundling these plus a hot-swappable runtime-settings snapshot, shared via `Arc`, hydrated from E3 at startup.

**Design notes**
- Concurrency model per SPEC §3.2: readers never block; writers swap; `moka` is already concurrent; runtime settings are swapped as a whole snapshot; stats are atomics (owned by E6).
- Expose a `Decision` enum and typed `MatchSet`/`Cache` APIs with methods.

**Out of scope**
- Where decisions are invoked (the pipeline, E6).
- Blocklist fetching/aggregation (E7) — E4 only provides the set + swap mechanism it writes into.
- Subdomain/parent-domain matching (future; would introduce the reversed-label trie).

**Validation**
- Precedence unit tests for every branch, incl. allowlist-vs-blacklist override.
- Wildcard tests: most-specific match, no false positives, qtype-specific local NODATA result.
- Cache tests: insert, expiry honouring TTL, TTL decrement on serve, txn-id patch, negative caching.
- Concurrency test: readers observe a consistent snapshot across a swap.
