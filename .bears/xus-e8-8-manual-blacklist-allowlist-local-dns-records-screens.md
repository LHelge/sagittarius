---
id: xus
title: E8.8 · Manual blacklist/allowlist + local DNS records screens
status: done
priority: P1
created: 2026-05-29T07:57:48.436239324Z
updated: 2026-05-29T21:48:19.526493992Z
tags:
- web
depends_on:
- tqg
- y72
- zcf
parent: p6b
---

CRUD admin screens for the explicit lists and local DNS records. See SPEC §9, §5.

## Deliverables
- Manual **blacklist** and **allowlist** management pages: add / remove / list domains.
- **Local DNS records** page: add / edit / remove records including **wildcards** (e.g. `*.home.lan`), with type (A/AAAA) + value + TTL. The same name may have both A and AAAA records; uniqueness is `(name, type)`.
- All mutations **write through to E3 (E3.5)** then **swap the E4 in-memory snapshots** (E4.4) so changes take effect on the next query. CSRF-protected (E8.3).

## Design notes
- Reuses the write-through + snapshot-swap pattern established by the one-click actions (E8.7).
- Domain normalization consistent with the codec/`Name`.

## Validation
- CRUD round-trips per screen (DB + in-memory both updated).
- A wildcard local record is stored and then resolves authoritatively.
- A local name with only A returns authoritative NODATA for unsupported/different qtypes rather than forwarding upstream.
- A manually blacklisted domain is blocked on the next query; removing it unblocks.
