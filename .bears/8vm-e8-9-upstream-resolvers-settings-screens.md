---
id: 8vm
title: E8.9 · Upstream resolvers + settings screens
status: done
priority: P1
created: 2026-05-29T07:57:54.513005805Z
updated: 2026-05-29T21:54:42.896016591Z
tags:
- web
depends_on:
- tqg
- beg
- zcf
- jcz
- tx4
parent: p6b
---

Configuration screens for upstream resolvers and global settings. See SPEC §9, §7, §4.

## Deliverables
- **Upstream resolvers** page: list / add / remove / enable-disable upstreams (address, transport udp/tcp/dot/doh, optional TLS server name), write-through to E3.4.
- **Settings** page: cache bounds (min/max TTL, negative-TTL cap, capacity), blocking mode + custom sinkhole IP, blocklist refresh interval, UI prefs — write-through to E3.4 (typed settings).
- Apply changes live where feasible; otherwise clearly document which take effect on restart:
  - upstreams → rebuild/swap the E5 pool through a typed upstream-pool handle,
  - cache **min/max TTL + negative cap** update E4.4's runtime-settings snapshot and apply to new inserts immediately; **cache capacity is fixed at build** in moka, so a capacity change requires rebuilding the cache (or a restart) — surface this in the UI,
  - blocking mode / custom IP update the runtime-settings snapshot and apply immediately (read at synthesis time),
  - blocklist refresh interval updates the scheduler control path from E7.4 (or is clearly marked restart-only if the implementation chooses not to hot-reload it).
- Session cookie secure policy is **not** a DB/UI setting; it is an operational CLI/env setting from E1.2 because it depends on deployment topology.
- CSRF-protected (E8.3).

## Design notes
- Settings are strongly typed (E3.4); validate inputs (valid IP, sane TTL bounds) before persisting.

## Validation
- Upstream add/remove/enable persists and (where applied live) changes forwarding behaviour.
- A settings change persists and re-reads with correct types; invalid input is rejected with a helpful message.
- Runtime-settings snapshot reflects blocking/TTL changes after write-through.
- Refresh interval change is either applied to the scheduler or explicitly surfaced as restart-required.
- Changing cache capacity is handled correctly (rebuild or documented restart), not silently ignored.
