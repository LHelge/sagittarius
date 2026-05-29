---
id: 44p
title: E8.7 · One-click list management from the live log
status: open
priority: P1
created: 2026-05-29T07:58:08.052116418Z
updated: 2026-05-29T07:58:08.052116418Z
tags:
- web
depends_on:
- gyj
- tqg
- y72
- zcf
parent: p6b
---

One-click allow/deny straight from the live query log. See SPEC §9.

## Deliverables
- **Only effective actions are shown** based on E6.6's detailed outcome:
  - `BlockedByBlocklist` rows expose **Whitelist** (add the domain to the **allowlist**),
  - `Forwarded` / `Cached` resolved rows expose **Blacklist** (add to the **admin blacklist**),
  - `BlockedByAdmin`, `Local`, and `LocalNoData` rows do **not** show those one-click actions because allowlisting cannot override admin blacklist and blacklisting cannot override local records.
- The action **writes through to SQLite (E3.5)** and immediately **swaps the in-memory E4 set** (E4.4) so it takes effect on the next query.
- Datastar-driven: the action is a CSRF-protected (E8.3) mutating request; the row/UI updates via a fragment/signal patch.

## Design notes
- Establishes the write-through + snapshot-swap pattern reused by the manual screens (E8.8).
- Mutations go through the E8.3 CSRF layer.

## Validation
- A Whitelist action on a blocklist-blocked row persists to the allowlist **and** the domain resolves on the next query.
- A Blacklist action on a forwarded/cached resolved row persists to the blacklist **and** the domain is blocked on the next query.
- Admin-blocked and local rows do not render ineffective one-click actions.
- The action is rejected without a valid CSRF token.
