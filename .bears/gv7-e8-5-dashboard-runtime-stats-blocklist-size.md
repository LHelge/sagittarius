---
id: gv7
title: E8.5 · Dashboard (runtime stats + blocklist size)
status: open
priority: P1
created: 2026-05-29T07:57:18.517226360Z
updated: 2026-05-29T07:57:18.517226360Z
tags:
- web
depends_on:
- 5kh
- 5jx
- zcf
parent: p6b
---

The dashboard page showing since-startup runtime figures. See SPEC §9.

## Deliverables
- An authenticated dashboard rendering from the E6.6 runtime counters:
  - total queries, blocked count + ratio, top blocked domains, top clients.
- Plus the **current blocklist set size** — the number of domains in the in-memory aggregated blocklist set, read from `ResolverState` (E4.4) via `AppState`.
- Server-rendered via Askama; values are a consistent-enough snapshot (SPEC §3.2).

## Design notes
- v0.1 figures are since-startup, in-memory (no historical/time-series charts — deferred).
- Live updates to these counters are wired through the shared SSE stream in E8.6.

## Validation
- Dashboard renders the counters and the blocklist size behind auth.
- Numbers match the underlying E6 counters / blocklist set length.