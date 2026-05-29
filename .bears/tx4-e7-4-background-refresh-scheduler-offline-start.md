---
id: tx4
title: E7.4 · Background refresh scheduler + offline start
status: open
priority: P1
created: 2026-05-29T07:47:31.151603769Z
updated: 2026-05-29T08:20:48.675910895Z
tags:
- blocklist
depends_on:
- nve
- pbr
- dyd
- beg
- bfx
parent: dqh
---

Orchestrate fetch → parse → aggregate → persist on a schedule, surviving restarts offline. See SPEC §3.1 (background tasks), §6.

## Deliverables
- **Offline start:** on boot, build the blocklist set from the SQLite-cached copies (E3.6) via parsers (E7.2) + aggregation (E7.3) — no network required. This initial cached aggregation should complete before the DNS listener is considered ready, so saved blocklists are active immediately after restart.
- **Scheduler:** a long-lived background task on the E1 TaskTracker (E1.4):
  - periodic refresh at the configured interval (from E4.4's runtime-settings snapshot, initially loaded from `Settings`, E3.4; **default 24 h**, seeded by E3.3),
  - an **on-demand trigger** (used by E8's manual "refresh now"),
  - each cycle: for every enabled source, conditional fetch (E7.1) → parse (E7.2) → aggregate + atomic swap (E7.3) → persist fetched copy + ETag/Last-Modified + entry count + last-updated (E3.6).
- **304 behaviour:** `NotModified` skips network body download but still contributes that source's domains to aggregation from the last cached body (or an in-memory parsed cache). Never drop a source from the live set merely because it returned `304`.
- **Resilience:** a failed fetch keeps the last good snapshot in use; one bad/erroring source never sinks the others.

## Design notes
- The scheduler is decoupled from the hot path; query serving never blocks on a refresh (SPEC §3.1).
- Define how interval changes from E8.9 are observed: either a watch/control message updates the running scheduler immediately, or the setting is explicitly marked restart-required. Prefer live update if it stays simple.

## Validation
- A scheduled refresh installs a new snapshot via atomic swap.
- A failing fetch retains the previous set (no clobber to empty).
- Offline start builds the set purely from the SQLite cache (no network).
- A `304 NotModified` source remains present in the aggregated set using its cached body.
- Per-source entry counts + last-updated are persisted; the on-demand trigger forces a refresh.
