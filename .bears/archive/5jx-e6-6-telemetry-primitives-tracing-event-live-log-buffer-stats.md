---
id: 5jx
title: E6.6 · Telemetry primitives (tracing event, live-log buffer, stats)
status: done
priority: P1
created: 2026-05-29T07:41:51.347781272Z
updated: 2026-05-29T17:32:29.262845882Z
tags:
- pipeline
- dns
depends_on:
- 5m2
- 3t7
parent: 4k2
---

The runtime-only telemetry the pipeline emits at the log step, consumed later by the admin UI (E8). See SPEC §3.1, §3.2, §9.

## Deliverables
- Per-query **structured `tracing` event** to stdout (client, qname, qtype, detailed outcome, block source when applicable, upstream, latency, rcode) — the operator handles retention externally.
- A **bounded live-log ring buffer** + `tokio::sync::broadcast` channel: each query event is pushed to the buffer and published on the broadcast (one receiver per future SSE subscriber; the buffer seeds a freshly opened view).
- **Runtime stats** counters (atomics): total queries, blocked/cached/forwarded counts + ratio, and top-N domains + top-N clients (sharded/relaxed structure acceptable). Since-startup only (v0.1).

## Design notes
- All runtime-only; nothing persisted in v0.1 (no `query_log`/`stats` tables).
- Shared via `Arc`; readers (E8) get a consistent-enough snapshot (SPEC §3.2).
- Live-log entries must distinguish `BlockedByAdmin` vs `BlockedByBlocklist` and `Local`/`LocalNoData` vs `Forwarded`/`Cached`, so E8.7 can show only one-click actions that will actually take effect.

## Validation
- A processed query emits a tracing event, pushes a live-log entry on the broadcast, and updates the counters.
- The ring buffer is bounded (oldest evicted); a late subscriber sees recent history then live events.
- Top-N domains/clients computed correctly over a sequence of queries.
