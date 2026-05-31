---
id: 55z
title: E10 · Persistent query log & historical telemetry
type: epic
status: done
priority: P2
created: 2026-05-30T19:31:36.273077353Z
updated: 2026-05-31T16:10:41.192119719Z
tags:
- telemetry
- storage
---

Persist per-query events in SQLite (replacing the in-memory ring buffer) to give a better live query log and durable, restart-surviving dashboard telemetry. Targets the **next release** (v0.1.0 is already shipped; this is post-MVP feature lock-in).

## Core principle

**The DNS response path must never wait on a DB write.** Today `TelemetrySink::record` runs on the response path (in `TelemetryService::call`). The new design decouples persistence:

```
hot path → sink.record() → mpsc.try_send(event)   [non-blocking; drop + count if full]
                                   │
                                   ▼
            dedicated writer task: batch N events / flush every ~1s
                                   │
                                   ▼
            single INSERT-many transaction → SQLite
```

The in-memory `broadcast` channel still powers the **live** tail (zero DB dependency); SQLite powers **history** and **dashboards**.

## Locked decisions (agreed before breakdown)

- **Live log**: DB-backed history (keyset pagination by rowid) + scroll-back; broadcast keeps the live tail. **The 1000-entry ring buffer is removed** — one source of truth for history.
- **Dashboard**: windowed counts + top domains/clients from the DB (survive restart). **No charting library this epic** (time-series charts are a follow-up).
- **Purge**: hourly task, batched deletes by `ts`, `PRAGMA incremental_vacuum` after. Retention in days (default 30). `auto_vacuum=INCREMENTAL` set on connect (effective for fresh DBs; existing DBs documented as "space reused, not returned" — no scheduled full VACUUM, which locks the whole DB).
- **Privacy**: `query_log_enabled` toggle (default ON) + `query_log_retention_days` (default 30) + a "Clear query log now" action.

## Notes

- `QueryEvent` has **no timestamp** today (the ring relied on insertion order) — E10.2 adds one.
- Storage already runs WAL + `synchronous=NORMAL` + busy-timeout; batching is the remaining write-throughput win.
- New table + compile-time queries → **`cargo sqlx prepare`** and commit `.sqlx/` (E10.1, E10.3).
- SPEC §4/§9/§11/§12 deferred this and flagged the privacy posture; E10.9 updates them.

Tests live in each subtask per the project's "test to lock in behavior" convention.