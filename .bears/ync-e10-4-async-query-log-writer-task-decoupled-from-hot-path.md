---
id: ync
title: E10.4 · Async query-log writer task (decoupled from hot path)
status: open
priority: P2
created: 2026-05-30T19:32:58.137874735Z
updated: 2026-05-30T19:32:58.137874735Z
tags:
- telemetry
depends_on:
- t8c
- 6f3
- 5xc
parent: 55z
---

Persist events without ever blocking the DNS response path.

## TelemetrySink (`src/telemetry/event.rs`)
- Add a **bounded** `tokio::sync::mpsc::Sender<QueryEvent>` (capacity const, e.g. 4096).
- In `record`: gate on `query_log_enabled` (read from `ResolverState`/`RuntimeSettings`, E10.6) — when off, do **not** enqueue. When on, `try_send`; on `Full`, bump a `dropped: AtomicU64` and emit a rate-limited `warn!` (never block, never `.await`).
- Keep `emit()`, `stats.record()`, and the `broadcast` publish exactly as today.

## Writer task (new)
- Owns the `Receiver` + an `SqliteQueryLogRepo` (E10.3).
- Loop: accumulate up to BATCH (e.g. 256) via `recv_many`, or flush every FLUSH_INTERVAL (~1s), whichever first → `insert_batch` (one txn).
- On `CancellationToken` cancel: **drain remaining events and do a final flush** before returning.

## Wiring (`src/app.rs`)
- Build the channel when constructing `TelemetrySink`; `spawn_subsystem("query-log-writer", …)` so it joins the `TaskTracker` drain.

## Tests
- Events enqueued via `record` appear in the DB after a flush.
- Channel-full path drops and increments the counter; DNS path returns without awaiting.
- Cancellation drains the buffer (no lost tail on graceful shutdown).
- `query_log_enabled = false` → nothing enqueued/written; stats + broadcast still fire.