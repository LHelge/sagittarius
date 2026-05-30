---
id: x5m
title: E10.5 · Hourly retention/purge task + incremental vacuum
status: open
priority: P2
created: 2026-05-30T19:33:04.686117793Z
updated: 2026-05-30T19:33:04.686117793Z
tags:
- storage
depends_on:
- 6f3
- 5xc
parent: 55z
---

Background subsystem that keeps the query log within its retention window and returns freed pages to disk.

## Task
- New `spawn_subsystem("query-log-purge", …)` in `src/app.rs`, modelled on the blocklist scheduler's `tokio::select!` loop (timer arm + cancellation arm).
- Interval const `PURGE_INTERVAL` (default **1 hour**). Run one purge shortly after startup too.
- Each cycle:
  1. Read `query_log_retention_days` from the live `RuntimeSettings` snapshot (E10.6) — picks up changes without restart.
  2. `cutoff_ms = now_ms - retention_days*86_400_000`.
  3. Loop `purge_older_than(cutoff_ms, BATCH)` (E10.3) until it returns 0 — bounded deletes so the write lock is never held long.
  4. `incremental_vacuum()` to return freed pages (works because E10.1 set `auto_vacuum=INCREMENTAL` on fresh DBs).
- Log a summary (rows removed) per cycle.

## Tests
- Old rows removed, recent rows kept, for a given retention.
- Empty table / nothing-to-purge → no error, returns promptly.
- Honors a changed retention value from the settings snapshot.
- Cancellation exits the loop promptly.