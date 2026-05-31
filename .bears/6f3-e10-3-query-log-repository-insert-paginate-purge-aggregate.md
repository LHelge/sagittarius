---
id: 6f3
title: E10.3 · query_log repository (insert, paginate, purge, aggregate)
status: done
priority: P2
created: 2026-05-30T19:32:11.831532822Z
updated: 2026-05-31T15:45:26.080717146Z
tags:
- storage
depends_on:
- pcm
- t8c
parent: 55z
---

New `src/storage/query_log.rs`: `QueryLogRepository` trait + `SqliteQueryLogRepo` (mirror the existing repo pattern: trait + `Sqlite*Repo`, compile-time `query!`/`query_as!`). Register the module in `storage/mod.rs`.

## Types
- `QueryLogRecord` — one row (id, ts, client, qname, qtype, outcome, rcode, upstream, latency_ms), with mapping from `QueryEvent` (uses `Outcome::as_str` from E10.2). Client stored as the IP string.

## Methods
- `insert_batch(&[QueryLogRecord]) -> Result<()>` — **single transaction** for the whole batch.
- `page(before: Option<i64>, limit: i64) -> Result<Vec<QueryLogRecord>>` — keyset pagination, newest-first: `WHERE (?before IS NULL OR id < ?before) ORDER BY id DESC LIMIT ?`. `before = None` → newest page.
- `purge_older_than(cutoff_ts_ms: i64, batch_limit: i64) -> Result<u64>` — bounded delete (`DELETE FROM query_log WHERE id IN (SELECT id FROM query_log WHERE ts < ? ORDER BY id LIMIT ?)`), looped by the caller until it returns 0; returns rows removed per call.
- `incremental_vacuum() -> Result<()>` — `PRAGMA incremental_vacuum;`.
- `clear_all() -> Result<()>` — `DELETE FROM query_log;`.
- Windowed aggregates for the dashboard (all `WHERE ts >= ?since_ms`):
  - `counts_since(since_ms) -> { total, blocked, cached, forwarded }`
  - `top_domains_since(since_ms, n) -> Vec<(String, i64)>`
  - `top_clients_since(since_ms, n) -> Vec<(String, i64)>`

Run `cargo sqlx prepare` and commit `.sqlx/`.

## Tests
- insert_batch then `page(None, …)` returns rows newest-first; `page(Some(cursor), …)` returns the next older slice with no overlap/gap.
- `purge_older_than` removes only rows older than the cutoff and returns the count; idempotent once drained.
- aggregates compute correct totals/top-N over a window and ignore older rows.
- `clear_all` empties the table.