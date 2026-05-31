---
id: pcm
title: E10.1 · Schema & settings migration for query log
status: done
priority: P2
created: 2026-05-30T19:31:49.663136807Z
updated: 2026-05-31T15:28:08.628617761Z
tags:
- storage
parent: 55z
---

Add the durable `query_log` table, the retention/enable settings, and incremental auto-vacuum.

## Work

Create a **reversible** migration with `sqlx migrate add -r query_log` (never hand-create files; write a true inverse `.down.sql`).

**`query_log` table** (timestamps as INTEGER epoch per repo convention; booleans/CHECK per convention):
- `id INTEGER PRIMARY KEY AUTOINCREMENT` — chronological order + pagination cursor
- `ts INTEGER NOT NULL` — receipt time, **epoch milliseconds**
- `client TEXT NOT NULL` — client IP (no port)
- `qname TEXT NOT NULL`
- `qtype TEXT NOT NULL`
- `outcome TEXT NOT NULL` — stable token from `Outcome::as_str` (E10.2)
- `rcode INTEGER` — nullable
- `upstream TEXT` — nullable
- `latency_ms INTEGER NOT NULL`
- `CREATE INDEX idx_query_log_ts ON query_log (ts)` — for retention purge (pagination uses the PK, no extra index)

**settings** columns (singleton row gets defaults automatically via `ALTER TABLE … ADD COLUMN … DEFAULT`):
- `query_log_enabled INTEGER NOT NULL DEFAULT 1 CHECK (query_log_enabled IN (0,1))`
- `query_log_retention_days INTEGER NOT NULL DEFAULT 30`

`.down.sql`: drop the index + `query_log`, then drop the two settings columns.

**auto-vacuum**: set `.auto_vacuum(SqliteAutoVacuum::Incremental)` in `SqliteConnectOptions` in `storage/mod.rs::connect`. Only takes effect on a **fresh** DB; document that existing DBs keep their current mode.

Run `cargo sqlx prepare` and commit `.sqlx/`.

## Tests
- `query_log` table + all columns + `idx_query_log_ts` exist after migrate.
- New settings columns exist with defaults (1 / 30) on the seeded singleton row.
- `PRAGMA auto_vacuum` is `2` (incremental) on a freshly created DB.
- Down migration drops the table, index, and columns cleanly.