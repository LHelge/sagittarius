---
id: dhj
title: E3.1 · sqlx + SQLite connection layer
status: open
priority: P1
created: 2026-05-29T06:55:01.699056225Z
updated: 2026-05-29T06:55:01.699056225Z
tags:
- storage
depends_on:
- '783'
parent: hga
---

The connection layer: an async `sqlx` SQLite pool with sane pragmas, opened at the configured DB path, running embedded migrations on connect. See SPEC §4, §10.

## Deliverables
- `cargo add sqlx` with features `runtime-tokio`, `sqlite`, `macros`, `migrate`.
- A `Db`/`Storage` type wrapping a `SqlitePool`, constructed from a path (the runtime passes `Config.db_path` from E1.2):
  - `create_if_missing(true)`
  - `journal_mode(WAL)` (sqlx does not set WAL by default; set it explicitly)
  - `busy_timeout(...)` and `synchronous(NORMAL)`
  - foreign keys on (sqlx default, assert it)
  - modest pool size given SQLite's single writer.
- Run embedded migrations via `sqlx::migrate!` on connect. **Create the `migrations/` directory now and commit a placeholder file in it** (e.g. `migrations/.gitkeep`) — git does **not** track empty directories, and `sqlx::migrate!("./migrations")` is a **compile error if the directory is absent**, so a tracked placeholder is what makes E3.1 build standalone on a fresh clone/CI. E3.2 (which adds the actual DDL) depends on this task; once it lands, delete the placeholder. Until then the migrator is simply empty.

## Design notes
- Behaviour on the `Db` type (methods), not free functions (CLAUDE.md).
- Errors via the E1.1 `error` convention.

## Validation
- Connecting to a temp-file path creates the DB and applies migrations.
- WAL is active after connect; foreign keys enforced.
- A trivial query round-trips through the pool.