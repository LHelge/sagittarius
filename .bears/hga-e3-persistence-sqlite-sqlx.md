---
id: hga
title: E3 · Persistence (SQLite + sqlx)
type: epic
status: open
priority: P1
created: 2026-05-28T22:38:06.046909766Z
updated: 2026-05-29T06:54:55.398762930Z
tags:
- storage
depends_on:
- p3k
---

A single SQLite file as the system of record for all configuration, accessed through compile-time-checked `sqlx` with embedded migrations, so a fresh database is immediately usable. See SPEC §4, §10.

**Scope**
- `sqlx` setup (SQLite, async pool); WAL mode and sane pragmas; one DB file at `--db-path`.
- Schema migrations embedded via `sqlx::migrate!`:
  - `settings` — **typed single-row** table (`CHECK(id=1)`), not key/value, leaning on Rust's strong types for compile-time-checked access (cache bounds, blocking mode + custom IP, refresh interval, UI prefs).
  - `upstreams` — **dedicated table** for upstream resolver definitions (`address`, `transport` enum udp/tcp/dot/doh, `tls_server_name` nullable, `enabled`, `sort_order`). *(Upstreams are a list, so they get their own table rather than being folded into `settings`.)*
  - `admin_users`, `sessions` — created here; their **repository/CRUD lives in E8** alongside Argon2id hashing + session logic.
  - `blocklists` (sources), plus a `blocklist_cache` table for offline-cached fetched contents.
  - `blacklist`, `allowlist`, `local_records`.
- Seed-defaults migration, kept **separate** from schema DDL and **idempotent** (`INSERT … ON CONFLICT DO NOTHING`): Cloudflare `1.1.1.1` / `1.0.0.1` upstreams, default cache bounds, default sinkhole response.
- **Repository trait pattern**: each repository is a trait with `async fn` members, implemented by the SQLite-backed type. Tests use **ephemeral SQLite DBs** (no mocking needed); the trait keeps the seam open. `FromRow`/`TryFrom` for row ↔ domain mapping; behaviour on types, not free functions.
- Startup load: repositories expose bulk reads that E4 hydrates the in-memory structures from (hydration itself lives in E4).
- Committed `.sqlx` offline query cache; E3.7 turns on `SQLX_OFFLINE=true` in CI once all compile-time sqlx queries are captured so no DB is needed to compile.

**Design notes**
- **Dev-DB setup for compile-time queries (read before starting any repository task):** `sqlx`'s `query!`/`query_as!` are checked against a live schema at compile time. *Until E3.7 commits the `.sqlx/` offline cache*, each repository task (E3.4/E3.5/E3.6) needs a dev database to compile: set `DATABASE_URL=sqlite://<dev.db>` (e.g. in a local `.env`), create the file, and run the migrations (E3.2/E3.3) against it once — then `query!`/`query_as!` will type-check. After E3.7, builds use `SQLX_OFFLINE=true` + `.sqlx/` and no DB is needed. Whenever you add or change a query, re-run `cargo sqlx prepare` and commit `.sqlx/` (CLAUDE.md).
- Seed inserts live in their own migration so re-running never clobbers user-changed values (SPEC §4 "Seed defaults", §10 bootstrapping).
- Config-only for v0.1 — no `query_log`/`stats` tables (deferred with charts).
- SQLite is single-writer; keep the pool modest and rely on `busy_timeout`.

**Out of scope**
- Query-history persistence and stats tables (post-MVP).
- Blocklist fetching/parsing logic (E7) — only the storage of sources and cached copies belongs here.
- Auth logic (Argon2id, session issuance) — E8; only the `admin_users`/`sessions` tables live here.

**Validation**
- Tests run migrations against a temp DB and assert schema + seed rows (default upstreams present).
- CRUD round-trips for each repository (against an ephemeral SQLite DB).
- `cargo build` succeeds offline against the committed `.sqlx` cache.
