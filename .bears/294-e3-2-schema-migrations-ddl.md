---
id: '294'
title: E3.2 · Schema migrations (DDL)
status: open
priority: P1
created: 2026-05-29T06:55:13.476610921Z
updated: 2026-05-29T08:18:26.128468697Z
tags:
- storage
depends_on:
- dhj
parent: hga
---

Embedded schema migrations creating all v0.1 configuration tables. See SPEC §4 (decisions: typed `settings`, dedicated `upstreams`).

## Deliverables
Migration(s) under `migrations/` (picked up by `sqlx::migrate!`) creating:
- `settings` — **typed single-row** table with a `CHECK(id = 1)` guard; columns for cache min/max TTL, **negative-TTL cap**, cache capacity, blocking mode (nxdomain / null-ip / custom), custom block IP, blocklist refresh interval, UI prefs.
- `upstreams` — `id`, `address`, `transport` (udp/tcp/dot/doh), `tls_server_name` (nullable), `enabled`, `sort_order`.
- `admin_users` — username, password hash (Argon2id, populated by E8), role, timestamps. *(Table only; repository/CRUD in E8.)*
- `sessions` — session id, **token hash** (store the hash, not the raw token), user FK, created, expires. *(Table only; logic in E8.)*
- `blocklists` — source URL, format (`hosts` / `domain-list` in v0.1), enabled, entry_count, last_updated, etag, last_modified.
- `blocklist_cache` — fetched contents per source for offline start (FK → `blocklists`).
- `blacklist`, `allowlist` — domain (unique), timestamps.
- `local_records` — name (incl. wildcard), type, value, ttl.

Add sensible constraints/indexes: unique domain on blacklist/allowlist; unique (name, type) on local_records; FK `blocklist_cache.blocklist_id → blocklists.id`.

## Design notes
- Keep DDL migrations separate from the seed migration (E3.3).
- Migrations are additive and ordered; never edited once shipped.
- No `query_log` / `stats` tables in v0.1 (SPEC §4).

## Validation
- Migrations apply cleanly on a temp DB.
- Schema assertions: every table, key column, constraint, and index present.
- A second migrate run is a no-op (idempotent ordering).
