---
id: y72
title: E3.5 · Lists & local-records repositories
status: open
priority: P1
created: 2026-05-29T06:55:34.120047211Z
updated: 2026-05-29T06:55:34.120047211Z
tags:
- storage
depends_on:
- '294'
parent: hga
---

Repositories for the admin blacklist, allowlist, and local DNS records. See SPEC §3.1, §4, §5.

## Deliverables
- `BlacklistRepository` / `AllowlistRepository` **traits** with `async fn` members (add, remove, list, bulk-read) + SQLite impls. Domain normalization consistent with the codec's `Name` normalization (lowercase, etc.).
- `LocalRecordRepository` trait + impl: CRUD over `local_records` including **wildcard** names (e.g. `*.home.lan`), record type, value, TTL. Treat uniqueness as `(name, type)` so a local name can hold both A and AAAA records.
- Bulk reads (`load_all`) for E4 to hydrate the `arc-swap` snapshots at startup (hydration itself is E4).
- Tests use ephemeral SQLite DBs.

## Validation
- CRUD + bulk-read round-trips for each repository.
- Duplicate-domain insert handled per the unique constraint.
- A wildcard local record stores and retrieves faithfully (incl. type + TTL); same name with A + AAAA round-trips as two records.
