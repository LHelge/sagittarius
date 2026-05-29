---
id: wus
title: E3.3 · Seed-defaults migration (idempotent)
status: open
priority: P1
created: 2026-05-29T06:55:22.270896024Z
updated: 2026-05-29T08:18:26.146982518Z
tags:
- storage
depends_on:
- '294'
parent: hga
---

A separate, idempotent migration that seeds working defaults so a fresh DB is usable with no first-run logic. See SPEC §4 ("Seed defaults"), §10.

## Deliverables
- A migration kept **separate** from the schema DDL (E3.2), seeding with `INSERT … ON CONFLICT DO NOTHING`:
  - **default upstreams:** Cloudflare `1.1.1.1` and `1.0.0.1` (transport `udp` for v0.1 default),
  - the single `settings` row with these **pinned defaults**:
    - cache min TTL `1` s, max TTL `86400` s, negative-TTL cap `3600` s, capacity `100000` entries,
    - **blocking mode `null-ip`** (the chosen default sinkhole response → `0.0.0.0` / `::`), custom block IP null,
    - blocklist refresh interval `86400` s (24 h).
- Must never clobber a value the admin later changed (that's why inserts are idempotent and live apart from DDL).

## Design notes
- Re-running all migrations on startup must be safe and non-destructive.
- These are starting points; all are editable via the admin UI (SPEC §4).

## Validation
- Fresh DB contains exactly the seed rows (both default upstreams present, one settings row with the pinned defaults).
- Simulate an admin edit → re-run migrations → the edited value is preserved (ON CONFLICT DO NOTHING holds).