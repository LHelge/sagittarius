---
id: dqh
title: E7 · Blocklist ingestion & refresh
type: epic
status: open
priority: P1
created: 2026-05-28T22:38:29.954422483Z
updated: 2026-05-28T22:44:28.236167639Z
tags:
- blocklist
depends_on:
- hga
- rbn
---

Turn subscribed blocklist URLs into the in-memory blocklist set — fetch, parse, dedupe, and refresh in the background with atomic swaps, surviving restarts offline. See SPEC §6.

**Scope**
- Source subscription model (persisted in E3): URL, format, enabled flag, metadata (entry count, last-updated, ETag/Last-Modified).
- Fetcher with conditional requests (ETag/Last-Modified); store the fetched copy in SQLite so startup works offline.
- Parsers: **hosts** format (`0.0.0.0 example.com`) and **domain-list** (one per line); ignore comments/blank lines. AdBlock-style parsing is future scope, not v0.1.
- Aggregation: merge all enabled sources, normalize, dedupe into one set, then **atomically swap** it into E4's blocklist snapshot.
- Background refresh scheduler: periodic (configurable interval) + on-demand trigger; a failed refresh keeps the last good snapshot.
- Per-source counts and last-updated surfaced for the UI (E8).

**Design notes**
- The blocklist set is memory-only; only source URLs + cached copies are persisted (SPEC §3.1, §6).
- The scheduler is a background task per E1's task model and uses E4's `arc-swap` for the update.

**Out of scope**
- Subdomain/parent blocking (future); the source-management UI (E8); the admin blacklist/allowlist (E3/E4/E8).

**Validation**
- Parser unit tests per format (incl. malformed lines and comments).
- Aggregation/dedupe tests across multiple sources.
- Scheduler test: a refresh installs a new snapshot via atomic swap; a failed fetch retains the previous one.
- Offline-start test: the set is built from the SQLite-cached copy with no network.
