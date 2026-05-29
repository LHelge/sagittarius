---
id: dyd
title: E3.6 · Blocklist-source & offline-cache repository
status: open
priority: P1
created: 2026-05-29T06:55:39.511423935Z
updated: 2026-05-29T06:55:39.511423935Z
tags:
- storage
depends_on:
- '294'
parent: hga
---

Storage for blocklist subscription sources and their offline-cached contents. Storage only — fetching/parsing/aggregation is E7. See SPEC §6.

## Deliverables
- A `BlocklistRepository` **trait** with `async fn` members + SQLite impl covering:
  - source CRUD: URL, format (hosts / domain-list), enabled flag,
  - refresh metadata: entry_count, last_updated, ETag, Last-Modified (for conditional requests in E7),
  - offline cache: store/retrieve the fetched copy in `blocklist_cache` so startup works without network.
- Tests use ephemeral SQLite DBs.

## Design notes
- The aggregated in-memory blocklist *set* is owned by E4 and populated by E7; this epic persists only source definitions + cached copies (SPEC §3.1, §6).

## Validation
- Source CRUD round-trips; enable/disable; hosts/domain-list format enum maps both ways.
- Conditional-refresh metadata (ETag/Last-Modified/entry_count/last_updated) persists and re-reads.
- Cached contents store and retrieve; an offline read returns the last-saved copy.
