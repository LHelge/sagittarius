---
id: q3r
title: E11.4 · Per-list effectiveness view (windowed block counts)
status: done
priority: P2
created: 2026-05-30T19:54:55.396099425Z
updated: 2026-06-01T04:31:51.395192299Z
tags:
- web
depends_on:
- p7t
parent: cds
---

Surface per-list effectiveness in the admin UI.

## Repo (`src/storage/query_log.rs`)
- `block_counts_by_source_since(since_ms) -> Vec<(Option<i64>, i64)>` — count of `BlockedByBlocklist` rows grouped by `blocklist_id` over the window.

## Web (`src/web/blocklists.rs` + template)
- On the **blocklists management page**, show each subscribed source with its windowed block count (e.g. "blocked N in last 24h") and its share of total blocklist blocks. LEFT JOIN `blocklists`; rows whose `blocklist_id` no longer matches a live source render as "removed list".
- Reuse the `group()` thousands formatter; keep it server-rendered (refresh on navigation), consistent with the rest of the blocklists page.

## Tests
- Aggregate groups counts by source over the window and excludes older rows.
- Page renders per-list counts from seeded `query_log` rows; unknown ids shown as "removed list".
- Empty log → zeros, no panic.