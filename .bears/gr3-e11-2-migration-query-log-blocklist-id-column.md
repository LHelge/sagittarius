---
id: gr3
title: 'E11.2 · Migration: query_log.blocklist_id column'
status: open
priority: P2
created: 2026-05-30T19:54:38.261265749Z
updated: 2026-05-30T19:54:38.261265749Z
tags:
- storage
depends_on:
- pcm
parent: cds
---

Add the attribution column to the query log.

## Work
- Reversible migration (`sqlx migrate add -r query_log_blocklist_id`) adding `blocklist_id INTEGER` (nullable) to `query_log`.
- **Plain integer, no FK** — preserve historical attribution after a list is deleted, and keep inserts cheap on the write-heavy table. (Read path LEFT JOINs `blocklists` and renders unknown ids as "removed list".)
- No extra index initially: the effectiveness query is windowed (`WHERE ts >= ? GROUP BY blocklist_id`), covered by the existing `ts` index from E10.1.
- `.down.sql` drops the column.
- Run `cargo sqlx prepare`, commit `.sqlx/`.

## Tests
- Column exists and is nullable after migrate.
- Down migration drops it cleanly.