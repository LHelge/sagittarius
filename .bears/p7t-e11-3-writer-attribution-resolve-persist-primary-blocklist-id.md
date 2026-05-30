---
id: p7t
title: 'E11.3 · Writer attribution: resolve & persist primary blocklist_id'
status: open
priority: P2
created: 2026-05-30T19:54:47.638947454Z
updated: 2026-05-30T19:54:47.638947454Z
tags:
- telemetry
- storage
depends_on:
- rqp
- gr3
- ync
parent: cds
---

Wire attribution into the off-hot-path writer and persist it.

## Work
- `QueryLogRecord` (E10.3) gains `blocklist_id: Option<i64>`; `insert_batch` persists it.
- The query-log writer task (E10.4) gets access to the blocklist handle (pass `Arc<ResolverState>` or just the attributed blocklist `Arc` into the writer at wiring time in `app.rs`).
- For events with `outcome == BlockedByBlocklist`, resolve `state.blocklist().primary_source(&qname)` (E11.1) and set it on the record. All other outcomes → `None`.
- **Eventual consistency:** the lookup uses the current snapshot (~1s after the block); a refresh in that window could shift attribution. Acceptable for effectiveness telemetry — leave a comment saying so. A name blocked-by-blocklist will normally still be present unless a refresh removed it in the gap (→ `None`, fine).

## Tests
- A `BlockedByBlocklist` event for a domain in source S persists `blocklist_id = S`.
- Non-blocklist outcomes persist `NULL`.
- A blocked domain absent from the current snapshot persists `NULL` without error.