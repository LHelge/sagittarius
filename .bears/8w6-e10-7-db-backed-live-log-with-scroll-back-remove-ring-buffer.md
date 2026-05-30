---
id: 8w6
title: E10.7 · DB-backed live log with scroll-back; remove ring buffer
status: open
priority: P2
created: 2026-05-30T19:33:25.264031947Z
updated: 2026-05-30T19:33:25.264031947Z
tags:
- web
depends_on:
- 6f3
- ync
parent: 55z
---

Make the live query log read history from SQLite while keeping the real-time tail over SSE, and retire the in-memory ring buffer.

## Work
- `/log` initial render: newest page from `SqliteQueryLogRepo::page(None, N)` (E10.3) instead of `LiveLog::recent()`.
- **Scroll-back**: new endpoint (e.g. `GET /log/older?before=<id>`) returning the next older page as a Datastar `PatchElements` **append** into `#log-body`. A "Load older" control carries the smallest currently-visible row `id` as the cursor.
- Row markup must carry the DB row `id` (cursor + de-dup across the live/history seam).
- `/events` SSE broadcast tail stays as-is for real-time prepends.
- **Remove the ring buffer** from `LiveLog` (`src/telemetry/live_log.rs`): keep only the `broadcast` sender/subscribe; drop `ring`, `capacity`, `recent()`, and `DEFAULT_CAPACITY`. Update `TelemetrySink::record`, the `query_log` handler, and tests accordingly.

## Seam note
Document the contract: history comes from the DB; the live stream covers "now" forward (existing "subscribe-then-render" semantics). The batch-writer lag (~1s) means the very newest events live in the broadcast before they hit the DB — that's fine, they render via the live tail; a manual refresh later shows them from the DB.

## Tests
- Initial `/log` page renders newest rows from the DB.
- `/log/older?before=` returns the next older slice with no overlap/gap.
- Live prepend still works over SSE after the ring removal.
- `LiveLog` no longer exposes a ring (`recent`/capacity gone); build + tests updated.