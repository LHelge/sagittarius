---
id: cds
title: E11 · Per-list blocklist attribution & effectiveness
type: epic
status: done
priority: P2
created: 2026-05-30T19:54:20.808651667Z
updated: 2026-06-01T04:34:00.337872139Z
tags:
- blocklist
- telemetry
---

Record which blocklist source was responsible for each block, so the admin can see per-list effectiveness ("list X blocked N requests in the last 24h"). Builds on E10's persisted query log.

## Locked decisions

- **Attribution off the hot path.** Blocklist becomes a map keyed by `Name`; the decision layer (`DecisionStack`) stays a pure presence check and `Outcome` stays payload-free (`Copy`). The async query-log writer (E10.4) resolves the source.
- **Store a single stable `blocklist_id`** (nullable) per blocked `query_log` row. Stable across refreshes (it's the DB PK), trivial `GROUP BY`.
- **No source mask / no 64-list cap.** Because we persist only the *primary* source, the map value is simply the primary `blocklist_id` (an `i64`), computed first-writer-wins as the aggregator iterates enabled sources in id order (lowest id wins the tie). No bitmask, no bit→id table, no interface validation needed. (Trade: no easy path to overlap/"uniquely blocked by X" analysis — revisit with a junction table if ever wanted.)

## Implementation notes baked into the tasks

- **`blocklist_id` is a plain integer, not a hard FK.** A write-heavy `query_log` with cascade / `SET NULL` would erase historical attribution when a list is deleted. Storing the bare id (LEFT JOIN at read time; render unknown ids as "removed list") preserves history and keeps inserts cheap.
- **Eventual consistency:** the writer reads the current blocklist snapshot ~1s after the block, so a refresh in that window could shift attribution. Negligible for effectiveness telemetry — documented in E11.3.

## Already done (no work needed)
Enable/disable of blocklist sources without deletion already ships: `POST /blocklists/toggle`, `set_enabled`, and the scheduler's `list_enabled()` gate. A disabled list keeps its row + offline cache but drops out of the active set.

Tests live in each subtask. E11.1 has no E10 dependency and can start in parallel with E10.