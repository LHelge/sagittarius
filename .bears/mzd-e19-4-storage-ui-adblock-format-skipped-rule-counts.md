---
id: mzd
title: "E19.4 · Storage + UI: adblock format, skipped-rule counts"
status: done
priority: P2
created: "2026-08-30T12:18:13.112044350Z"
updated: "2026-08-30T13:24:27.388423061Z"
tags:
  - blocklist
  - web
  - storage
depends_on:
  - "9kf"
  - xff
parent: "8j5"
assignee: opencode
attempts: 1
---

Epic: E19. Surface the `adblock` format and parse/skip accounting in storage and the admin UI. Depends on E19.1 and E19.2.

## Current state

- `src/storage/blocklists.rs` — `BlocklistFormat` (strum TEXT), row CRUD; `entry_count` column holds the source's deduped domain count, persisted by the scheduler from `SourceContribution`.
- `src/web/blocklists.rs` + templates — subscription management: add/remove/enable, manual refresh, per-list effectiveness (windowed block counts, E11).
- Database: SQLite, migrations under `migrations/` (reversible pairs), compile-time-checked queries verified against `.sqlx/`.

## Requirements

1. **Format option.** The add/edit blocklist form gains `adblock` in the format selector; the default fetch/parse path (scheduler) handles it via the existing `Parser::from(BlocklistFormat::AdBlock)` dispatch. Seeded lists are unchanged.

2. **Skip accounting.** Persist per-source unsupported-rule counts so the UI can show them after restart:
   - New column `blocklists.skipped_count INTEGER NOT NULL DEFAULT 0` via `sqlx migrate add -r <name>` (true inverse in `.down.sql`).
   - Scheduler writes it alongside `entry_count` from the contribution data (E19.2).
   - **Regenerate the `.sqlx` cache** and commit it with the change (AGENTS.md gotcha) — `cargo sqlx prepare -- --all-targets`; CI's `sqlx-cache` job will fail otherwise.

3. **UI.** Blocklists page per-list row shows parsed vs skipped (e.g. "62,410 rules · 118 skipped"); a non-zero skipped count gets a subtle indicator (icon + tooltip or inline note) explaining unsupported rule types were ignored. Keep Pico/askama/Datastar conventions — no new JS.

4. **Secondary sync.** Confirm the config snapshot (SPEC §13.3) already mirrors the `format` column (it mirrors source definitions wholesale) so a secondary applies `adblock` lists with no extra work; add a test if the snapshot serializer enumerates formats explicitly.

5. Tests: storage round-trip of the new column, migration up/down, form accepts/rejects formats as today, UI render shows counts (template test if one exists).

Quality gate per AGENTS.md; commit `.sqlx/` alongside.