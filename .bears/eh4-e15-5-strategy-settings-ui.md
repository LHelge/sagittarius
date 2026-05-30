---
id: eh4
title: E15.5 · Strategy settings + UI
status: open
priority: P2
created: 2026-05-30T20:48:07.426395245Z
updated: 2026-05-30T20:48:07.426395245Z
tags:
- web
- storage
depends_on:
- ge8
parent: xa8
---

Let the admin choose the upstream selection strategy.

## Storage / settings
- Reversible migration adding `upstream_selection_strategy TEXT NOT NULL DEFAULT 'random' CHECK (... IN ('random','latency-weighted','parallel'))` and `upstream_parallel_fanout INTEGER NOT NULL DEFAULT 2` to `settings`. `cargo sqlx prepare`.
- Extend `Settings` + `SettingsRow` + `RuntimeSettings`.

## Wiring
- Map the setting → the concrete `UpstreamSelector` / parallel mode when (re)building the pool; rebuild/swap the `SharedUpstreamPool` on change (mirror the existing upstream-edit pool rebuild).

## UI
- A control on the upstreams/settings page: strategy dropdown + parallel fan-out (shown when `parallel`). CSRF-protected; persist then swap.

## Tests
- Settings round-trip incl. the new fields + defaults.
- Selecting a strategy rebuilds the pool with the matching selector/mode.
- Migration up/down clean.