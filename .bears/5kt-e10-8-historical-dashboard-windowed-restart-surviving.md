---
id: 5kt
title: E10.8 · Historical dashboard (windowed, restart-surviving)
status: open
priority: P2
created: 2026-05-30T19:33:10.373409282Z
updated: 2026-05-30T19:33:10.373409282Z
tags:
- web
depends_on:
- 6f3
parent: 55z
---

Add durable, windowed telemetry to the dashboard sourced from `query_log` (survives restart). **No charting library** — figures only.

## Work (`src/web/dashboard.rs` + template)
- Add a windowed section (e.g. **Last 24h**, optionally 7d) computed from `SqliteQueryLogRepo` aggregates (E10.3): total / blocked / cached / forwarded counts + top domains + top clients over the window.
- Keep the existing since-startup live counters (SSE `PatchSignals`) for the real-time cards — relabel clearly so "live since startup" vs "last 24h (persisted)" are distinguishable.
- Reuse the existing `group()` thousands formatter and `DomainDisplay` trimming.

## Tests
- Dashboard renders correct windowed counts and top-N from seeded `query_log` rows.
- Rows outside the window are excluded.
- Empty log → zeros, no panic.