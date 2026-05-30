---
id: uka
title: 'E15.6 · Docs: SPEC + README for upstream selection & health'
status: open
priority: P2
created: 2026-05-30T20:48:13.988987734Z
updated: 2026-05-30T20:48:13.988987734Z
tags:
- docs
depends_on:
- 6gq
- ge8
- eh4
parent: xa8
---

Document upstream selection strategies + health telemetry.

## SPEC.md
- **§7 Upstream resolution**: selection strategies (random / latency-weighted / parallel) and the per-attempt latency + which-upstream-answered tracking. Update the "chosen at random" language.
- **§9**: per-upstream health table in the admin UI.
- **§3.1**: per-upstream health stats as runtime-only state; note `QueryEvent.upstream` is now populated.

## README.md
- Mention selectable upstream strategies + per-upstream stats.

## Tests
- None (docs only); keep SPEC ↔ README consistent.