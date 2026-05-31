---
id: 6jr
title: 'E10.9 · Docs: SPEC + README for persistent query log'
status: done
priority: P2
created: 2026-05-30T19:33:35.741115467Z
updated: 2026-05-31T16:10:41.191976848Z
tags:
- docs
depends_on:
- 5xc
- x5m
- 8w6
- 5kt
parent: 55z
---

Bring the docs in line with the now-persisted query log. v0.1.0 is released; this feature is part of the **next release**, so move it out of the future/roadmap framing.

## SPEC.md
- **§12 Roadmap**: move "Durable query-log storage with configurable retention" out of *Later (future)*. Keep historical time-series **charts** as future (this epic ships figures, not charts).
- **§4 Data model**: promote `query_log` from "Deferred to post-MVP" to a live table; document its columns + the retention/enable settings. (Leave `stats` materialized-aggregates deferred.)
- **§3.1**: update the "live-log buffer" description — it's now a `broadcast` tail plus DB-backed history; the ring buffer is gone. Adjust the architecture diagram note if needed.
- **§9**: live log is persisted + paginated; dashboard has windowed (restart-surviving) figures; document the enable toggle, retention, and clear-log action.
- **§11 Security**: revise the privacy posture — query events are now **persisted** with configurable retention and an opt-out toggle; spell out the operator/privacy implications (was: "nothing is persisted by the application").

## README.md
- Mention the persistent query log, retention setting, and that the live log/dashboard now survive restart.

## Tests
- None (docs only); confirm SPEC ↔ README stay consistent.