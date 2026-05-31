---
id: mk2
title: E8.10 · Blocklist source management + manual refresh
status: done
priority: P1
created: 2026-05-29T07:57:59.493022497Z
updated: 2026-05-29T21:57:50.424339370Z
tags:
- web
depends_on:
- tqg
- dyd
- tx4
parent: p6b
---

The blocklist subscription management screen. See SPEC §9, §6.

## Deliverables
- A page to **add / remove / enable-disable** blocklist sources (URL + format), write-through to E3.6.
- A **manual "refresh now"** button that fires the E7.4 on-demand refresh trigger.
- Surface per-source **entry count** and **last-updated** (from E3.6 metadata), plus refresh status/errors.
- CSRF-protected (E8.3).

## Design notes
- Enabling/disabling or adding a source should schedule (or trigger) a refresh so the in-memory set reflects the change.

## Validation
- Source CRUD persists; enable/disable respected on the next aggregation.
- "Refresh now" triggers E7 and the per-source counts + last-updated update in the UI.
- A failing source surfaces an error without breaking the page or clobbering the live set.