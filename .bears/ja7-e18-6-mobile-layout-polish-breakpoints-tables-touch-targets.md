---
id: ja7
title: E18.6 — Mobile layout polish (breakpoints, tables, touch targets)
status: done
priority: P2
created: "2026-06-13T14:59:14.529815108Z"
updated: "2026-06-13T17:04:25.311425840Z"
tags:
  - web
  - ui
depends_on:
  - tny
parent: ag8
---

Round out responsiveness in `assets/app.css`: breakpoints for the paused banner
(`.sgt-paused`), pause dropdown (`.sgt-pause-*`), forms, and stat cards; ensure
≥44px touch targets. Make dense management tables mobile-friendly — baseline is
the existing `.sgt-table-wrap{overflow-x:auto}`; consider stacked/responsive rows
for the worst offenders (log, upstream health) or keep horizontal scroll with
clear affordance.

Verify at ~375px: no horizontal page overflow, controls tappable, tables usable.