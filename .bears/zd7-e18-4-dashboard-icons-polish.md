---
id: zd7
title: E18.4 — Dashboard icons + polish
status: open
priority: P2
created: "2026-06-13T14:59:04.472160628Z"
updated: "2026-06-13T14:59:04.472160628Z"
tags:
  - web
  - ui
depends_on:
  - vj4
parent: ag8
---

`templates/dashboard.html`: add icons to the stat-card labels / section headings
(Live cards lines 9-42, System lines 44-67, 24h lines 69-87) and the table
headers (top domains/clients 90-121, upstream health 123-151, top talkers
153-186). Tidy card spacing/typography in `assets/app.css` (`.sgt-card`,
`.sgt-cards`, `.sgt-label`). Keep the Pico pumpkin look.

Verify icons render and theme in light/dark at narrow + wide viewports.