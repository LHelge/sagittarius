---
id: qzr
title: E18.3 — Icons in navigation
status: done
priority: P2
created: "2026-06-13T14:58:58.649284182Z"
updated: "2026-06-13T16:50:49.407645404Z"
tags:
  - web
  - ui
depends_on:
  - vj4
  - tny
parent: ag8
---

Add a leading icon to each of the 8 nav links in `templates/base.html:25-34`
using the icon macro (dashboard→LayoutDashboard/Gauge, log→ScrollText/List,
blacklist→ShieldBan, allowlist→ShieldCheck, local→Server, blocklists→ListChecks,
upstreams→Globe, settings→Settings). Add icons to the pause/logout controls.

`assets/app.css`: adjust `.sgt-nav a` for icon+label alignment and gap; ensure
the mobile drawer (E18.2) shows icon+label cleanly and the active-link accent
recolors the icon (`currentColor`).