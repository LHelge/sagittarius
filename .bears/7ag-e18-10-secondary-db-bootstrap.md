---
id: "7ag"
title: E18.10 — Secondary DB bootstrap
status: done
priority: P2
created: "2026-07-05T12:34:05.159353201Z"
updated: "2026-07-05T13:26:47.416464168Z"
tags:
  - secondary
depends_on:
  - q3j
parent: b6b
---

Fresh secondary DB runs all migrations (seed defaults) → serves DNS immediately before first sync; hydrate + load_from_cache unchanged; first sync overwrites config. No login until first sync mirrors users — verify/document. Mostly verification + small wiring in src/app.rs secondary branch.