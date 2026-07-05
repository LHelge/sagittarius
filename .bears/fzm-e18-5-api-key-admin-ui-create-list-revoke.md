---
id: fzm
title: E18.5 — API-key admin UI (create/list/revoke)
status: done
priority: P2
created: "2026-07-05T12:33:46.816376523Z"
updated: "2026-07-05T12:49:17.869429678Z"
tags:
  - secondary
  - web
depends_on:
  - cdj
parent: b6b
---

New templates/apikeys.html, src/web/apikeys.rs: GET /apikeys (list), POST /apikeys/create (show plaintext once, never re-shown), POST /apikeys/revoke. Follow src/web/blocklists.rs (askama + Datastar + csrf write-through). Nav link in templates/base.html; key glyph in src/web/icons.rs. Tests mirror blocklist_sources_manage_over_http.