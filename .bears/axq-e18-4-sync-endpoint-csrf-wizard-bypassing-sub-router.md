---
id: axq
title: E18.4 — Sync endpoint + csrf/wizard-bypassing sub-Router
status: done
priority: P1
created: "2026-07-05T12:33:45.333593347Z"
updated: "2026-07-05T12:57:23.111653170Z"
tags:
  - secondary
  - web
  - sync
depends_on:
  - d7p
  - cdj
parent: b6b
---

GET /api/v1/config (ApiKeyAuth) in src/web/sync.rs: build ConfigSnapshot, compute version, honour If-None-Match:"<version>" => 304, else 200 with ETag:"<version>". In AppState::router (src/web/mod.rs:246) build api routes as separate Router and admin.merge(api).with_state(self) so csrf/wizard never see api traffic. Tests: missing/bad bearer 401, valid 200+ETag, repeat If-None-Match 304, wizard doesn't bounce /api/* on fresh DB.
Depends on E18.2 (extractor, in auth.rs) + E18.3.