---
id: be4
title: E18.2 — ApiKeyAuth extractor
status: done
priority: P1
created: "2026-07-05T12:33:38.742637816Z"
updated: "2026-07-05T12:46:11.829310427Z"
tags:
  - secondary
  - web
depends_on:
  - cdj
parent: b6b
---

src/web/auth.rs next to CurrentUser (:280): ApiKeyAuth FromRequestParts<AppState>. Read Authorization: Bearer {id}.{token}; db.api_keys().find_active(id); constant-time verify token hash; throttled touch_last_used. Rejection = 401 (plain/JSON, not /login redirect). Small ApiKey value type owning parse/verify like SessionCookie.