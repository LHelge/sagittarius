---
id: tqg
title: E8.3 · CSRF protection on mutating routes
status: open
priority: P1
created: 2026-05-29T07:57:13.540873330Z
updated: 2026-05-29T07:57:13.540873330Z
tags:
- web
- auth
depends_on:
- 5kh
parent: p6b
---

Protect all state-changing requests from cross-site abuse. See SPEC §9 (CSRF), §11.

## Deliverables
- A CSRF layer applied to **every mutating route** (POST/PUT/PATCH/DELETE):
  - `SameSite` cookies (already `Strict` on the session cookie from E8.2),
  - a **session-bound anti-CSRF token** issued to rendered pages and required on mutating requests (sent via a custom header — e.g. Datastar `data-headers` — or a form field),
  - **Origin / Referer** validation against the browser-facing admin origin. Derive it from the request host/scheme in simple local mode, and from trusted reverse-proxy headers (`X-Forwarded-Proto` / `X-Forwarded-Host`) only when that deployment path is configured/documented.
- A helper to embed the token in Askama templates / Datastar requests.

## Design notes
- Token bound to the session (E8.2); rotate on login.
- Cookie policy and origin handling share the same browser-facing scheme/host helper so `auto` secure cookies and CSRF origin checks agree behind Caddy/Traefik.
- All one-click + management mutations (E8.7–E8.10) go through this layer.

## Validation
- A mutating request with a missing/invalid token is rejected (403).
- A request with a valid token + matching origin passes.
- A cross-origin request (bad Origin/Referer) is rejected.
