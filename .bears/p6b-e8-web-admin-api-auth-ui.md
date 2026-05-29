---
id: p6b
title: E8 · Web admin (API, auth, UI)
type: epic
status: done
priority: P1
created: 2026-05-28T22:38:36.964929565Z
updated: 2026-05-29T21:57:50.424493372Z
tags:
- web
depends_on:
- hga
- rbn
- 4k2
- dqh
---

The operator's control surface — an authenticated `axum` app with server-rendered Askama pages, Datastar/SSE interactivity, and Pico CSS — covering setup, configuration, live monitoring, and one-click list management. See SPEC §9.

**Scope**
- `axum` server bound to `--admin-addr`; shared `tower` middleware; honours E1 graceful shutdown.
- Auth: Argon2id password hashing, custom opaque session cookies with hashed tokens in SQLite, login/logout; **CSRF protection** on all mutating routes (SameSite + token + origin checks). Session cookie `Secure` handling follows the `auto | always | never` deployment policy from SPEC §9/§10.
- First-run wizard: when `admin_users` is empty, force creation of the initial admin (username/password) before unlocking the UI; everything else uses seeded defaults.
- Embedded assets: Datastar JS, Pico CSS, custom stylesheet, favicon/images via `include_str!`/`include_bytes!` — no CDN, no Node build.
- Dashboard: runtime stats (total queries, blocked ratio, top domains/clients) from the E6 counters.
- Live query log: SSE stream from the live-log broadcast/ring buffer; filtering; **one-click** Whitelist (blocklist-blocked rows → allowlist) / Blacklist (forwarded/cached resolved rows → admin blacklist) that writes through to E3 and swaps the E4 sets. Rows where the action would be ineffective (admin-blacklist blocks, local answers) do not show that one-click action.
- Management screens: blocklist sources (add/remove/enable, manual refresh → E7), manual blacklist/allowlist, local DNS records (incl. wildcards), upstream resolvers, settings.

**Design notes**
- Askama compile-time templates render full pages + fragments; Datastar merges fragments/signals; one SSE stream can update the log and dashboard together (SPEC §9).
- Serves plain HTTP behind a reverse proxy for TLS; binds loopback by default.
- Handlers as methods on typed router/state modules.

**Out of scope**
- Built-in TLS / ACME (future); time-series charts (future); per-client policies (future).

**Validation**
- Auth flow tests (login, session expiry, logout); wizard appears only when `admin_users` is empty.
- CSRF rejection tests on mutating endpoints.
- SSE endpoint delivers live events; a one-click action persists to the DB and is reflected in the in-memory set.
- e2e against HTTP endpoints for each management screen.
