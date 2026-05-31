---
id: zkb
title: E8.4 · First-run wizard
status: done
priority: P1
created: 2026-05-29T07:57:32.552844071Z
updated: 2026-05-29T21:26:40.433718848Z
tags:
- web
- auth
depends_on:
- 5kh
- tqg
parent: p6b
---

A one-step first-run wizard that creates the initial admin account before the web UI unlocks. See SPEC §9, §10.

## Deliverables
- When `admin_users` is empty, **all admin-UI routes** redirect to the wizard, which collects only a username + password and creates the first admin (Argon2id via E8.2).
- Once an admin exists, the wizard is inaccessible and normal login applies.

## Design notes
- The wizard gates **only the admin web UI**. The **DNS resolver serves from boot** using the seeded defaults (upstreams, cache, blocklists) regardless of whether an admin account exists — creating the admin only unlocks the web UI.
- The wizard form is CSRF-protected (E8.3).
- No other configuration is collected here — defaults come from seeds (SPEC §10).

## Validation
- With an empty `admin_users`, any admin-UI route shows the wizard; submitting creates the admin and unlocks the UI.
- DNS queries are answered normally **before** the admin account is created (only the UI is locked).
- With an existing admin, the wizard is not reachable (redirects to login).
- The created admin can log in immediately afterwards.