---
id: 5kh
title: 'E8.2 · Auth: Argon2id + sessions repository + login/logout'
status: done
priority: P1
created: 2026-05-29T07:57:04.434822048Z
updated: 2026-05-29T21:13:35.989937742Z
tags:
- web
- auth
depends_on:
- vhe
- '294'
parent: p6b
---

Authenticated admin access: Argon2id password hashing, the (deferred) `admin_users`/`sessions` repositories, and login/logout with a custom lightweight session (opaque random token, hashed at rest — no third-party session framework). See SPEC §9, §11.

## Deliverables
- `cargo add argon2`. Hash + verify admin passwords with **Argon2id**, PHC strings, **pinned params m = 19456 KiB (19 MiB), t = 2, p = 1** (OWASP); constant-time verify via `PasswordVerifier`.
- The **`admin_users` and `sessions` repositories** (traits + SQLite impls) deferred from E3 — typed, compile-time-checked queries. These are the only new compile-time `sqlx` queries added **after** the E3.7 offline gate, so re-run `cargo sqlx prepare --workspace --all-targets` and **commit the updated `.sqlx/`**, or CI's `cargo sqlx prepare --check` fails (CLAUDE.md).
- **Custom sessions:** a random 256-bit token, **stored hashed** in `sessions`; set in a session cookie with `HttpOnly`, `SameSite=Strict`, and `Path=/`. Lifetimes: **idle 7 days, absolute 30 days**. Session lookup as an axum extractor; expiry + logout invalidation.
- Implement E1.2's `SessionCookieSecurePolicy`:
  - `auto` (default): set `Secure` and use cookie name **`__Host-sgt_session`** when the browser-facing scheme is HTTPS (directly, or via trusted `X-Forwarded-Proto: https`); omit `Secure` and use **`sgt_session`** for direct plain-HTTP local/loopback use,
  - `always`: always set `Secure` and use `__Host-sgt_session`,
  - `never`: never set `Secure` and use `sgt_session`; log a warning, especially if admin bind is not loopback.
- Login + logout handlers/pages; unauthenticated access to protected routes redirects to login.

## Design notes
- Session tokens are opaque random IDs (no hand-rolled crypto); Argon2id is only for passwords. Store a hash of the token, not the raw token, so a DB read can't mint sessions.
- The `__Host-` prefix is only legal with `Secure`, `Path=/`, and no `Domain`; never use the prefixed name in insecure/plain-HTTP mode. This keeps browser prefix rules correct while still allowing release builds to run directly over local HTTP when explicitly or automatically configured.
- `X-Forwarded-Proto` should only be trusted when the admin interface is deployed behind a trusted reverse proxy; document this in the auth module and deployment docs.

## Validation
- Login with correct creds succeeds; wrong password rejected (and timing-safe).
- A valid session authorizes protected routes; an expired/invalidated session does not.
- Logout invalidates the session; unauthenticated request → redirect to login.
- Cookie policy tests: `auto` on HTTPS/X-Forwarded-Proto sets `Secure` + `__Host-`; `auto` on plain HTTP uses unprefixed insecure cookie; `always`/`never` force the expected behaviour.
