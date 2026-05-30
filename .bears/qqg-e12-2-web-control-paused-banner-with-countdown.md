---
id: qqg
title: E12.2 · Web control + paused banner with countdown
status: open
priority: P2
created: 2026-05-30T20:05:26.902914505Z
updated: 2026-05-30T20:05:26.902914505Z
tags:
- web
depends_on:
- vp7
parent: kv7
---

Expose pause/resume in the admin UI.

## Routes (`src/web/`, new handler module e.g. `blocking.rs`)
- `POST /blocking/pause` — body carries the duration (preset seconds or a custom value); calls `state.resolver.pause_for_secs(secs)`; log it.
- `POST /blocking/resume` — calls `state.resolver.resume()`; log it.
- Both **CSRF-protected**, mirroring the existing state-changing POSTs (see `web/lists.rs` / `web/blocklists.rs` patterns).
- Register routes in `web/mod.rs`.

## UI
- Navbar control: a small menu/buttons for **5 m / 30 m / 1 h / custom** + **Resume now**.
- Paused banner: "Blocking paused — resumes in MM:SS", shown whenever `paused_until()` is `Some`. Drive the countdown **client-side with Datastar** (seed seconds-remaining into a signal); when it reaches 0, clear the banner (optionally reload). Carry pause state via `Chrome` so `base.html` can render the banner on every page.

## Optional (nicety)
- A small `sleep_until(deadline)` task (spawned/replaced on each pause) that logs "blocking resumed" and could push an SSE banner-clear. Not required — correctness is handled by E12.1's comparison.

## Tests
- `POST /blocking/pause` sets a future deadline (assert via `state.resolver.blocking_paused()` / `paused_until()`); `/blocking/resume` clears it.
- State-changing routes reject missing/invalid CSRF.
- Banner renders when paused, absent when active.