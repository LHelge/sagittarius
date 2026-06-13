---
id: vp7
title: E12.1 · Pause flag on ResolverState + hot-path gate
status: done
priority: P2
created: "2026-05-30T20:05:16.099967828Z"
updated: "2026-06-13T07:14:03.649626712Z"
tags:
  - dns
parent: kv7
---

Add the pause deadline to shared state and gate the decision stack on it.

## ResolverState (`src/resolver/state.rs`)
- New field `paused_until: AtomicI64` (0 = active). Initialise to 0 in `hydrate`.
- Methods (relaxed atomic ordering, consistent with `Stats`):
  - `pause_for_secs(secs: i64)` → store `Clock::now_secs() + secs`.
  - `resume()` → store `0`.
  - `blocking_paused() -> bool` → `Clock::now_secs() < paused_until` (and `paused_until != 0`).
  - `paused_until() -> Option<i64>` → `Some(deadline)` when in the future, else `None` (for the UI countdown).

## DecisionStack (`src/resolver/pipeline/layers.rs`)
- After **Stage 1 (local records)** — which must keep answering — insert a gate: if `state.blocking_paused()`, skip Stage 2 (blacklist), Stage 3 (allowlist), and Stage 4 (blocklist) and fall through to the inner service (cache → forward). Otherwise unchanged.

## Tests
- While paused: a blacklisted name and a blocklisted name both fall through to the stub (`Forwarded`), not blocked.
- While paused: a local record still answers `Outcome::Local`.
- Not paused: existing precedence behavior unchanged (existing tests pass).
- Expired deadline (set a past `paused_until`) → blocking active again.
- `paused_until()` returns `None` when not paused / expired, `Some` when active.