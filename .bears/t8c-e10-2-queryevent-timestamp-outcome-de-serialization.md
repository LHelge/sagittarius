---
id: t8c
title: E10.2 · QueryEvent timestamp + Outcome (de)serialization
status: open
priority: P2
created: 2026-05-30T19:31:57.026376849Z
updated: 2026-05-30T19:31:57.026376849Z
tags:
- telemetry
parent: 55z
---

Give `QueryEvent` an absolute timestamp and give `Outcome` a stable on-disk form. Pure in-memory/type work — no DB yet.

## Work

**Timestamp on `QueryEvent`** (`src/telemetry/event.rs`):
- Add `ts` field — receipt time as **epoch milliseconds** (`i64`).
- Set it where the event is constructed in `TelemetryService::call` (`src/resolver/pipeline/engine.rs`). Capture at request start (alongside the existing `Instant::now()` latency start). Add `Clock::now_millis()` to `src/time.rs` if it isn't there (only `now_secs()` exists today).
- Decide ergonomics: constructor param vs `with_ts` builder — match the existing `with_*` style.

**Stable `Outcome` (de)serialization** (`src/resolver/pipeline/mod.rs`):
- `Outcome::as_str(&self) -> &'static str` returning stable kebab tokens, distinct per variant:
  `blocked-admin`, `blocked-blocklist`, `cached`, `forwarded`, `local`, `local-nodata`, `refused`, `formerr`, `servfail`, `error`.
- `impl FromStr for Outcome` as the exact inverse (unknown token → error).
- **Leave `Display` unchanged** (it renders human labels for the UI); `as_str`/`FromStr` are the persistence format.

## Tests
- `as_str` → `FromStr` round-trips for **every** `Outcome` variant; unknown string errors.
- `as_str` tokens are all distinct.
- A `QueryEvent` built in the pipeline carries a non-zero `ts`.