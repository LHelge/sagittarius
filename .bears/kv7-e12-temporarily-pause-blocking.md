---
id: kv7
title: E12 · Temporarily pause blocking
type: epic
status: open
priority: P2
created: 2026-05-30T20:05:06.751142929Z
updated: 2026-05-30T20:05:06.751142929Z
tags:
- dns
- web
---

Let the admin pause all DNS blocking for a chosen duration (5 min / 30 min / 1 h / custom), with a "Resume now" control — Pi-hole's "disable blocking," time-boxed.

## Locked decisions

- **Pause disables all blocking** — admin blacklist *and* blocklists stand down while paused. **Local records still answer** (they sit above the blocking stages and are authoritative).
- **Timed flag, not state mutation.** A `paused_until: AtomicI64` on `ResolverState` (0 = active). `DecisionStack` checks it once and skips the blocking stages while `now < paused_until`. **Auto-resumes by comparison** — the next query after the deadline blocks again; no timer needed for correctness. The blocklist set is never touched (no data loss, no network/refresh to restore, no clash with the refresh scheduler).
- **In-memory only** → a restart resumes blocking (fail-safe). The deadline is not persisted.
- Durations **5 m / 30 m / 1 h + custom**, plus **Resume now**.

## Notes

- Independent of E10/E11 — no shared dependencies; could be implemented first.
- While paused, would-be-blocked queries resolve and log as `Forwarded`/`Cached` (accurate). Documented; no dependency on E10.
- The optional `sleep_until(deadline)` task is a nicety (log "blocking resumed" / clear the banner), not required for correctness.

Tests live in each subtask.