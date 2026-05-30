---
id: y7h
title: E15.2 · Per-upstream health & latency stats
status: open
priority: P2
created: 2026-05-30T20:47:40.653857587Z
updated: 2026-05-30T20:47:40.653857587Z
tags:
- upstream
- telemetry
depends_on:
- x3v
parent: xa8
---

Aggregate per-upstream health in memory so the dashboard (E15.3) and the latency-weighted selector (E15.4) have data to use.

## Work
- A per-upstream tracker (keyed by upstream addr/index) recording, on **every** forward attempt (success *and* failure): an EWMA (and/or p50) latency, success/failure counters, and last-error.
- Updated inside `UpstreamPool::forward` using the per-attempt measurements from E15.1.
- Expose a `snapshot()` (like `telemetry::Stats`) returning per-upstream rows. In-memory only; resets on restart.
- Keep it lock-light (atomics / small mutex per upstream); this is on the forward path but the forward path already awaits the network, so a tiny update is negligible.

## Tests
- Successful attempts update latency EWMA + success count for the right upstream.
- Failed/timed-out attempts increment the failure count (and don't corrupt latency).
- Snapshot reports per-upstream rows with sane values.