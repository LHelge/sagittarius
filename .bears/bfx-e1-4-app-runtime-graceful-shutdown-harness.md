---
id: bfx
title: E1.4 · App runtime & graceful-shutdown harness
status: open
priority: P1
created: 2026-05-29T06:00:26.010768179Z
updated: 2026-05-29T08:17:04.384246892Z
tags:
- foundation
- runtime
depends_on:
- 7nu
- 3t7
parent: p3k
---

The `app` runtime that owns shared state, wires (stubbed) subsystems, and shuts down cleanly. See SPEC §10 ("Graceful shutdown"), §3.2.

## Deliverables
- An `App`/runtime type built from `Config` (E1.2); owns:
  - a `CancellationToken` (shutdown signal), and
  - a `TaskTracker` (in-flight drain), both from `tokio-util`.
- Signal handling: `SIGTERM` + `SIGINT` via `tokio::signal` → cancel the token → stop accepting → `TaskTracker::close()` + `wait()` bounded by a configurable **drain timeout (default 10 s)** → exit `0`.
- A `run()` that spawns placeholder subsystem tasks (no real DNS/web/storage yet — just tasks that observe the token and exit on cancel), demonstrating the drain path end to end.
- Clones of the token + tracker handed to subsystems so each later epic plugs in without changing the harness.
- Log a shutdown line when draining begins and when drain completes/times out.

## Design notes
- `CancellationToken` + `TaskTracker` chosen over a hand-rolled broadcast (current tokio idiom).
- This is the seam E5 (upstream), E6 (pipeline/listeners), E7 (refresh scheduler), and E8 (web) all attach to.

## Validation
- Integration test: start the runtime, trigger the token (or send the signal), assert it drains within the timeout and returns `Ok`.
- Test that a task exceeding the drain timeout is bounded — the timeout fires and the runtime still returns (process exits).
- Manual: `Ctrl-C` / `kill -TERM` exits 0 after logging a shutdown line.