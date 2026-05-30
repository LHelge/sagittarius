---
id: gug
title: E9.1 · Full binary assembly & wiring
status: done
priority: P2
created: 2026-05-29T08:05:03.686206455Z
updated: 2026-05-30T13:13:24.489299197Z
tags:
- integration
depends_on:
- 58n
- vhe
- tx4
- zcf
- zkb
parent: 8wg
---

Compose the whole product: the one place the binary wires every subsystem into a single running process. See SPEC §3, §10.

## Deliverables
- `app.run()` concurrently starts, sharing `ResolverState` / `AppState` via `Arc`:
  - startup hydration + E7.4's offline blocklist aggregation from SQLite cache,
  - the **DNS engine** — listeners + pipeline (E6.7),
  - the **web admin** — axum server (E8),
  - the **blocklist refresh scheduler** (E7.4),
- all spawned on the E1 runtime + **TaskTracker**, hydrated from SQLite at startup (E4.4), and wired to the E1 graceful-shutdown signal. DNS listeners start after DB hydration and cached blocklist aggregation, so saved config is active before serving.

## Design notes
- This is the cross-cutting assembly that no single upstream epic owns; each subsystem plugs into the E1 runtime seam.
- **Router scope:** this task wires the subsystem *seams* and mounts the admin server via the E8.1 router/`AppState`; the individual E8 screens (E8.5–E8.10) register their own routes onto that shared router as they are built. gug therefore depends only on the web foundation (E8.1) + wizard (E8.4); the *full* admin surface is required and exercised end-to-end in E9.2. If a screen's route isn't present yet, the binary still starts — E9.2 is where completeness is enforced.
- A failure to start one subsystem should fail startup clearly (typed error at the `main` boundary via `anyhow`).
- The **DNS engine serves immediately on startup** from seeded defaults, independent of whether an admin account exists; only the admin web UI is gated by the first-run wizard (E8.4).

## Validation
- The binary starts all three subsystems against a temp DB + ephemeral ports; the first-run wizard is reachable and DNS answers queries **even before any admin account exists**.
- `SIGTERM` / `SIGINT` drains DNS in-flight queries, the scheduler, and the web server, then exits 0 within the drain timeout.
