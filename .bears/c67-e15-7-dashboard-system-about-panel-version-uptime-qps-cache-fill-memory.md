---
id: c67
title: E15.7 · Dashboard system/about panel (version, uptime, qps, cache fill, memory)
status: open
priority: P2
created: "2026-06-13T12:42:58.638063850Z"
updated: "2026-06-13T12:42:58.638063850Z"
tags:
  - web
parent: xa8
---

A "System" section on the dashboard for at-a-glance server health. Folded into E15 (user request) so it ships alongside the per-upstream health table (E15.3) as one coherent dashboard PR. **Dependency-free** — does not need the E15.1/.2 upstream foundation, so it can be built first or with E15.3.

## Cards (all app-native, no new crates)
- **Version** — `env!("CARGO_PKG_VERSION")`, server-rendered.
- **Uptime** — capture a monotonic start `Instant` (or epoch-secs) in `AppState` at construction; seed seconds into a Datastar signal and tick client-side (reuse the `data-on-interval` pattern from E12's pause banner). No new SSE plumbing.
- **Queries/sec** (since startup) — compute client-side as `$queries / uptimeSecs`, reusing the already-streamed `$queries` signal ÷ the client-side uptime ticker.
- **Process memory (RSS)** — read `/proc/self/statm` (Linux is the only supported target per `deploy/install.sh`); no crate. Point-in-time on page load. Format human-readable (MB).
- **Cache fill** — moka `entry_count()` / `cache_capacity` (expose `entry_count()` on `DnsCache`; capacity is already in `RuntimeSettings`). On page load.

## Explicitly out of scope
- Host CPU/RAM (decided: monitor with other tools; avoids a `sysinfo` dependency and the container-misreporting footgun).
- Upstream health belongs to E15.3, not here.

## Tests
- Template renders version/uptime/memory/cache cards from a seeded view model.
- RSS reader returns a plausible non-zero value on Linux (guard/skip on non-Linux); cache-fill handles capacity with zero entries (no divide-by-zero on percentage).

## Docs
- E15.6 should also note the System panel in SPEC §9 / README.