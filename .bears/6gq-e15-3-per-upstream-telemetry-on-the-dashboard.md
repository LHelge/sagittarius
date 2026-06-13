---
id: "6gq"
title: E15.3 · Per-upstream telemetry on the dashboard
status: done
priority: P2
created: "2026-05-30T20:47:51.594000247Z"
updated: "2026-06-13T13:03:45.339939445Z"
tags:
  - web
depends_on:
  - y7h
parent: xa8
---

Show per-upstream health in the admin UI.

## Work
- A per-upstream table from E15.2's `snapshot()`: address/transport, query count, success rate, latency (EWMA / p50), last error.
- Place on the dashboard (or the upstreams page — pick the cleaner fit; the upstreams page already lists the configured resolvers, so augmenting it may read best).
- Server-rendered, refresh on navigation; reuse the `group()` formatter.

## Tests
- Renders per-upstream rows from a seeded stats snapshot.
- Sensible display for an upstream with zero queries (no divide-by-zero on success rate).