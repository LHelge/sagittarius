---
id: tqc
title: E14.2 · Render hostnames in live log + top-clients
status: open
priority: P2
created: 2026-05-30T20:24:30.745948259Z
updated: 2026-05-30T20:24:30.745948259Z
tags:
- web
depends_on:
- akd
- 8w6
- 5kt
parent: tcb
---

Display hostnames (with IP fallback) in the admin UI, resolved from the E14.1 cache at render time.

## Work
- **Live log** (E10.7, `web/live_log.rs`): each row shows `hostname (ip)` or just the IP when no hostname is cached. Resolve per row's client IP from E14.1.
- **Top clients** (E10.8 dashboard): label each entry with its hostname, IP fallback. Group/aggregate still by IP; hostname is display-only, resolved once per distinct IP.
- Keep it cheap: a handful of distinct IPs per view; never block rendering on a live lookup (use cached value, fall back to IP, let the cache warm asynchronously).

## Tests
- A row / top-client with a cached hostname renders `hostname (ip)`.
- No cached hostname → bare IP, no error.
- Aggregation remains keyed by IP (two names for one IP don't split the count).