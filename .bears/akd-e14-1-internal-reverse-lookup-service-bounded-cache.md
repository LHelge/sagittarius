---
id: akd
title: E14.1 · Internal reverse-lookup service + bounded cache
status: open
priority: P2
created: 2026-05-30T20:24:21.842901695Z
updated: 2026-05-30T20:24:21.842901695Z
tags:
- telemetry
- dns
depends_on:
- e5x
- 2pd
parent: tcb
---

A component that resolves client IP → hostname through Sagittarius's own resolution path and caches the result.

## Work
- Given an `IpAddr`, issue a PTR query through the internal engine so **private IPs resolve via E13** (local PTR synth / conditional forwarding) and public IPs via the normal upstream.
- Cache `IpAddr → Option<Name>` in a bounded, TTL'd store (moka), with **negative caching** (remember "no hostname") and periodic refresh, so a chatty log never hammers the router.
- Off the hot path — invoked lazily by the render layer (E14.2) for distinct client IPs, or by a small background warmer. No DNS-response-path involvement.

## Tests
- A known local IP resolves to its hostname (via a test engine wired to E13).
- Result is cached; repeated lookups don't re-query.
- Unknown IP is negatively cached; cache is bounded.