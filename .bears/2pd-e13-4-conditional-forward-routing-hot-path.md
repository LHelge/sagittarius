---
id: 2pd
title: E13.4 · Conditional-forward routing (hot path)
status: open
priority: P2
created: 2026-05-30T20:23:58.736362293Z
updated: 2026-05-30T20:23:58.736362293Z
tags:
- dns
depends_on:
- gkd
parent: s2e
---

Route queries whose name falls under an enabled forward zone to that zone's target instead of the default upstream pool.

## Zone forwarders
- Build per-zone forwarders from `forward_zones.list_enabled()` (a hickory UDP/TCP client to each zone's target). Hold in shared state behind `arc-swap`, rebuilt when the config changes (mirror how upstreams/blocklist snapshots swap).

## Routing (`src/resolver/pipeline/layers.rs` / forward path)
- After local records + local PTR synth (E13.2), and **before** blacklist/blocklist (you don't block your own reverse zones), suffix-match the qname against enabled zones (most-specific wins, like the local wildcard probe).
- On match: forward to that zone's target; use the cache normally. On no match: continue the normal pipeline unchanged.
- Order so a local PTR answer (E13.2) wins over forwarding.

## Tests
- A query under an enabled zone forwards to the zone's target (mock upstream) and is cached.
- A non-matching name falls through to the normal pipeline.
- A disabled zone (or NULL target) is ignored.
- Most-specific zone wins when two zones overlap.