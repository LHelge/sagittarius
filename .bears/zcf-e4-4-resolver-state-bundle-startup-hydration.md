---
id: zcf
title: E4.4 · Resolver-state bundle + startup hydration
status: done
priority: P1
created: 2026-05-29T07:11:37.960923384Z
updated: 2026-05-29T13:50:09.489760763Z
tags:
- dns
- cache
depends_on:
- g86
- jve
- p8x
- beg
- y72
parent: rbn
---

A cohesive `ResolverState` that bundles the match sets, local-record matcher, and cache, shared via `Arc` and hydrated from SQLite at startup. See SPEC §3.1, §3.2.

## Deliverables
- `Arc<ResolverState>` holding: blacklist / allowlist / blocklist `MatchSet`s (E4.1), the local-record matcher (E4.2), the `moka` cache (E4.3), and a hot-swappable `RuntimeSettings` snapshot.
- Build the cache with bounds derived from `Settings` (E3.4): min/max TTL clamp + capacity. Store cache TTL bounds, negative-TTL cap, blocking mode/custom IP, and blocklist refresh interval in `RuntimeSettings`.
- **Startup hydration** from the E3 repositories:
  - blacklist / allowlist / local records loaded via the lists repo (E3.5),
  - settings via the settings repo (E3.4) into both cache construction and `RuntimeSettings`,
  - the blocklist set starts **empty** (E7 fills it on first refresh).
- Expose:
  - the per-set lookup methods the E6 layers call,
  - the **swap** methods E7 (blocklist refresh) and E8 (admin edits/settings changes) use to install fresh snapshots, including runtime settings.

## Design notes
- This is the shared hot-path state the DNS engine and web admin both hold by `Arc` (SPEC §3.2).
- Precedence/ordering is **not** here — that's the E6 layer composition. Blocking mode/custom IP are runtime settings read by E6/E2.5 at synthesis time.

## Validation
- Hydrate from an ephemeral DB: match sets + local records reflect the rows; cache bounds and runtime settings taken from settings.
- A swap (simulating an admin edit / refresh) updates the live snapshot observed by a concurrent reader.
- A runtime-settings swap changes what new synthesis/cache-store operations observe without rebuilding the resolver state.
- Blocklist set is empty immediately after hydration (pre-refresh).
