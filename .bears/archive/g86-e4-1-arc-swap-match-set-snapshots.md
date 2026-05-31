---
id: g86
title: E4.1 · arc-swap match-set snapshots
status: done
priority: P1
created: 2026-05-29T07:11:05.108512506Z
updated: 2026-05-29T13:27:44.747270891Z
tags:
- dns
- cache
depends_on:
- nq7
parent: rbn
---

Lock-free, hot-swappable match sets for the admin blacklist, allowlist, and aggregated blocklist set. See SPEC §3.1, §3.2.

## Deliverables
- `cargo add arc-swap`.
- A `MatchSet` type wrapping `ArcSwap<HashSet<Name>>` (normalized `Name` from E2.2):
  - cheap atomic **`contains`** lookup via `load` (hot path never blocks),
  - a **rebuild-and-swap** writer that constructs the fresh `HashSet` *off* the hot path and atomically stores it.
- Used for three independent sets: admin blacklist, allowlist, and the aggregated blocklist set (the latter filled by E7).

## Design notes
- Readers never block; writers swap whole immutable snapshots — no reader sees a torn/partial set (SPEC §3.2).
- This provides only the per-set lookup primitive; cross-set **precedence/ordering lives in the E6 tower stack**, not here.

## Validation
- Lookup hit/miss against a populated set.
- A swap installs a new set atomically and is observed by subsequent loads.
- Concurrency test: under concurrent readers + a writer swap, every reader observes a consistent (never torn) snapshot.