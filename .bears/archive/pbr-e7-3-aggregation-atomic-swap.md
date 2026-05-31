---
id: pbr
title: E7.3 · Aggregation + atomic swap
status: done
priority: P1
created: 2026-05-29T07:47:21.182173111Z
updated: 2026-05-29T19:41:19.025147423Z
tags:
- blocklist
depends_on:
- 9x4
- zcf
parent: dqh
---

Merge all enabled sources into one deduplicated set and atomically swap it into the resolver's blocklist snapshot. See SPEC §3.1, §6.

## Deliverables
- Merge the parsed domains (E7.2) from all enabled sources, normalize, and **dedupe** into a single `HashSet<Name>`.
- Build the immutable snapshot and **atomically swap** it into E4.4's blocklist `MatchSet` (rebuild off the hot path; readers never block).
- Report per-source contributed counts (for E7.4 to persist and E8 to display).

## Design notes
- The blocklist set is **memory-only** (SPEC §3.1) — only source URLs + cached copies are persisted (E3.6).
- Uses E4.1's rebuild-and-swap semantics via the ResolverState (E4.4).

## Validation
- Dedupe across overlapping sources yields a single set with no duplicates.
- The swap installs the new set; a concurrent reader observes it consistently.
- Zero enabled sources → empty set (no panic).