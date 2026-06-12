---
id: z2e
title: Extract a generic hot-swap primitive under MatchSet/AttributedSet
status: done
priority: P3
created: "2026-06-12T23:03:14.983125291Z"
updated: "2026-06-12T23:19:13.756571046Z"
tags:
  - refactor
  - resolver
parent: cde
---

`resolver/matchset.rs` defines two near-identical ArcSwap wrappers: `MatchSet` (over `HashSet<Name>`) and `AttributedSet` (over `HashMap<Name, i64>`). They duplicate the full surface — `new/empty/contains/snapshot/load_full/len/is_empty/store/store_arc` plus `Default`, `Debug`, `FromIterator`. `LocalMatcher` (`local.rs`) and `SharedUpstreamPool` (`upstream/pool.rs`) repeat a smaller version of the same pattern.

**Change:** extract a generic core, e.g. `HotSwap<C>` providing `snapshot/load_full/store/store_arc/Default/Debug(len)`, and rebuild `MatchSet`/`AttributedSet` as thin wrappers that keep their current public names and domain-specific methods (`contains`, `primary_source`). The SPEC §3.2 no-torn-read doc lives once on the core.

**Scope decision at task start:** merging MatchSet + AttributedSet is the required minimum; migrating `LocalMatcher` / `SharedUpstreamPool` / `ResolverState.settings` onto the same core is optional — only do it if it stays a clear win (they have slightly different surfaces).

The concurrency test (`concurrent_store_and_contains_sees_consistent_snapshot`) and all existing API tests must pass unchanged.

Commit: `refactor(resolver): extract generic hot-swap core under the match sets`