---
id: xff
title: "E19.2 · AttributedSet: suffix + exception tiers with O(labels) match walk"
status: done
priority: P2
created: "2026-08-30T12:17:09.373223409Z"
updated: "2026-08-30T13:12:03.280098686Z"
tags:
  - blocklist
  - dns
depends_on:
  - "9kf"
parent: "8j5"
assignee: opencode
attempts: 1
---

Epic: E19. Extend the aggregated blocklist snapshot to carry **exact + suffix + exception** sets with attribution, and make the hot-path decision an O(labels) hash-walk. Depends on E19.1's `ParsedRules` shape.

## Current state

- `src/resolver/matchset.rs` — `AttributedSet`: `Name → primary blocklist_id` map behind `ArcSwap`; `contains(&Name)` (presence, hot path) and `primary_source(&Name)` (off-hot-path attribution).
- `src/blocklist/aggregate.rs` — `Aggregator::add(source_id, HashSet<Name>)`, first-writer-wins, `install(&AttributedSet) -> Vec<SourceContribution>`; sources fed in ascending `blocklist_id` order by the scheduler.
- `src/blocklist/scheduler.rs` — feeds the aggregator from parsed sources.

## Requirements

1. Extend `AttributedSet` (or introduce a sibling snapshot type it wraps) with three attributed maps:
   - `exact: Name → blocklist_id` (today's map),
   - `suffix: Name → blocklist_id` (from `||domain^` rules),
   - `exceptions: Name → blocklist_id` (from `@@||domain^`).
   Keep `store()` whole-snapshot swap semantics; empty install clears all three.

2. Hot-path decision API. Replace/augment `contains(&Name)` with something like `match_name(&Name) -> Option<Decision>` where `Decision` is `Block { source: i64 }` / `Exception { source: i64 }`. Semantics:
   - Exact probe first (1 hash).
   - Then suffix walk: strip leftmost labels, probing the `suffix` map (`a.b.example.com` → 3 probes). First (most-specific) hit wins.
   - Exception walk runs **only when** an exact/suffix hit was found (same label walk against `exceptions`, most-specific wins) — an exception over a match means the name is allowed (return an exception decision rather than block).
   - No allocation; bounded by label count. Document the budget in the type's docs.

3. Aggregation: `Aggregator` accepts `ParsedRules` per source (E19.1). Attribution stays first-writer-wins **within each tier** (lowest id wins overlap). Cross-tier: a rule in two sources' suffix tiers dedupes to the first; a name that is exact in one source and suffix in another exists in both tiers — the decision layer's exact-first order resolves it. `SourceContribution` must also carry the source's skipped count (E19.1) and per-tier counts as needed by E19.4.

4. Keep `primary_source()` working for existing call sites (query-log writer, dashboard per-list effectiveness) — extend it to resolve the matched decision's source instead of only exact-map lookups.

5. Tests as executable spec: tier precedence (exact beats suffix beats nothing), most-specific suffix wins, exception suppresses both tiers for the name and its subdomains, attribution across overlapping sources, whole-swap clears stale entries in all three tiers, no-panic on empty installs. Add a small benchmark-style smoke test if a pattern exists already; otherwise keep it test-only.

No pipeline changes in this task — the layer still calls the old API until E19.3.