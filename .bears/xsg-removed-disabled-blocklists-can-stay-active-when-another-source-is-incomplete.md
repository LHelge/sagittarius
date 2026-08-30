---
id: xsg
title: Removed/disabled blocklists can stay active when another source is incomplete
status: open
priority: P2
created: "2026-06-13T22:08:05.558137516Z"
updated: "2026-06-13T22:08:05.558137516Z"
tags:
  - blocklist
  - bug
---

## Problem

A blocklist removal or disable can silently fail to take effect.

`refresh_once` (`src/blocklist/scheduler.rs:393`) rebuilds the aggregate from
the currently-enabled sources, but discards the **entire** new snapshot if
**any** source is `Incomplete` — a failed fetch with no usable cache
(`scheduler.rs:413-418`):

```rust
let contributions = if complete_snapshot {
    aggregator.install(self.state.blocklist())
} else {
    warn!("refresh: incomplete snapshot; keeping existing live blocklist");
    Vec::new()
};
```

That all-or-nothing guard exists to avoid erasing domains on a transient fetch
loss, but it also blocks a legitimate **removal**: when the admin removes/disables
source A and a *different* still-enabled source B is `Incomplete` on the same
refresh, the old live set — still containing A's domains — is kept. A's domains
stay blocked indefinitely, for as long as B keeps failing without a cache. No
error is surfaced to the admin.

Removal/toggle handlers only update the DB then `refresh.trigger()`
(`src/web/blocklists.rs:182-207`), so they rely entirely on `refresh_once`
applying the shrink.

## Trigger (narrow)

All three at once:
1. Remove/disable a blocklist, **and**
2. another enabled source fails to fetch on that refresh, **and**
3. that source has **no usable cache** (never fetched successfully — e.g. a
   freshly-added dead/typo'd URL).

Any source that has ever fetched has a cache and falls back to `Complete`, so
this needs a never-cached failing peer. Self-heals once that peer succeeds once.
Low frequency, but the symptom ("I deleted this list but its domains are still
blocked") is silent and confusing.

## Fix direction

Make carry-over **per-source, keyed on the current enabled set**, instead of the
whole-snapshot guard: a source that is no longer in the enabled set must never
carry over, even within an incomplete snapshot. Only sources that are still
enabled *and* transiently unavailable should retain their last-good contribution.

## Tests

- Removal applies even when an unrelated enabled source is `Incomplete`.
- Existing guard still holds: a transiently-failing *enabled* source with no
  cache retains its prior domains (no erase on transient loss).

## Context

Found in the 0.2.0 pre-release review (review/0.2.0 branch). Not release-blocking
— filed as a standalone follow-up. Sibling review findings deferred as documented
limitations: DNS-0x20 case / RD passthrough on forward, and the sub-second
forward-zone cache-clear TOCTOU.