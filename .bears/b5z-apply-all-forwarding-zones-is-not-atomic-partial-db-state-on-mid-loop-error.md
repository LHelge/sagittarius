---
id: b5z
title: "\"Apply all forwarding zones\" is not atomic — partial DB state on mid-loop error"
status: open
priority: P3
created: "2026-06-13T22:19:15.860036541Z"
updated: "2026-06-13T22:19:15.860036541Z"
tags:
  - forwarding
  - bug
---

## Problem

`AppState::apply_target_to_all` (`src/web/forward_zones.rs:144`) — the one-click
"forward all reverse zones to <router>" action — performs **two independent,
un-transacted** DB updates per zone:

```rust
for zone in repo.list().await? {
    repo.set_target(zone.id, Some(&target)).await?;
    repo.set_enabled(zone.id, true).await?;
}
self.rebuild_forward_zones().await
```

If a DB error occurs partway through the loop, the function returns early:
- the persisted `forward_zones` table is left **partially updated** (some zones
  targeted/enabled, others not, and a zone can even be half-updated: target set
  but not yet enabled), **and**
- `rebuild_forward_zones` (which swaps the live snapshot) never runs, so the
  **live resolver state is unchanged** — it diverges from what's persisted.

On the next restart, hydration builds the live set from the partial persisted
rows, silently **activating a configuration the admin never confirmed**.

## Severity

Low. SQLite is local so mid-loop write errors are rare, and the partial state
("some reverse zones forwarded to the router") is benign rather than dangerous.
Filed as a correctness/robustness follow-up, not release-blocking.

## Fix direction

Make the batch atomic. Transactions are already used elsewhere
(`src/storage/query_log.rs:237` uses `self.pool.begin()`), but the
`ForwardZoneRepository` trait methods each take their own connection. Add a
single transactional repo method — e.g. `apply_target_to_all(target)` (or a
generic "apply these (id,target,enabled) rows in one tx") — that begins a
transaction, performs every update, and commits, so the persisted state is
all-or-nothing. Then `rebuild_forward_zones` runs only after a successful
commit.

`forward_zone_set_target` / `forward_zone_toggle` are single-row and already
fine; only the multi-row apply-all path needs the transaction.

## Tests

- Apply-all commits every zone's (target, enabled) atomically on success.
- A simulated mid-batch failure leaves the persisted set unchanged (no partial
  rows) — i.e. rolls back.

## Context

Found in the 0.2.0 pre-release review (review/0.2.0 branch). Sibling deferred
findings: [[xsg]] (blocklist removal vs incomplete snapshot), plus DNS-0x20
case / RD passthrough on forward and the forward-zone cache-clear TOCTOU
(documented limitations).