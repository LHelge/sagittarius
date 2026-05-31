---
id: rqp
title: E11.1 · Attributed blocklist structure + aggregator (primary source per domain)
status: done
priority: P2
created: 2026-05-30T19:54:33.957463770Z
updated: 2026-05-31T22:00:08.446949588Z
tags:
- blocklist
- dns
parent: cds
---

Make the blocklist remember, per domain, the **primary** source that put it there — without touching the hot path's behavior. No E10 dependency; can start in parallel.

## Blocklist structure (`src/resolver/matchset.rs` or a new sibling type)
- Introduce a map-backed blocklist (e.g. `AttributedSet` wrapping `ArcSwap<HashMap<Name, i64>>`, value = primary `blocklist_id`). **Blacklist and allowlist stay plain `MatchSet`** (`HashSet`).
- Hot-path API unchanged in spirit: keep a `contains(&Name) -> bool` (presence via `contains_key`) so `DecisionStack` is untouched and `Outcome` stays `Copy`/payload-free.
- Add `primary_source(&Name) -> Option<i64>` for the off-hot-path writer (E11.3).

## Aggregator (`src/blocklist/aggregate.rs`)
- Change `merged: HashSet<Name>` → `HashMap<Name, i64>`.
- `add(source_id, names)` does `entry.or_insert(source_id)` per name → **first writer wins**. Caller iterates enabled sources in **id order** (lowest id wins the tie = oldest-added list is primary). Document the tie-break.
- Keep the existing `SourceContribution` counts behavior (per-source `names.len()`).
- `install`/`into_parts` yield the map; the target stores it.

## Decision layer (`src/resolver/pipeline/layers.rs`)
- `state.blocklist().contains(&name)` keeps working as a presence check. Behavior and `Outcome::BlockedByBlocklist` are unchanged — existing layer tests must still pass untouched.

## state.rs
- `blocklist()` accessor returns the new attributed type.

## Tests
- Map membership + `contains` parity with the old set.
- A domain in two sources is attributed to the **lowest-id** source (tie-break).
- `primary_source` returns the expected id; `None` for non-members.
- Existing `DecisionStack` precedence tests pass unchanged.