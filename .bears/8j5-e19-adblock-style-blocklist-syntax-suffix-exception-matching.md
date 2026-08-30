---
id: "8j5"
title: E19 · AdBlock-style blocklist syntax (suffix + exception matching)
type: epic
status: open
priority: P2
created: "2026-08-30T12:14:50.914219960Z"
updated: "2026-08-30T12:14:50.914219960Z"
tags:
  - blocklist
  - dns
  - epic
---

Add **AdBlock-style blocklist syntax** — the subset of Adblock Plus filter rules that maps onto Sagittarius's domain-oriented blocking model — without giving up the O(1)-per-probe hot path (SPEC §5, §6, §12).

## Design summary (agreed with the maintainer)

Real-world AdBlock lists are overwhelmingly `||domain^` suffix rules, not regex. So the blocklist becomes a **three-tier matching stack**; every tier stays hash-based, no scan, no trie (the reversed-label trie of §3.1/§12 stays future scope):

- **Tier 1 — exact rules.** Plain domains (as today) → the existing aggregated `Name → primary blocklist_id` map (`AttributedSet`).
- **Tier 2 — `||domain^` suffix rules.** The stripped domain goes into a second same-shaped set. A match walks the query name's labels and probes per candidate suffix (`a.b.example.com` → probe `a.b.example.com`, `b.example.com`, `example.com`), each an O(1) hash lookup, bounded by the label count. The matched entry's `blocklist_id` is the attribution.
- **Tier 3 — penalty box (rejected in this epic).** True in-pattern wildcards (`*`), `/regex/`, and option-carrying rules (`$third-party`, `$domain=…`, …) are **not matched** — they are counted as *skipped* per source and surfaced in the UI. Parsing never becomes fatal.

Exceptions: `@@||domain^` maps onto the existing allow-bypass concept — suppresses **blocklist** matches (Tier 1 + 2) for the name and its subdomains, never the admin blacklist. This mirrors existing allowlist precedence (SPEC §5).

Scope guardrails:

- The admin blacklist / allowlist stay exact-match; unchanged.
- The `hosts` and `domain-list` formats keep their current behaviour exactly.
- Aggregation merges across all enabled sources regardless of format, preserving first-writer-wins (ascending `blocklist_id`) attribution.
- Hot-path budget: exact probe (1) + suffix walk (≤ label count) + exception walk on match only. No allocation on the decision path.

## Subtasks

1. **AdBlock parser** (`src/blocklist/parse.rs`, `BlocklistFormat`): parse `||domain^`, `@@||domain^`; skip+count everything else. New `BlocklistFormat::AdBlock` (`strum` serialize `"adblock"`).
2. **Aggregated snapshot extension** (`src/resolver/matchset.rs`, `src/blocklist/aggregate.rs`): carry exact + suffix + exception sets (each attributed); O(labels) `contains` walk.
3. **Decision layer + attribution** (`src/resolver/pipeline/layers.rs`, query-log writer): blocklist stage consults the suffix walk; exceptions suppress; blocked rows log the matched rule's `blocklist_id`.
4. **Storage + UI**: `"adblock"` format option in the blocklist form; per-list parsed/skipped rule counts (needs a reversible migration + `.sqlx` cache regen).
5. **SPEC/README + e2e**: update §6 (and §12 note), e2e coverage of suffix block / exception / skip-counting.

Implementation must follow AGENTS.md (quality gate order, Conventional Commits, PR workflow, sqlx-cache rules).