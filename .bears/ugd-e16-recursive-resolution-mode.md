---
id: ugd
title: E16 · Recursive resolution mode
type: epic
status: open
priority: P3
created: 2026-05-30T20:47:21.441454701Z
updated: 2026-05-30T20:47:21.441454701Z
tags:
- upstream
- dns
- roadmap
---

**STUB — not in 0.2.0.** Roadmap epic; subtasks to be defined after the architecture fork below is decided.

## Goal
Add a `recursive` resolution mode alongside `forward`: instead of forwarding to a configured upstream, iterate from the root servers (root → TLD → authoritative). Selected via a resolution-mode setting. The privacy-focused option (no third party sees all queries). Independently useful even without DNSSEC validation (E17).

## Architecture fork to settle first
**Lean on `hickory-recursor` (parse/deserialize on the recursive path) vs. build iteration over the custom codec.** Recommendation: **use hickory-recursor.** Keep the raw-passthrough shallow-parse fast-path for `forward` mode; the recursive mode is opt-in and inherently heavier, so using hickory's parsed types there does not compromise the hot-path philosophy where it matters.

## Likely shape (to flesh out)
- Resolution-mode setting (`forward` / `recursive`) + RuntimeSettings + UI.
- A recursive resolver leaf service (root hints, referral following, glue, QNAME minimization, caching) as an alternative to the upstream pool.
- Integration with the existing moka cache and the custom codec's response synthesis for the client reply.

## Relationship
E17 (DNSSEC validation) builds on this track. Out of 0.2.0 scope (which is E10–E15).