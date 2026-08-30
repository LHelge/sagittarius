---
id: peg
title: "E19.3 · Decision layer: suffix matching, exceptions, and log attribution"
status: done
priority: P2
created: "2026-08-30T12:17:48.248301810Z"
updated: "2026-08-30T13:19:02.177794423Z"
tags:
  - blocklist
  - dns
depends_on:
  - xff
parent: "8j5"
assignee: opencode
attempts: 1
---

Epic: E19. Wire the tiered blocklist decision into the query pipeline and make suffix/exception blocks attribute correctly in the query log. Depends on E19.2.

## Decisions (confirmed by maintainer)

- **Whitelist action on a suffix-blocked row**: adds the **queried name** to the allowlist.
- **Blacklist action on exception-served rows**: allowed — admin blacklist wins over `@@` exceptions, so the action is coherent. Exception-served rows (which render as forwarded/cached) already offer the *Blacklist* action via the existing forwarded-row path; no change beyond tests.

## Current state

- `src/resolver/pipeline/layers.rs` — the blocking stages. Around line 207: `if !bypass && state.blocklist().contains(&name)` → synthesize sinkhole response, outcome `BlockedByBlocklist`. The allow-bypass flag (admin allowlist) already short-circuits here. Pause gate (E12) skips all blocking stages — must keep doing so.
- Query-log writer stamps `query_log.blocklist_id` from `primary_source()` off the hot path (SPEC §6, E11).
- Web one-click actions (`src/web/live_log.rs`, `src/web/lists.rs`): blocklist-blocked rows offer *Whitelist*; forwarded rows offer *Blacklist*.

## Requirements

1. Blocklist stage: call the new `match_name`-style API (E19.2) instead of `contains()`.
   - `Block` decision → sinkhole response as today; outcome stays `BlockedByBlocklist`.
   - `Exception` decision → skip blocking (fall through to cache/forward), same as an allow-bypass.
   - Admin allowlist flag continues to take precedence as today (allowlist flag set → skip stage entirely).
2. Attribution: the decision carries the matched rule's `blocklist_id`; thread it to the query event so the writer persists it for suffix-blocked rows too. Verify E11's per-list effectiveness counting picks suffix blocks up with no change beyond the id being present.
3. One-click actions per the confirmed decisions above; cover both in tests.
4. Runtime stats: blocked counters must count suffix blocks (they already count on outcome; verify nothing special-cases exact-only).
5. Tests: pipeline unit tests in `layers.rs` style — exact hit, suffix hit (subdomain of a rule), exception suppresses suffix block, admin blacklist still wins over exception, allowlist flag precedence unchanged, pause gate skips the whole stage, logged `blocklist_id` equals the matched rule's source. Add/extend an e2e in `tests/pipeline_e2e.rs` covering a suffix block flowing through the real stack with attribution in the DB.

Hot-path budget check: the decision replaces one hash probe with probe + label walk; confirm no allocation and document the layer's comment accordingly.