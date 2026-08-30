---
id: u2q
title: E19.5 · SPEC/README update + e2e coverage
status: in_progress
priority: P2
created: "2026-08-30T12:18:40.349133236Z"
updated: "2026-08-30T13:24:37.829222945Z"
tags:
  - blocklist
  - docs
depends_on:
  - peg
  - mzd
parent: "8j5"
assignee: opencode
attempts: 1
---

Epic: E19. Documentation and end-to-end closure. Depends on E19.1–E19.4.

## Requirements

1. **SPEC.md updates** (source of truth — update, don't append a changelog):
   - §6 *Sources*: add the `adblock` format and the supported grammar (`||domain^`, `@@||domain^`, bare domains as exact; wildcards/regex/options skipped and counted). State the tiered-matching design and the explicit non-goal (no pattern rules, no regex — Tier 3 rejected; §12 trie remains future).
   - §5 *Blocking granularity*: replace the "exact match only" paragraph — blocking is now exact + suffix with `@@` exceptions; document precedence (exact before suffix; exceptions suppress blocklist tiers only, never the admin blacklist; admin allowlist flag precedence unchanged) and the hot-path budget (probe + ≤label-count walk, no allocation).
   - §12: tick/remove the "Full AdBlock filter syntax" *Later* item or narrow it to "remaining AdBlock syntax (patterns, options, regex)".
   - §13 if anything about mirrored formats needed stating.
2. **README.md** — mention AdBlock-format blocklist support wherever blocklists are described; keep aligned with SPEC wording.
3. **e2e sweep** — one `tests/` scenario (likely `pipeline_e2e.rs` or a new fixture-driven test) exercising: subscribe an `adblock`-format source (local fixture), query a subdomain of a `||rule^` → blocked with attribution; query under an `@@||…^` exception → forwarded; restart-independent bits covered by existing suites.
4. **Quality gate** — `cargo fmt --all --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test` all green, plus `cargo sqlx prepare --check` if E19.4 touched queries.
5. Wrap-up: confirm every E19 subtask is completed in the tracker before the final commit; note any deliberate deferrals (e.g. chosen exception/blacklist one-click behaviour from E19.3) in the PR description for review.