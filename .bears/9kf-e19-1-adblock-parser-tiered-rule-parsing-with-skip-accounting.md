---
id: "9kf"
title: "E19.1 · AdBlock parser: tiered rule parsing with skip accounting"
status: done
priority: P2
created: "2026-08-30T12:15:42.315619626Z"
updated: "2026-08-30T12:56:12.373013776Z"
tags:
  - blocklist
parent: "8j5"
assignee: opencode
attempts: 1
---

Epic: E19. Implement an **AdBlock-format parser** producing the tiered rule structure, leaving existing formats untouched.

## Current state

- `src/blocklist/parse.rs` — `BlocklistParser` trait returns `HashSet<Name>`; `HostsParser` / `DomainListParser` + shared `preprocess()` (inline `#` stripping, `#`/`!` whole-line comments, `\r\n` via `lines()`). Extensive unit tests here are the style template.
- `src/storage/blocklists.rs:29` — `BlocklistFormat` enum (`strum`, `#[strum(serialize = "hosts")]` / `"domain-list"`), stored as TEXT.

## Requirements

1. Add `BlocklistFormat::AdBlock` (`#[strum(serialize = "adblock")]`) and dispatch through the `Parser` enum like the others. Check whether the column is plain TEXT (no migration expected) — but since any query change may touch `.sqlx`, run the cache-regen check per AGENTS.md if needed.

2. Introduce a structured parse result (new type in `parse.rs`, e.g. `ParsedRules`):
   - `exact: HashSet<Name>` — bare domains and `||domain^` whose intent is exact-or-suffix? **No** — decide: bare domains → `exact`; `||domain^` → `suffix`; `@@||domain^` → `exception` (own `HashSet<Name>`).
   - `suffix: HashSet<Name>` — domains stripped from `||domain^` (strip leading `||`, trailing `^`).
   - `exceptions: HashSet<Name>` — from `@@||domain^`.
   - `skipped: usize` — lines that are recognizable rules but unsupported (`*` inside the pattern, `/regex/`, `$option` suffixes, separator chars other than the trailing `^`, etc.).
   - Existing formats should be able to produce `ParsedRules` too (exact-only, `skipped: 0`) so the aggregator has one input shape — either widen the trait's return type or add a sibling trait; prefer keeping `BlocklistParser` untouched and adding a `parse_rules`-style method so `hosts`/`domain-list` call sites (scheduler, tests) don't churn.

3. Rule grammar to support (document in the module docs):
   - `||domain^` — block domain and all subdomains.
   - `@@||domain^` — exception; allowlist-style suppression.
   - Lines starting `!` and `#` remain comments; inline `#` stripping keeps current behaviour **only for hosts/domain-list** — for AdBlock, inline comment stripping must NOT eat `#` characters that are part of… (actually `#` never appears in valid AdBlock rules; keep the shared preprocess but verify tests).
   - A line that is just a bare valid domain is treated as an exact rule (many "AdBlock" lists mix these in).
   - Anything else containing `$`, `*`, `/`, `|` (single-pipe anchors), `~`, or other separator semantics → `skipped += 1`, never fatal.

4. Normalization: rule domains go through `Name::from_str` like today; invalid rule domains count as skipped, not errors.

5. Tests as executable spec (follow existing test style in `parse.rs`): basic `||`/`@@||`, subdomain intent documented, mixed bare domains, option/wildcard/regex rules skipped with counts, case normalization, CRLF, dedup within each tier, and equivalence: an AdBlock list of bare domains parses identically to `domain-list`.

Do not touch aggregation, the pipeline, or the DB in this task beyond the enum variant.