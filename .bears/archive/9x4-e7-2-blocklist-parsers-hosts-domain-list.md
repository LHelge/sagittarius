---
id: 9x4
title: E7.2 · Blocklist parsers (hosts + domain-list)
status: done
priority: P1
created: 2026-05-29T07:47:12.803612913Z
updated: 2026-05-29T19:36:46.708330016Z
tags:
- blocklist
depends_on:
- nq7
parent: dqh
---

Parse fetched blocklist text into a set of normalized domains. See SPEC §6.

## Deliverables
- A parser **trait** plus two implementations:
  - **hosts** format (`0.0.0.0 example.com`, `127.0.0.1 example.com`) — extract the domain field,
  - **domain-list** (one domain per line).
- Ignore comments (`#`, `!`) and blank lines; skip (and optionally log) malformed lines rather than failing the whole list.
- Normalize each domain via `Name` (E2.2) — lowercase, trailing dot — so it matches the codec's normalization at query time.

## Design notes
- AdBlock-subset parsing is future scope; the trait leaves room for it without churn.
- Behaviour on types (the trait + impls), not free functions (CLAUDE.md).

## Validation
- Per-format unit tests, including comments, blank lines, and malformed lines.
- Output is a set of normalized names; hosts vs domain-list produce the same names for equivalent content.
- A line with an invalid domain is skipped, not fatal.