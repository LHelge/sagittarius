---
id: 46z
title: 'E8.5 follow-up: "behavior lives on types" refactor round'
type: epic
status: open
priority: P2
created: 2026-05-30T11:32:05.225133024Z
updated: 2026-05-30T11:32:05.225133024Z
tags:
- refactor
- tech-debt
---

A short refactoring round to run **after the E8 web-admin PR merges, before the next epic**.

The E8 review surfaced that several module-level free functions are really behavior that belongs on a type — and a few diverge from conventions already used elsewhere in the codebase (`From`/`TryFrom` row conversions, classifier methods on enums). The in-PR offenders (auth handlers, wizard handlers, `Outcome::category`) were fixed inside the E8 PR; this epic captures the remaining ones, which live **outside** the E8 diff (DNS engine + earlier-epic storage).

Guiding convention (CLAUDE.md): *behavior lives on types and traits; prefer standard traits (`From`/`TryFrom`, `Display`, …) over bespoke free functions.*

These items are largely independent — ordered by priority (quick standard-trait wins first, riskier engine restructures later) rather than hard dependencies. Each task is self-contained and should keep `cargo fmt`/`clippy`/`test` green.