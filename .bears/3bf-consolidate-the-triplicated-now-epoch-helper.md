---
id: 3bf
title: Consolidate the triplicated now_epoch() helper
status: open
priority: P1
created: 2026-05-30T11:32:26.469620908Z
updated: 2026-05-30T11:32:26.469620908Z
tags:
- refactor
- dry
parent: 46z
---

**Where:** identical `now_epoch() -> i64` (`SystemTime::now().duration_since(UNIX_EPOCH)…as i64`) copied in:
- `src/blocklist/scheduler.rs:480`
- `src/web/blocklists.rs:180`
- `src/web/auth.rs:86`

**Why:** DRY — three copies of the same Unix-epoch-seconds helper.

**Do:**
- Pick one home for a single definition (e.g. a small `crate::time` util, or a `Clock`/epoch helper). Avoid leaving it as three free fns.
- Replace all three call sites; delete the duplicates.
- Note: `auth.rs` and `blocklists.rs` are E8 files and `scheduler.rs` is E7 — this is the one item that touches both PR and non-PR code, hence deferred to the round.