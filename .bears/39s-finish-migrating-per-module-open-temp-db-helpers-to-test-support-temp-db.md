---
id: "39s"
title: "Finish migrating per-module open_temp_db helpers to test_support::temp_db"
status: done
priority: P3
created: "2026-06-12T23:03:33.909386343Z"
updated: "2026-06-12T23:22:42.485622278Z"
tags:
  - test
  - tech-debt
parent: cde
---

`test_support::temp_db()` landed in `d260474`, but four test modules still define a private `open_temp_db()` clone of it:

- `resolver/state.rs:397`
- `resolver/pipeline/layers.rs:240`
- `resolver/pipeline/forward.rs:249`
- `storage/mod.rs:196`

Replace each with `crate::test_support::temp_db()` and drop the local helper (and now-unused `tempfile`/`Db` imports where applicable). `storage/mod.rs` tests that need a bare `TempDir` without a `Db` keep constructing it directly.

Commit: `test: use the shared temp_db helper in the remaining modules`