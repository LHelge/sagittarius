---
id: q3j
title: E18.9 — Read-only UI (middleware + banner + wizard skip)
status: done
priority: P1
created: "2026-07-05T12:33:58.949992236Z"
updated: "2026-07-05T13:24:04.352616930Z"
tags:
  - secondary
  - web
depends_on:
  - pry
parent: b6b
---

New src/web/readonly.rs guard (like csrf::guard, admin router only, outside csrf so it short-circuits): secondary mode rejects non-safe methods (reuse csrf::is_safe) with 403 except /login,/logout. Add read_only + primary_label to Chrome (src/web/mod.rs); base.html persistent "Mirroring <primary> — read-only" banner + templates wrap edit controls in {% if !chrome.read_only %}. needs_setup returns false in secondary mode so wizard::guard doesn't trap at /setup; show "waiting for first config sync" until admin_users populated.