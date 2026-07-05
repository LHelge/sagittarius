---
id: fvu
title: E18.7 — admin_users upsert/reconcile support
status: done
priority: P1
created: "2026-07-05T12:33:31.070705026Z"
updated: "2026-07-05T13:04:48.655681946Z"
tags:
  - secondary
  - storage
parent: b6b
---

src/storage/admin_users.rs: add upsert(username, hash, role) (ON CONFLICT(username) DO UPDATE SET password_hash, role, updated_at), list_usernames, delete_by_username (cascades local sessions). For the syncer to reconcile users by username. cargo sqlx prepare.