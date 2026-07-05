---
id: cdj
title: E18.1 — api_keys table + repository
status: done
priority: P1
created: "2026-07-05T12:33:21.031106420Z"
updated: "2026-07-05T12:42:06.439538665Z"
tags:
  - secondary
  - storage
parent: b6b
---

`sqlx migrate add -r api_keys`. Columns: id (PK opaque), token_hash (hex SHA-256), label, created_at, last_used_at?, revoked_at? + idx_api_keys_active. New src/storage/api_keys.rs: ApiKeyRepository trait + SqliteApiKeyRepo (impl Future convention), methods create(label)->(plaintext_once, record), list, find_active(id), revoke(id), touch_last_used. Register db.api_keys() in src/storage/mod.rs; add "api_keys" to schema_all_tables_exist test. Reuse id/token/hash primitives from src/web/auth.rs. Down-migration inverse test. cargo sqlx prepare.