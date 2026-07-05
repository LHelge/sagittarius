---
id: d7p
title: E18.3 — Config snapshot DTOs + content version
status: done
priority: P1
created: "2026-07-05T12:33:25.049213524Z"
updated: "2026-07-05T12:53:14.723533299Z"
tags:
  - secondary
  - sync
parent: b6b
---

New src/sync/dto.rs shared by primary (Serialize) + secondary (Deserialize). ConfigSnapshot: settings (no id), upstreams, blacklist/allowlist (sorted names), local_records, forward_zones, blocklists (url/format/enabled only), admin_users (username/password_hash/role). From<&Storage> per DTO; fixed field + ORDER BY ordering. version(&self)->String = hex SHA-256 of serde_json::to_vec(self). Add serde/serde_json (already deps).