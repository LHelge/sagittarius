---
id: qs8
title: Move cache clamp_ttl / patch_response / patch_txn_id onto their types
status: open
priority: P2
created: 2026-05-30T11:32:35.299201256Z
updated: 2026-05-30T11:32:35.299201256Z
tags:
- refactor
parent: 46z
---

**Where:**
- `src/resolver/cache.rs:91` — `fn clamp_ttl(secs, min, max) -> u32`
- `src/resolver/cache.rs:108` — `fn patch_response(…)`
- `src/resolver/pipeline/forward.rs:189` — `fn patch_txn_id(bytes: &Bytes, id: u16) -> Bytes`

**Why:** TTL clamping and response/transaction-id patching are operations on the cache and DNS-message/response types; they read better as methods on those types.

**Do:**
- `clamp_ttl` → method on the cache (or a TTL-bounds value) — it already has `min`/`max` context the cache owns.
- `patch_response` → method on the cached-response/message type.
- `patch_txn_id` → method on the DNS message/bytes wrapper (e.g. `msg.with_txn_id(id)`).
- Behavior-preserving; keep the existing unit tests passing (relocate where it reads better).