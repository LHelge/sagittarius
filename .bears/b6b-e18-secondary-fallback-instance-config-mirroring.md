---
id: b6b
title: E18 — Secondary/fallback instance (config mirroring)
type: epic
status: done
priority: P1
created: "2026-07-05T12:33:10.759120436Z"
updated: "2026-07-05T13:28:55.415783314Z"
tags:
  - secondary
---

Add a read-only secondary/fallback instance that mirrors a primary's config over an API-key-authenticated sync API. See plan: /home/lhelge/.claude/plans/i-want-to-maki-precious-lampson.md

Decisions: pairing via CLI/env (`--primary-url`/`--primary-api-key`); trust via API keys minted in the primary UI; mirror admin_users; blocklists re-fetched independently on the secondary.

Mirror-worthy tables: settings, upstreams, blocklists (source defs), blacklist, allowlist, local_records, forward_zones, admin_users. Local-only: sessions, query_log, blocklist_cache, moka cache, paused_until.