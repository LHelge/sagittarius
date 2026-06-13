---
id: "8pg"
title: "E12.3 · Docs: SPEC + README for pause-blocking"
status: done
priority: P2
created: "2026-05-30T20:05:33.630233075Z"
updated: "2026-06-13T07:22:53.857311525Z"
tags:
  - docs
depends_on:
  - vp7
  - qqg
parent: kv7
---

Document the pause-blocking feature.

## SPEC.md
- **§5 DNS query lifecycle**: note the pause gate — after local records, when blocking is paused the blacklist/allowlist/blocklist stages are skipped and the query proceeds to cache/upstream.
- **§3.1**: `paused_until` is runtime-only in-memory state (resets to active on restart, fail-safe).
- **§9 Web administration**: capability — pause blocking for a chosen duration (5 m / 30 m / 1 h / custom) with Resume now; navbar control + countdown banner.
- Note: while paused, would-be-blocked queries resolve and log as `Forwarded`/`Cached`.

## README.md
- Mention temporary pause ("snooze blocking for 5 min / 30 min / 1 h").

## Tests
- None (docs only); keep SPEC ↔ README consistent.