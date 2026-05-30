---
id: d9u
title: 'E14.3 · Docs: SPEC + README for hostname decoration'
status: open
priority: P2
created: 2026-05-30T20:24:36.839909935Z
updated: 2026-05-30T20:24:36.839909935Z
tags:
- docs
depends_on:
- akd
- tqc
parent: tcb
---

Document client-hostname decoration.

## SPEC.md
- **§9 Web administration**: the live log + top-clients show device hostnames (IP fallback), resolved internally.
- **§3.1**: the reverse-lookup cache (IP→hostname) as runtime-only state; bounded + negatively cached.
- **§11 Security/privacy**: note that Sagittarius issues reverse lookups for client IPs; bounded/cached; mention any opt-out.

## README.md
- Mention hostnames in the log/dashboard (depends on reverse DNS being configured — E13).

## Tests
- None (docs only); keep SPEC ↔ README consistent.