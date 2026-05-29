---
id: 58n
title: E6.7 · Pipeline integration + end-to-end tests
status: open
priority: P1
created: 2026-05-29T07:42:25.396829332Z
updated: 2026-05-29T07:42:25.396829332Z
tags:
- pipeline
- dns
depends_on:
- ynh
- 5jx
parent: 4k2
---

Assemble the full engine and lock in cross-component behaviour with end-to-end tests. See SPEC §3, §5.

## Deliverables
- Wire it all together: listeners (E6.5) → cross-cutting middleware (E6.4) → decision layers (E6.2) → inner forward+cache-store (E6.3), with telemetry (E6.6) emitted at the log step and the whole thing attached to the E1 runtime/shutdown.
- A single entry point the `app` runtime starts (sharing E4 state + the E5 pool via `Arc`).

## Design notes
- This is the capstone of the resolver half; E9 later proves the whole product (DNS + admin) together.

## Validation (e2e over real sockets against an ephemeral bind + mock upstream)
- **Blocked** domain → configured sinkhole answer (NXDOMAIN / null-IP / custom).
- **Local / wildcard** record → authoritative answer.
- **Local qtype mismatch** → authoritative NODATA and no upstream call.
- **Cache hit** → repeat query served from cache (txn-id + decremented TTL).
- **Forwarded** → cache miss resolved via the mock upstream.
- **Malformed** query with recoverable ID → FORMERR; unrecoverable header → no response.
- Telemetry observed end to end: tracing event + live-log broadcast entry + updated stats.
- Clean shutdown while queries are in flight (drains within the timeout).
