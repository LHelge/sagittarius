---
id: tcb
title: E14 · Client hostname decoration (admin UI)
type: epic
status: open
priority: P2
created: 2026-05-30T20:24:13.210287968Z
updated: 2026-05-30T20:24:13.210287968Z
tags:
- web
- telemetry
---

Show device hostnames instead of bare `192.168.x.x` in the live log and "top clients," by having Sagittarius reverse-look-up client IPs internally and cache the results.

## Depends on
- **E13** — so private-IP reverse lookups actually resolve (local PTR synth / conditional forwarding). Public client IPs resolve via the normal upstream.
- **E10** — the live log (E10.7) and dashboard top-clients (E10.8) are the surfaces being decorated.

## Locked decisions
- **Resolve at render time from a bounded, TTL'd cache — no `query_log` hostname column.** Avoids write-path work and stale names when DHCP leases change; "top clients" groups by IP regardless, so hostname is a cheap per-distinct-IP decoration.
- **Bounded + negatively cached** reverse lookups so a chatty log never hammers the router. Worth a privacy/opt-in note.

Tests live in each subtask.