---
id: s2e
title: E13 · Reverse DNS for the LAN (answer PTR)
type: epic
status: open
priority: P2
created: 2026-05-30T20:23:24.574108892Z
updated: 2026-05-30T20:23:24.574108892Z
tags:
- dns
---

Make Sagittarius answer reverse-DNS (PTR) queries for the local network, so `nslookup 192.168.1.5` resolves network-wide. Two sources, in precedence order: **manual local records first, then conditional-forward to the router/DHCP** for everything else.

## Today's gap
`Qtype` is `A`/`Aaaa`/`Other(u16)`, so a PTR is `Other(12)`. Local records are keyed by forward name, so a PTR qname (`5.1.168.192.in-addr.arpa`) misses and is **forwarded to the public upstream** — useless for private space.

## Locked decisions
- **Both sources, local-first:** answer PTR from local records when the IP is one we own; otherwise conditional-forward the private reverse zones to the router/DHCP.
- **Conditional forwarding is a general `forward_zones` table** (suffix → target upstream), not PTR-specific — the same mechanism later serves split-horizon forward zones (e.g. `corp.internal`). Seeded with the RFC1918 / ULA reverse zones + a configurable router target.
- **PTR synthesis is the codec-touching piece** (name-encoded RDATA) — E13.2 carries the most risk/tests.

## Scope boundary
This epic only makes Sagittarius *answer* PTR. Decorating the admin log/dashboard with client hostnames is the separate **E14**, which depends on this epic + E10.

Independent of E10–E12; E13.1 and E13.3 can start immediately. Tests live in each subtask.