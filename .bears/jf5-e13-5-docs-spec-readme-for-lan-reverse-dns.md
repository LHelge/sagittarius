---
id: jf5
title: 'E13.5 · Docs: SPEC + README for LAN reverse DNS'
status: open
priority: P2
created: 2026-05-30T20:24:08.269008930Z
updated: 2026-05-30T20:24:08.269008930Z
tags:
- docs
depends_on:
- e5x
- gkd
- 2pd
parent: s2e
---

Document LAN reverse DNS + conditional forwarding.

## SPEC.md
- **§4 Data model**: add the `forward_zones` table.
- **§5 DNS query lifecycle**: PTR handling — local PTR synth from local records (authoritative), then conditional-forward of matching zones to their target, ahead of blacklist/blocklist.
- **§3.1**: the reverse index (IP→name) and the per-zone forwarders as runtime state.
- **§9**: the forwarding config UI (router/DHCP target + zone toggles).
- **§12 Roadmap**: note reverse DNS / conditional forwarding now shipping.

## README.md
- Mention reverse DNS for the LAN + conditional forwarding to the router.

## Tests
- None (docs only); keep SPEC ↔ README consistent.