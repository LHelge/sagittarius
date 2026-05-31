---
id: ase
title: E9.2 · Full-stack e2e harness + scenario suite
status: done
priority: P2
created: 2026-05-29T08:05:13.068332202Z
updated: 2026-05-30T13:41:26.003685534Z
tags:
- integration
- test
depends_on:
- gug
- zkb
- 44p
- xus
- 8vm
- mk2
- tgx
- jss
parent: 8wg
---

Prove the whole binary works as a product by driving the real DNS + admin surfaces end to end. See SPEC §5, epic body.

## Deliverables
- A harness that **builds & launches the real binary** on ephemeral ports against a temp DB + a **mock upstream**, programmatically completes the **first-run wizard** (E8.4), and exposes drivers for DNS queries + admin HTTP (auth + CSRF token handling).
- Scenario suite:
  1. **Blocked** domain → configured sinkhole answer (NXDOMAIN / null-IP / custom).
  2. **Allowlisted** domain bypasses the blocklist and resolves.
  3. **Local / wildcard** record resolves authoritatively.
  4. **Local qtype mismatch** returns authoritative NODATA without hitting upstream.
  5. **Repeat** query served from cache (txn-id + decremented TTL).
  6. **Cache-miss** forwarded and resolved via the mock upstream.
  7. **One-click whitelist** (E8.7) from the live log takes effect on the next query.

## Design notes
- Set up each scenario through the admin surfaces (manual lists/records E8.8, upstreams/settings → mock E8.9, blocklist source E8.10) to exercise the real write-through + swap paths.
- Keep UDP/TCP + mock upstream so the suite runs network-free in CI.

## Validation
- The suite is green across all six scenarios against a running binary.
- Runs in default CI without external network.
