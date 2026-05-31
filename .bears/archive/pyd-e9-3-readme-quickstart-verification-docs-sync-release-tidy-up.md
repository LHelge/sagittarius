---
id: pyd
title: E9.3 · README quickstart verification + docs sync + release tidy-up
status: done
priority: P2
created: 2026-05-29T08:05:22.918556320Z
updated: 2026-05-30T13:49:22.448068522Z
tags:
- integration
- docs
depends_on:
- ase
parent: 8wg
---

Get v0.1 into shippable shape: verify the user-facing quickstart, reconcile the docs with what was built, and add release scaffolding. See SPEC §10, §12.

## Deliverables
- **README quickstart verification:** follow the "Building" + "Running" steps from a fresh checkout and confirm they produce a working sinkhole (build → run → wizard → resolves + blocks).
- **Docs sync** across `SPEC.md` / `README.md` / `CLAUDE.md`: reconcile any decisions made during implementation, e.g.:
  - dedicated `upstreams` table + typed `settings` (E3),
  - strict RFC 2308 negative caching via hickory `negative_ttl()` (E4/E5),
  - OPT pseudo-RRs excluded from TTL patching,
  - v0.1 blocklist formats limited to hosts + domain-list (AdBlock-style future),
  - qtype-aware local records and local-name NODATA behaviour,
  - `SO_REUSEPORT` UDP listener pool (E6.5),
  - custom lightweight sessions + `auto | always | never` session-cookie secure policy (E8),
  - rate-limited / load-shed queries answered with **REFUSED**; timeout / upstream-all-fail with **SERVFAIL** (E6.4/E6.5),
  - upstream forwarding with **DO=0** (no DNSSEC) for v0.1 (E5.2),
  - the full crate stack actually used (reqwest, governor, socket2, rand, argon2, tokio-util, …) reflected in SPEC §2.
- **Release tidy-up:** confirm the crate version, seed a `CHANGELOG.md`, and add optional example **systemd unit** + **reverse-proxy (TLS) snippet** for deployment.

## Design notes
- This closes the loop: SPEC is the source of truth and must reflect shipped behaviour (CLAUDE.md).

## Validation
- A fresh clone following the README yields a working sinkhole.
- SPEC/README/CLAUDE match the shipped behaviour (no stale claims).
- `CHANGELOG.md` and example deployment files present.
