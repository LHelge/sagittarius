---
id: 8wg
title: E9 · End-to-end integration & release readiness
type: epic
status: done
priority: P2
created: 2026-05-28T22:38:41.470521457Z
updated: 2026-05-30T14:01:13.036100725Z
tags:
- integration
depends_on:
- 4k2
- dqh
- p6b
---

Capstone: prove the whole binary works as a product — a real resolver with a working admin — and get v0.1 into shippable shape.

**Scope**
- Full-stack e2e harness: build & launch the binary on ephemeral ports against a temp DB, complete the first-run wizard, then drive both the DNS and admin surfaces.
- Scenarios:
  - Blocked domain → configured sinkhole answer.
  - Allowlisted domain bypasses the blocklist and resolves.
  - Local / wildcard record resolves authoritatively.
  - Local qtype mismatch returns authoritative NODATA without upstream leakage.
  - Repeat query served from cache.
  - Cache-miss forwarded and resolved via a (mock) upstream.
  - One-click whitelist from the live log takes effect on the next query.
- README quickstart verification — the "Running" steps actually produce a working sinkhole.
- Docs sync check (SPEC / README / CLAUDE) and release tidy-up: version, example systemd unit / reverse-proxy snippet (optional), CHANGELOG seed.

**Design notes**
- Depends on the full pipeline + blocklists + admin; this is where the cross-component behaviour is locked in by tests.

**Out of scope**
- Everything on the post-MVP "future" list (DNSSEC, DHCP, charts, durable query log, native TLS, per-client policies).

**Validation**
- e2e suite green against a running binary across all scenarios above.
- A fresh checkout following the README yields a working sinkhole.
