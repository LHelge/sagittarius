---
id: jss
title: E5.4 · Integration tests (mock/local upstream)
status: done
priority: P1
created: 2026-05-29T07:23:34.569179710Z
updated: 2026-05-29T16:08:24.908101844Z
tags:
- upstream
- dns
- test
depends_on:
- jcz
parent: tbk
---

End-to-end tests of the upstream client against a controllable upstream. See SPEC §7 validation.

## Deliverables
- A test harness with a controllable upstream:
  - a local mock/real resolver for UDP and TCP,
  - injectable failing / slow upstreams to exercise failover and timeout.
- Scenarios:
  - **success** — query forwarded and resolved; raw bytes re-parse correctly,
  - **timeout → failover** — slow/dead first upstream, second succeeds,
  - **all-fail** — every upstream errors → typed all-fail error,
  - **each transport** (UDP/TCP/DoT/DoH) exercised at least once.

## Design notes
- Keep UDP/TCP + failover/timeout tests network-free so they run in default CI.
- DoT/DoH live tests against a real public resolver are gated behind `#[ignore]` or a feature flag.

## Validation
- All scenarios green.
- Default `cargo test` runs the UDP/TCP + failover/timeout cases without external network; DoT/DoH live tests run only when explicitly enabled.