---
id: unc
title: E6.4 · Cross-cutting tower middleware (rate limit, concurrency, timeout)
status: open
priority: P1
created: 2026-05-29T07:42:01.496267400Z
updated: 2026-05-29T08:19:53.218805367Z
tags:
- pipeline
- dns
depends_on:
- h3u
- amy
parent: 4k2
---

The protective `tower` layers wrapping the resolve stack (decision layers E6.2 → inner E6.3). See SPEC §3.1, §5 step 1, §11.

## Deliverables
- `cargo add governor`. (The base `tower` crate is already added by E6.1.)
- **Per-client rate limiting**: a small custom `tower` layer over `governor`'s **keyed** `RateLimiter`, keyed on the client IP (`DnsRequest.client`). Chosen over `tower_governor`, whose key extractors assume HTTP request types. Default **~100 qps, burst 200** per client (tunable).
- **Concurrency limit / backpressure** + **load shed**: bound in-flight requests (default cap **1024**); shed (error) rather than queue unboundedly when saturated.
- **Per-request timeout (default 5 s)** — exceeds the default upstream budget (2 s per attempt × 2 attempts from E5.3) so one failover can complete within it.
- Sensible layer order (e.g. load_shed → concurrency_limit → timeout → resolve stack).
- **On-the-wire behaviour for rejected queries (decided):** when a query is dropped by the per-client **rate limit** or by **concurrency/load-shed**, reply with a minimal **REFUSED** response (synthesized by E2.5, preserving the request ID), Outcome=`Refused`. The protective layers signal these conditions as typed errors that the listener (E6.5) maps to REFUSED; the **per-request timeout** instead maps to SERVFAIL (consistent with upstream all-fail). This keeps a rate-limited client informed rather than left to retransmit blindly.

## Design notes
- Per-datagram, the listener oneshots a request through a cloned stack; these layers bound total work and protect against floods/amplification.
- The limiter instances are built **once and shared** (cloned) across every UDP socket task + the TCP handler — limits are global, not per-socket (see E6.5).

## Validation
- An over-limit client is throttled (its excess queries get REFUSED) while other clients still pass.
- Saturating concurrency sheds load (returns the typed shed error promptly → REFUSED; no unbounded queue growth).
- A slow request hits the timeout and returns the typed timeout error (→ SERVFAIL at the listener).
