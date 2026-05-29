---
id: tbk
title: E5 · Upstream resolution
type: epic
status: done
priority: P1
created: 2026-05-28T22:38:16.375074671Z
updated: 2026-05-29T16:08:24.908280803Z
tags:
- upstream
- dns
depends_on:
- p3k
- rjw
---

Forward cache-miss queries to configured upstream resolvers over plain and encrypted transports, spreading load randomly with timeout-based failover. See SPEC §7.

**Scope**
- `hickory`-based upstream client supporting **UDP, TCP, DoT, DoH**.
- Upstream configuration model (address, transport, optional TLS server name) loaded from settings (E3).
- **Random** upstream selection per query to spread load; on error/timeout, fail over to another randomly chosen upstream. Default retry budget is one failover (two upstreams tried total) so the outer resolver timeout stays bounded.
- Per-query timeout; return the answer as wire `Bytes` suitable for E4's raw-bytes cache and direct client reply.
- Connection reuse/keep-alive where the transport benefits (TCP/DoT/DoH).

**Design notes**
- The receive-side codec stays custom (E2); `hickory` is used **only** for upstream transport (SPEC §2.1).
- Raw-byte decision: E5.2 returns hickory's response buffer as `Bytes` without re-serializing; E6 patches the client-facing transaction ID and E4 stores the raw bytes for cache hits.
- Behaviour on an `Upstreams`/`UpstreamClient` type; selection behind a small trait so future strategies (fastest, weighted) can be added without churn.

**Out of scope**
- DNSSEC validation (future); non-random selection strategies (future); pipeline wiring (E6).

**Validation**
- Integration tests against a local/mock upstream: success, timeout → failover, all-fail behaviour.
- Each transport (UDP/TCP/DoT/DoH) exercised at least once.
