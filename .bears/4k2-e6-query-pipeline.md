---
id: 4k2
title: E6 · Query pipeline
type: epic
status: done
priority: P1
created: 2026-05-28T22:38:25.003394094Z
updated: 2026-05-29T18:01:57.284645172Z
tags:
- pipeline
- dns
depends_on:
- rjw
- rbn
- tbk
---

Tie the components together — bind sockets, run the `tower` middleware stack, execute the resolution lifecycle, and emit telemetry — turning the parts into a working resolver. See SPEC §3, §5, §3.2.

**Scope**
- Listeners: UDP and TCP on each configured `--dns-addr` (IPv4 and IPv6 / dual-stack). TCP length framing; UDP truncation (`TC` bit) → expect TCP retry.
- `tower` service stack: per-client rate limiting, concurrency limit / backpressure (load shedding), per-request timeout, and the early-return decision layers.
- Request type carrying raw `Bytes` + the shallow parse + client `SocketAddr`.
- **Match precedence is owned here.** The tower layer ordering *is* the precedence (SPEC §5): shallow parse → local records → admin blacklist → allowlist (sets `allow-bypass`, continues) → blocklist → cache → forward (E5) → cache store → reply → log. E4 provides only the per-set lookup primitives; E6 composes them in order and implements the `allow-bypass` flag interaction. The allowlist suppresses **only** the bulk blocklist, never the admin blacklist; local records win over all blocking. Local-name qtype mismatches return authoritative NODATA rather than falling through.
- **Malformed-query behaviour.** If shallow parse fails after the transaction ID is recoverable, return a minimal FORMERR response; if not even the ID is recoverable, drop the message.
- **Cache-store TTL policy (SPEC §5 step 9).** On a forwarded response: run E2.6's scan for the real TTL-field offsets and the positive min TTL (excluding EDNS OPT pseudo-RRs); set the cache expiry from the **positive** min TTL, or — for **negative** responses (NXDOMAIN / NODATA) — from hickory `DnsResponse::negative_ttl()` (RFC 2308 `min(SOA.ttl, SOA.minimum)`, surfaced by E5.2); **skip caching** SOA-less negatives (`negative_ttl()` is `None`) and positive responses with no real TTL-bearing RRs. Clamp to configured bounds. E4.3's cache just stores bytes + offsets with the supplied expiry.
- **Reply ID policy.** Forwarded raw bytes and cached bytes are patched to the client's transaction ID before sending.
- Telemetry primitives: structured query event via `tracing` to stdout; bounded live-log ring buffer + `tokio::sync::broadcast`; runtime stats counters (atomics; top-N for domains/clients). Outcome variants distinguish admin blocks, blocklist blocks, local answers, local NODATA, cached, and forwarded so E8 can show only effective one-click actions.

**Design notes**
- Early-return middleware idiom (like an HTTP 403 layer); only the inner service touches answer sections.
- Local/blacklist/blocklist layers short-circuit with a synthesized response (E2.5); the allowlist layer never answers — it only sets the flag and continues.
- Error exits synthesize typed DNS errors where possible: FORMERR for malformed queries with a recoverable ID, SERVFAIL for upstream all-fail.
- Shares E4 state and the E5 client via `Arc`; integrates the E1 shutdown signal so listeners stop accepting and in-flight queries drain.

**Out of scope**
- Admin UI consumption of live-log/stats (E8); durable query log (future).

**Validation**
- Integration tests sending real DNS queries to a bound ephemeral socket; assert blocked (NXDOMAIN/null), local answer, cache hit, and forwarded outcomes.
- **Per-branch precedence tests (owned here, moved from E4):** blacklisted+allowlisted → still blocked; allowlisted+blocklisted → forwarded (bypass works); local record wins over all blocking; plain blocklist hit → blocked; non-matching → forwarded.
- **Cache-store TTL tests:** positive answer cached with min-TTL expiry; negative-with-SOA cached using `negative_ttl()`; SOA-less negative and OPT-only/no-real-TTL responses are not cached.
- Malformed query tests: recoverable transaction ID → FORMERR; unrecoverable header → drop/no response.
- Rate-limit / backpressure behaviour under load.
- A processed query produces a `tracing` event, a live-log entry on the broadcast, and updated stats.
