---
id: 3fz
title: E5.1 · Upstream transport clients (UDP/TCP/DoT/DoH)
status: open
priority: P1
created: 2026-05-29T07:23:07.075071989Z
updated: 2026-05-29T07:23:07.075071989Z
tags:
- upstream
- dns
depends_on:
- '783'
parent: tbk
---

Build hickory-backed upstream clients over all four transports. hickory is used **only** for upstream transport — the receive-side codec stays custom (SPEC §2.1, §7).

## Deliverables
- Add hickory via `cargo add` (`hickory-proto` and/or `hickory-client`) with the **rustls** features for DoT/DoH (`tls-ring`, `https-ring`); hickory 0.25 dropped native-tls/OpenSSL, so TLS is **rustls 0.23** only.
- A runtime `UpstreamConfig` (address, `transport` enum udp/tcp/dot/doh, optional `tls_server_name`). *(Mapping from E3.4's persisted `Upstream` row happens at the wiring boundary — keeps E5 DB-decoupled.)*
- A factory that, given an `UpstreamConfig`, builds a hickory `DnsHandle` over the correct transport, returning the handle **plus the background driver future** for the caller to spawn (so E5.3 can register it on the runtime TaskTracker). Connection reuse/keep-alive for TCP/DoT/DoH.

## Design notes
- Behaviour on an `UpstreamClient`/factory type, not free functions (CLAUDE.md).

## Validation
- Each transport constructs a working handle.
- A UDP and a TCP query against a local mock/real resolver resolve successfully.
- DoT and DoH against a real public resolver behind an opt-in / `#[ignore]` test (no network in default CI run).