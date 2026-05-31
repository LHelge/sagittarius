---
id: 3fz
title: E5.1 · Upstream transport clients (UDP/TCP/DoT/DoH)
status: done
priority: P1
created: 2026-05-29T07:23:07.075071989Z
updated: 2026-05-29T15:25:18.815806661Z
tags:
- upstream
- dns
depends_on:
- '783'
parent: tbk
---

Build hickory-backed upstream clients over all four transports. hickory is used **only** for upstream transport — the receive-side codec stays custom (SPEC §2.1, §7).

## hickory version note (updated 2026-05-29)
Use the **latest** hickory, which is **0.26**. In 0.26 the low-level client (`Client`/`DnsHandle`) and *all* transport implementations moved out of `hickory-proto` into a new **`hickory-net`** crate (which re-exports `hickory-proto as proto`). The old `hickory-client` crate was **not** ported to 0.26 (latest is 0.25.2), so do **not** use it — its `Client` now lives at `hickory_net::client::Client`. TLS is **rustls 0.23** via `tokio-rustls` (ring provider); native-tls/OpenSSL are gone.

## Deliverables
- Deps already added via `cargo add`:
  - `hickory-net` with features **`tls-ring`, `https-ring`** (UDP/TCP come with the default `tokio` feature; `tls-ring` adds DoT, `https-ring` adds DoH).
  - `hickory-proto` (for the `op`/`rr`/`xfer` types: `op::{Message, Query, DnsRequest, DnsResponse}`, `rr::{Name, RecordType}`).
- A runtime `UpstreamConfig` (address, `transport` enum udp/tcp/dot/doh, optional `tls_server_name`). *(Mapping from E3.4's persisted `Upstream` row happens at the wiring boundary — keeps E5 DB-decoupled.)*
- A factory that, given an `UpstreamConfig`, builds a `hickory_net::client::Client` over the correct transport, returning the handle **plus the background driver future** for the caller to spawn (so E5.3 can register it on the runtime TaskTracker). `Client::new(stream, stream_handle)` / `Client::with_timeout(...)` return `(Client, DnsExchangeBackground<…>)` — the second element is exactly that driver future. UDP: `UdpClientStream::builder(addr, provider).build()`; TCP: `TcpClientStream::new(...)`; DoT/DoH via their `hickory-net` builders. Use `TokioRuntimeProvider` as the `RuntimeProvider`. Connection reuse/keep-alive for TCP/DoT/DoH.

## Design notes
- Behaviour on an `UpstreamClient`/factory type, not free functions (CLAUDE.md).

## Validation
- Each transport constructs a working handle.
- A UDP and a TCP query against a local mock/real resolver resolve successfully.
- DoT and DoH against a real public resolver behind an opt-in / `#[ignore]` test (no network in default CI run).