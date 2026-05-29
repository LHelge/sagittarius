---
id: 5m2
title: E6.1 · Request/response model + service scaffolding
status: done
priority: P1
created: 2026-05-29T07:41:24.825291276Z
updated: 2026-05-29T16:35:28.944388641Z
tags:
- pipeline
- dns
depends_on:
- qr4
parent: 4k2
---

The request/response vocabulary the whole pipeline is built on, and the `tower::Service` shape the layers + inner service implement. See SPEC §5.

## Deliverables
- `cargo add tower` (features `util`) — this epic is the first to use `tower::Service`, so the base `tower` crate is added here. (`governor` is added later by E6.4.)
- `DnsRequest` carrying: the original datagram as `Bytes`, the shallow parse (`Header` + `Question` from E2.4), the client `SocketAddr`, and a mutable `allow_bypass` flag.
- An `Outcome` / action enum for logging with enough detail for UI actions: `Local`, `LocalNoData`, `BlockedByAdmin`, `BlockedByBlocklist`, `Cached`, `Forwarded`, `Refused`, `Formerr`, `Servfail`, `Error` (or equivalent structured variants). This drives telemetry in E6.6 and determines whether E8.7 can safely show Whitelist/Blacklist actions. `Refused` is the outcome for queries rejected by the protective middleware (per-client rate limit or concurrency/load-shed), which reply with a minimal REFUSED response (E6.4/E6.5).
- The `tower::Service` trait shape (request → response future) that the decision layers (E6.2) and the inner forward service (E6.3) implement; a response type carrying the reply `Bytes` + the `Outcome`.

## Design notes
- Layers route on `Question`/`Header` only; only the inner service touches answer sections (SPEC §2.1).
- Keep the request cheap to clone for the per-datagram oneshot through the stack.

## Validation
- A `DnsRequest` constructs from a parsed query (E2.4) + client addr.
- The `Outcome` enum covers every lifecycle exit and distinguishes admin-block vs blocklist-block and local vs forwarded/cached resolved answers; round-trips through a trivial stub service.
