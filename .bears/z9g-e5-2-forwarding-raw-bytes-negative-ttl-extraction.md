---
id: z9g
title: E5.2 · Forwarding + raw-bytes & negative-TTL extraction
status: done
priority: P1
created: 2026-05-29T07:23:17.950014255Z
updated: 2026-05-29T15:35:30.668961179Z
tags:
- upstream
- dns
depends_on:
- 3fz
- qr4
parent: tbk
---

Send a query through an upstream client and return everything the cache-store seam (E6) needs. See SPEC §7, §8, §5 step 9.

## Deliverables
- Given an E2.4 `Question`, build a hickory `DnsRequest` (carry RD) and send it via the E5.1 `Client` (`DnsHandle`). **Do not request DNSSEC records (DO=0)** for v0.1: DNSSEC validation is out of scope and the cache key is `(qname, qtype, qclass)` with no DO bit, so forwarding without DO keeps cached responses uniform. (Revisit if/when DNSSEC validation lands.)
- Return a **public `ForwardResult { bytes: Bytes, negative_ttl: Option<u32>, is_negative: bool }`** (the type E5.3 propagates and E6.3 consumes):
  - `bytes` — the response as **raw bytes** via `DnsResponse::into_buffer()` (exact upstream wire bytes). Note: in hickory 0.26 `into_buffer()` returns `Vec<u8>`; wrap as `Bytes::from(vec)` (takes ownership, no copy),
  - `negative_ttl` — from `DnsResponse::negative_ttl()` (RFC 2308 `min(SOA.ttl, SOA.minimum)`; `None` when no SOA),
  - `is_negative` — rcode NXDOMAIN, or NOERROR with no answer (NODATA).
- A per-attempt **timeout (default 2 s)** used by E5.3's retry/failover budget.

## hickory 0.26 type locations
- `DnsRequest`, `DnsResponse`, `Message`, `Query` live in `hickory_proto::op`; `Name`/`RecordType` in `hickory_proto::rr`. `DnsHandle` is `hickory_net::DnsHandle`. (`hickory-net` re-exports `hickory_proto as proto`.)

## Design notes
- Read `negative_ttl()` / classification **before** consuming the response with `into_buffer()` (or use `into_parts() -> (Message, Vec<u8>)`), since `into_buffer` moves out of the `DnsResponse`.
- The raw bytes are exactly what E2.6 scans and E4.3 stores — no re-serialization. E6.3 is responsible for patching the transaction ID on the client-facing reply and cache hits.

## Validation
- A forwarded query returns raw bytes that re-parse (custom codec) to the expected answer.
- A negative response surfaces the correct `negative_ttl()` and `is_negative`; a SOA-less negative yields `None`.
- The per-attempt timeout fires and surfaces a typed error.