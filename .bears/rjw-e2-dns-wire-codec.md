---
id: rjw
title: E2 · DNS wire codec
type: epic
status: open
priority: P1
created: 2026-05-28T22:38:00.597942343Z
updated: 2026-05-28T22:43:40.349682360Z
tags:
- codec
- dns
depends_on:
- p3k
---

The performance- and security-critical core: a hand-written, lazy DNS wire-format codec that parses only what routing needs and treats all input as hostile. See SPEC §2.1 for the philosophy.

**Scope**
- Framing: UDP datagrams and TCP 2-byte length-prefixed messages.
- Header (12 bytes): ID, flags, section counts; helpers to read/build flags (QR, Opcode, AA, TC, RD, RA, RCODE).
- Question: single QNAME labels + QTYPE + QCLASS; name normalization (lowercase, trailing dot). No general decompression — the question name is never compressed.
- Defensive validation: reject `QDCOUNT != 1`, a compression pointer in the question, truncated/oversized buffers, and label-length violations — errors, never panics.
- EDNS/OPT-aware response synthesis: build NXDOMAIN / null-IP (`0.0.0.0`, `::`) / custom-IP block answers and local-record answers directly into an output buffer; echo the client OPT (UDP payload size, COOKIE) when present.
- Bounded TTL scan (forward path only): walk RR sections once to find the minimum TTL and record each TTL field's byte offset; name-skipping hard-capped to defeat pointer loops.
- `cargo-fuzz` target exercising the parser against arbitrary bytes.

**Design notes**
- Zero/low-copy over `bytes::Bytes`; carry the original datagram for raw passthrough and caching (SPEC §8).
- Types/traits: `Header`, `Question`, `Name`, message-view types with methods; consider `TryFrom<&[u8]>` for parsing and `FromStr`/`Display` for names; a writer type for synthesis (no free functions).
- Keep the hand-written surface minimal (shallow reader, synthesis, TTL scan) — full RR-type parsing is intentionally avoided on the hot path.

**Out of scope**
- Upstream transport / DoT/DoH (E5); decompression of RR sections beyond bounded skipping; full RR-type modelling.

**Validation**
- Unit tests over hand-built byte vectors and real capture fixtures (A/AAAA queries & responses, EDNS, NXDOMAIN).
- Round-trip (parse → synthesize → re-parse) and TTL-offset patch correctness.
- Fuzz target runs without panics/UB; malformed inputs return errors.