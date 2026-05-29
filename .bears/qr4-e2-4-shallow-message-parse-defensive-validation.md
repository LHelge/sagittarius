---
id: qr4
title: E2.4 · Shallow message parse & defensive validation
status: open
priority: P1
created: 2026-05-29T06:24:30.820847161Z
updated: 2026-05-29T06:24:30.820847161Z
tags:
- codec
- dns
depends_on:
- nq7
- rf6
parent: rjw
---

The routing-critical parse: header + the single question, hardened against hostile input. See SPEC §2.1, §5 step 2, §11.

## Deliverables
- A shallow message view = `Header` (E2.3) + `Question` (normalized qname + qtype + qclass, using `Name` from E2.2), carrying the original datagram as `Bytes` for raw passthrough and caching (SPEC §8).
- `QTYPE` / `QCLASS` represented usefully (at least A, AAAA, plus pass-through of others).
- Defensive validation — **all as typed errors, never panics**:
  - reject `QDCOUNT != 1`
  - reject a compression pointer in the question (delegates to E2.2)
  - reject truncated / oversized buffers
  - reject label-length violations
- Parse errors should carry the transaction ID when the 12-byte header was recoverable, so E6.5 can return FORMERR; errors before the ID is recoverable lead to drop/no response.
- `TryFrom<Bytes>` / `TryFrom<&[u8]>` for the parse.

## Design notes
- This is the only parse on the routing hot path; it must not walk RR sections (§2.1).
- The view is what the pipeline (E6) routes on; keep it cheap and allocation-light.

## Validation
- Unit tests on hand-built byte vectors + real capture fixtures (A/AAAA query).
- Every rejection path has a test (bad QDCOUNT, pointer-in-question, truncation, oversize, bad label length).
- Rejection after a valid header exposes the transaction ID for FORMERR synthesis; rejection before a complete header does not.
- No panic on any malformed input (precursor to the E2.7 fuzz target).
