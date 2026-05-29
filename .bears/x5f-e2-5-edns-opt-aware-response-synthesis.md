---
id: x5f
title: E2.5 · EDNS/OPT-aware response synthesis
status: open
priority: P1
created: 2026-05-29T06:24:48.638459658Z
updated: 2026-05-29T08:17:16.057345016Z
tags:
- codec
- dns
depends_on:
- qr4
parent: rjw
---

Build block and local-record answers directly into an output buffer, EDNS-aware. See SPEC §2.1, §5 steps 3–6, §8.

## Deliverables
- Synthesize from the question (E2.4 view) into the E2.1 writer, supporting all three block modes (mode is configurable; seeded default is **null-IP**):
  - **NXDOMAIN** block response,
  - **null-IP** block (`0.0.0.0` for A, `::` for AAAA),
  - **custom-IP** block (configured address),
  - **local-record** answers: A / AAAA with a TTL.
- **Authoritative local NODATA** for a local name/wildcard match where no record exists for the requested qtype (e.g. local A exists, client asks MX). Local names do not fall through to upstream.
- **Non-address qtypes:** null-IP / custom-IP modes only synthesize an address for **A/AAAA**; a block of any other qtype (MX, TXT, …) returns **NODATA** (NOERROR, empty answer). In **NXDOMAIN** mode every qtype returns NXDOMAIN.
- **Minimal error responses** used by the pipeline/listeners: `FORMERR` for malformed requests when the transaction ID is recoverable, `SERVFAIL` for upstream all-fail / per-request timeout, and `REFUSED` for queries rejected by the protective middleware (per-client rate limit or concurrency/load-shed — see E6.4/E6.5). These responses preserve the request ID and copy RD when available. A small `rcode → minimal response` helper covers all three.
- Correct response header: set QR, RA, RCODE; copy the request ID and RD; set counts.
- EDNS handling: scan the **query's raw bytes** for an OPT record in the additional section (E2.4 parses only header+question, so synthesis must scan the raw datagram itself). If present, echo a matching OPT in the response —
  - honour the requestor's advertised UDP payload size,
  - reflect an EDNS **COOKIE** (OPT option-code 10, RFC 7873) when present.
  - Cheap scan of the otherwise near-empty additional section (SPEC §2.1).
- Expose a small `EdnsInfo` / OPT-query scan helper (payload size + cookie, if present) so E6.5 can apply the same UDP-size decision before truncating large responses.
- A non-EDNS query gets no OPT in the response.

## Design notes
- OPT pseudo-RR (RFC 6891): NAME = root, TYPE = 41, CLASS = UDP payload size, TTL = ext-rcode/version/flags, RDATA = options.
- Build directly into the buffer — no intermediate message model (SPEC §2.1).

## Validation
- For each block mode and local A/AAAA: synthesize → re-parse, assert rcode / answer records / TTL.
- A blocked non-A/AAAA query in null-IP mode → NODATA; in NXDOMAIN mode → NXDOMAIN.
- Local qtype mismatch → authoritative NODATA and no upstream/cache lookup.
- FORMERR/SERVFAIL/REFUSED response helpers produce valid minimal DNS responses.
- EDNS echo test: payload size + COOKIE reflected; non-EDNS query → no OPT.
- Round-trip: parse → synthesize → re-parse stays consistent.
