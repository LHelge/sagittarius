---
id: rf6
title: E2.3 · Header codec & flags
status: done
priority: P1
created: 2026-05-29T06:24:20.203451061Z
updated: 2026-05-29T11:25:18.167631725Z
tags:
- codec
- dns
depends_on:
- zc5
parent: rjw
---

The 12-byte DNS header as a type with ergonomic flag access. See SPEC §2.1, §5 step 2.

## Deliverables
- `Header` struct holding: ID, the flag bitfield, and the four section counts (QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT).
- Flag access: QR, Opcode, AA, TC, RD, RA, Z, RCODE — via get/set helper methods.
- `Opcode` and `RCODE` modelled as enums where it aids correctness (e.g. NXDOMAIN, NOERROR, SERVFAIL, FORMERR).
- Read from bytes (via E2.1 reader) + build/serialize (via E2.1 writer).

## Design notes
- Methods/enums on the type rather than ad-hoc bit twiddling at call sites (CLAUDE.md).

## Validation
- Bit-exact round-trip over hand-built headers.
- Flag get/set correctness: e.g. set QR + RA and RCODE = NXDOMAIN, serialize, re-read, assert.
- Count fields read/write correctly at the right offsets.