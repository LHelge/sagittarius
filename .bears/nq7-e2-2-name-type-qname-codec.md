---
id: nq7
title: E2.2 · Name type & QNAME codec
status: open
priority: P1
created: 2026-05-29T06:24:14.784643923Z
updated: 2026-05-29T06:24:14.784643923Z
tags:
- codec
- dns
depends_on:
- zc5
parent: rjw
---

A `Name` type with normalization plus the QNAME reader/writer. No general decompression — the question name is never compressed (SPEC §2.1).

## Deliverables
- `Name` type with `FromStr` + `Display`; normalization = lowercase + trailing dot.
- QNAME **reader**: length-prefixed labels; enforce label length ≤ 63 and total name length ≤ 255; **reject a compression pointer (top two bits `0b11`) appearing in the question** (SPEC §2.1).
- QNAME **writer** for synthesis (encode a `Name` into the output buffer).
- A separate **bounded name-skip** helper: advance the cursor past a name occurring in an RR, following compression pointers but with a **hard cap** on pointer hops / total work to defeat loops. (Reused by E2.6.)

## Design notes
- The question-name reader needs no decompression logic at all (§2.1); only the RR name-skip handles pointers, and only defensively.
- Prefer standard traits (`FromStr`/`Display`) over bespoke parse/format methods (CLAUDE.md).

## Validation
- Round-trip parse ↔ serialize for several names.
- Normalization cases: mixed case → lowercase; missing trailing dot added.
- Oversize label (>63) and oversize name (>255) → error.
- Compression pointer in question position → error.
- Bounded skip terminates with an error on a crafted pointer loop (no hang).