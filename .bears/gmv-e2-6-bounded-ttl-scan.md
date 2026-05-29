---
id: gmv
title: E2.6 · Bounded TTL scan
status: done
priority: P1
created: 2026-05-29T06:24:37.654347868Z
updated: 2026-05-29T11:36:22.960794506Z
tags:
- codec
- dns
depends_on:
- nq7
- rf6
parent: rjw
---

Forward-path-only single walk of the RR sections to find the minimum TTL and record each TTL field's byte offset. See SPEC §5 step 9, §8.

## Deliverables
- Walk the answer / authority / additional sections per the header counts (E2.3); for each RR:
  - skip the owner name with the **bounded name-skip** from E2.2,
  - read TYPE / CLASS / TTL / RDLENGTH, then skip RDATA.
- Track the **minimum TTL** and collect the **byte offset of each real RR TTL field** (for in-place patching on cache serve).
- Recognize EDNS OPT pseudo-RRs (`TYPE=41`) and **exclude** their TTL-shaped field from min-TTL and offset collection; that field contains extended rcode/version/flags, not cache TTL.
- Hard-cap total iterations / work so malformed counts or pointer loops cannot hang — return an error instead.
- Output a **public `TtlScan { min_ttl: Option<u32>, ttl_offsets: Vec<usize> }`** type, consumed by E4.3 (cache) and E6.3 (cache-store + serve patching). `min_ttl=None` means no real TTL-bearing RRs were present.

## Design notes
- Forward path only — never runs on the routing fast path (§2.1).
- This walks past the question, unlike E2.4; it is a deliberately bounded reader.

## Validation
- Fixture multi-RR response → correct min TTL and correct offsets.
- Patching the TTL at the recorded offsets yields a valid, decremented TTL on re-parse.
- Crafted pointer loop / oversized counts terminate with an error, not a hang.
- A response with only OPT/no real RRs yields `min_ttl=None` and no TTL offsets.
