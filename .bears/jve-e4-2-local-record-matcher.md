---
id: jve
title: E4.2 · Local-record matcher
status: done
priority: P1
created: 2026-05-29T07:11:11.233024344Z
updated: 2026-05-29T13:36:20.919079672Z
tags:
- dns
depends_on:
- nq7
parent: rbn
---

Authoritative local-record matching: exact names plus wildcard suffix-probe, most-specific match wins. See SPEC §3.1, §5 step 3.

## Deliverables
- Exact map keyed by `(Name, QType)` for literal names, plus **wildcard suffix-probe** keyed by `(wildcard Name, QType)`: strip leftmost labels and probe `*.<suffix>`, with the **most-specific** match winning (e.g. `*.a.home.lan` beats `*.home.lan`).
- Track local-name existence separately from qtype-specific record matches so the pipeline can distinguish:
  - `Answer(record)` — name/wildcard matched and qtype has an A/AAAA record,
  - `NameExistsNoData` — name/wildcard matched locally, but no record exists for the requested qtype,
  - `Miss` — no local exact/wildcard name matched at all.
- `Record` carries type (A / AAAA) + value + TTL. (CNAME deferred unless explicitly added later.)
- Held behind `arc-swap` like the match sets (rebuild-and-swap on admin edit).
- Returns a typed local-match result — **not** wire bytes; response synthesis is E2.5, invoked by the pipeline.

## Design notes
- Internal precedence (most-specific wildcard) lives here; cross-feature precedence (local vs blocking) is the E6 layer order.
- Deliberately not optimized for large volumes — a handful of records (SPEC §3.1).

## Validation
- Exact match returns the record.
- Wildcard most-specific selection across nested wildcards.
- Same local name can hold both A and AAAA records; qtype-specific lookup returns the right one.
- A local-name qtype mismatch returns `NameExistsNoData` so E6 can synthesize authoritative NODATA without forwarding.
- **No false positives**: `*.home.lan` matches `x.home.lan` but not `home.lan` nor `evilhome.lan`.
- Miss returns none.
