---
id: e5x
title: E13.2 · Synthesize PTR answers from local records
status: done
priority: P2
created: "2026-05-30T20:23:52.217428115Z"
updated: "2026-06-13T14:32:20.625493933Z"
tags:
  - dns
  - codec
depends_on:
  - b8k
parent: s2e
---

Answer PTR for IPs we own (manual local records), authoritatively. This is the codec-touching subtask.

## Reverse index
- Build an `IpAddr → Name` index from the existing `LocalRecords` (which hold `name → A/AAAA`). A device with multiple names picks a canonical one (document the rule — e.g. first by insertion / shortest). Rebuild alongside the `LocalRecords` snapshot in `hydrate` and on local-record edits (swap together).

## Codec synthesis (`src/codec/synth.rs`)
- Add a PTR-RR synth path: rtype 12, **RDATA = the target name encoded as DNS labels** (encode via `Name::write` into a temp buffer, set RDLENGTH). EDNS-aware like the other synth paths. Authoritative (AA=1).

## Decision stack (`src/resolver/pipeline/layers.rs`)
- In the local stage: if the question parses as a reverse query (E13.1) and the IP is in the reverse index → synth the PTR answer (`Outcome::Local`).
- If the IP is **not** ours → `Miss` (fall through to conditional forwarding / upstream). Do **not** answer NODATA for arbitrary reverse zones — that's the router's job (E13.4). Document this precedence: local PTR synth first, then conditional forward.

## Tests
- PTR for a local A/AAAA record returns the correct name; response well-formed (rtype 12, name RDATA, AA=1).
- PTR for an unknown IP falls through (not answered here).
- Reverse index rebuilds after a local-record change.