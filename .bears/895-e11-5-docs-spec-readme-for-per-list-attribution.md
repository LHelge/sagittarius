---
id: '895'
title: 'E11.5 · Docs: SPEC + README for per-list attribution'
status: done
priority: P2
created: 2026-05-30T19:55:04.854586552Z
updated: 2026-06-01T04:34:00.337716284Z
tags:
- docs
depends_on:
- rqp
- p7t
- q3r
parent: cds
---

Document per-list attribution and effectiveness.

## SPEC.md
- **§6 Blocklists**: the aggregated set now records a per-domain **primary source** (lowest-id tie-break for overlaps); document the off-hot-path attribution and the single-primary trade-off (no overlap/unique-credit analysis).
- **§4 Data model**: note `query_log.blocklist_id` (nullable, plain integer — no FK, to preserve history after a list is deleted).
- **§9 Web administration**: the blocklists page shows windowed per-list block counts ("effectiveness").
- **§3.1 / §3.2**: blocklist set is now a `Name → primary blocklist_id` map behind `arc-swap`; the decision layer remains a presence check.

## README.md
- Mention per-list effectiveness ("see which lists are pulling their weight").

## Tests
- None (docs only); keep SPEC ↔ README consistent.