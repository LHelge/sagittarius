---
id: nve
title: E7.1 · HTTP fetcher with conditional requests
status: done
priority: P1
created: 2026-05-29T07:47:07.772204123Z
updated: 2026-05-29T19:30:56.598360420Z
tags:
- blocklist
depends_on:
- '783'
parent: dqh
---

A pure HTTP fetcher for blocklist sources with conditional-request support. See SPEC §6.

## Deliverables
- `cargo add reqwest` with `default-features = false` and features `rustls-tls` (matches hickory's TLS stack) + `gzip` (auto-decompress large/gzipped lists; optionally `brotli`).
- A fetcher that, given a URL + optional stored validators (ETag / Last-Modified), issues a conditional GET (`If-None-Match` / `If-Modified-Since`) and returns:
  - `Modified { body, etag, last_modified }` on `200`,
  - `NotModified` on `304`.
- Per-fetch **timeout (default 30 s)** and a **max-size guard (default 64 MiB)** (defensive against huge/hostile lists).

## Design notes
- Pure HTTP only — no persistence here; the scheduler (E7.4) stores results via E3.6. Keeps this unit testable against a mock HTTP server.
- Reuse one `reqwest::Client` across fetches.

## Validation
- `200` returns the body + new validators.
- A `304` (against a mock server seeded with a matching ETag) returns `NotModified`.
- A gzip-encoded body decompresses automatically.
- Oversize / timeout cases are guarded and surface typed errors.