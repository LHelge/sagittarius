---
id: zc5
title: E2.1 · Wire reader/writer primitives & framing
status: open
priority: P1
created: 2026-05-29T06:24:05.182142111Z
updated: 2026-05-29T06:24:05.182142111Z
tags:
- codec
- dns
depends_on:
- '783'
parent: rjw
---

The lowest layer of the codec — bounds-checked reads/writes over `bytes` that never panic, plus DNS message framing. See SPEC §2.1, §3 (codec).

## Deliverables
- `cargo add bytes`.
- A bounds-checked cursor/reader over `&[u8]` / `Bytes`: `u8` / `u16` / `u32` (big-endian) and slice reads that return a typed error on truncation — **never index-panic**.
- An output writer over `BytesMut` for response synthesis (append integers/slices, track length).
- Framing helpers:
  - UDP — a datagram is exactly one message.
  - TCP — 2-byte big-endian length prefix encode/decode.
  - (Listener socket IO itself is E6; this provides only the codec-side framing logic.)

## Design notes
- Behaviour on types (a `Reader`/`Writer` with methods), not free functions (CLAUDE.md).
- Errors come from the E1.1 `error` convention (typed, `thiserror`).
- Zero/low-copy: prefer slicing `Bytes` over copying where possible.

## Validation
- Short-buffer reads of each width error cleanly (no panic).
- Round-trip of each integer width and slice read.
- TCP length-prefix encode/decode, incl. a truncated prefix → error.