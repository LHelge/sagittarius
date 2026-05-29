---
id: gyj
title: E8.6 · Live query log over SSE (Datastar) + filtering
status: open
priority: P1
created: 2026-05-29T07:57:38.577137943Z
updated: 2026-05-29T07:57:38.577137943Z
tags:
- web
depends_on:
- gv7
- 5jx
parent: p6b
---

A live, filterable query log streamed over SSE, sharing one stream with the dashboard counters. See SPEC §9, §3.1.

## Deliverables
- An SSE endpoint subscribing to the E6.6 broadcast; the bounded ring buffer seeds a freshly opened view with recent history, then live events stream in.
- Datastar drives the UI: **`PatchElements`** appends/merges log rows, **`PatchSignals`** updates the dashboard counters — so a **single SSE stream updates the log and the dashboard together** (SPEC §9).
- Client-side / server-side **filtering** (e.g. by outcome blocked/forwarded/cached, by domain/client).

## Design notes
- One receiver per SSE subscriber; backpressure/lagging handled gracefully (drop-oldest semantics).
- Rows carry E6.6's detailed outcome (`BlockedByBlocklist`, `BlockedByAdmin`, `Local`, `Forwarded`, etc.) so E8.7 can render only actions that will actually take effect.

## Validation
- The SSE endpoint delivers live query events to a connected client.
- A late subscriber first sees recent history (from the ring buffer), then live events.
- Filtering narrows the displayed rows; the dashboard counters update over the same stream.
