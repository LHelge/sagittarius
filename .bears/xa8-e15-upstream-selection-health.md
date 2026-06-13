---
id: xa8
title: E15 · Upstream selection & health
type: epic
status: done
priority: P2
created: "2026-05-30T20:47:03.075897654Z"
updated: "2026-06-13T14:04:15.308708334Z"
tags:
  - upstream
  - dns
---

Smarter upstream selection (beyond random) plus per-upstream response-time tracking and telemetry. Concerns the **forward track only** — orthogonal to recursion/DNSSEC (E16/E17). Final epic of the **0.2.0** scope.

## Grounding (current code)
- `UpstreamSelector` trait (`resolver/upstream/pool.rs`) is the seam; `RandomSelector` is the only impl. But `order(count) -> Vec<usize>` only expresses "try in this order, sequentially":
  - **Weighted-by-latency** needs per-upstream latency fed into the selector → the trait signature must grow.
  - **Parallel** needs `UpstreamPool::forward` itself to change (fan out, take first success, cancel the rest) — not just a different order.
- `ForwardResult` carries bytes/negative_ttl/is_negative — **not** which upstream answered, nor latency. `QueryEvent.upstream` exists but is **never populated**. Surfacing that is the shared foundation.

## Synergy (no hard dependency)
Once E15.1 populates `QueryEvent.upstream`, E10's query-log writer persists it automatically (the `query_log.upstream` column already exists from E10.1). E15 does not otherwise depend on E10–E14.

## Locked decisions
- Foundational seam first: surface answering-upstream + per-attempt latency up the forward path.
- Per-upstream health kept in-memory (like `Stats`); dashboard reads a snapshot.
- New strategies behind the (extended) selector seam; parallel mode changes the pool's forward model.

Tests live in each subtask.