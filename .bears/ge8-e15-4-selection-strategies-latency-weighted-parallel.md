---
id: ge8
title: "E15.4 · Selection strategies: latency-weighted + parallel"
status: done
priority: P2
created: "2026-05-30T20:47:58.600437282Z"
updated: "2026-06-13T13:23:59.583435708Z"
tags:
  - upstream
  - dns
depends_on:
  - y7h
parent: xa8
---

Add selection strategies beyond random. This is the chunkiest subtask — parallel changes the pool's forward model.

## Selector seam
- Extend the `UpstreamSelector` seam so a strategy can see per-upstream health (E15.2) — e.g. `order(&[UpstreamHealth])` instead of `order(count)`. Update `RandomSelector` accordingly (ignores health).
- **`LatencyWeightedSelector`**: weighted-random ordering biased toward lower-latency / higher-success upstreams (e.g. weight ∝ 1/EWMA, penalize recent failures). Still sequential-with-failover.

## Parallel mode (pool change)
- Add a **parallel** forwarding path to `UpstreamPool::forward`: fan out to the first N upstreams concurrently, return the first successful answer, cancel the rest. This is a new code path, not just an `order()` — model it explicitly (e.g. a strategy/mode the pool matches on).
- Respect a bounded fan-out N and the existing per-attempt timeout.

## Tests
- `LatencyWeightedSelector` favors the faster upstream over many trials (statistical, loose bounds — mirror `random_selector_spread`).
- Parallel mode returns the fastest responder and does not wait for slow/silent ones (mock: one fast, one slow/silent).
- Failover semantics preserved for the sequential strategies.