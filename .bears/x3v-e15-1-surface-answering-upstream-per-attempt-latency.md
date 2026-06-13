---
id: x3v
title: E15.1 · Surface answering upstream + per-attempt latency
status: done
priority: P2
created: "2026-05-30T20:47:14.131751902Z"
updated: "2026-06-13T12:49:09.988868552Z"
tags:
  - upstream
  - dns
parent: xa8
---

The shared foundation: make the forward path report *which* upstream answered and *how long* it took.

## Work
- In `UpstreamPool::forward` (`resolver/upstream/pool.rs`), measure each attempt's latency and capture the answering upstream's `SocketAddr` (or index → addr). Return it alongside the result — extend `ForwardResult` with `upstream: SocketAddr` + `latency: Duration` (the successful attempt).
- Thread it through `ForwardService` (`resolver/pipeline/forward.rs`) → `ForwardOutput`/`PipelineResponse` so the telemetry layer can read it.
- Populate `QueryEvent.upstream` (currently always `None`) in `engine.rs`'s `TelemetryService`, and set the per-query upstream latency where useful (the event already has `with_upstream`/`with_latency`).

## Notes
- Failure attempts also have a latency/target — keep that available for E15.2 (per-upstream health), even though only the successful upstream lands on the `QueryEvent`.
- This automatically populates E10's `query_log.upstream` column once both ship — no edge needed.

## Tests
- A forwarded answer's `QueryEvent.upstream` equals the upstream that actually answered (mock pool with two upstreams; the one that responds is recorded).
- Latency is measured and non-zero.
- Failover: when the first upstream times out and the second answers, the second is recorded.