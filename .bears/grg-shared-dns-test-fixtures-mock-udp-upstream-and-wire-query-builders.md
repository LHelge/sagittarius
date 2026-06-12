---
id: grg
title: "Shared DNS test fixtures: mock UDP upstream and wire-query builders"
status: done
priority: P3
created: "2026-06-12T23:03:46.411571199Z"
updated: "2026-06-12T23:26:28.982163792Z"
tags:
  - test
  - tech-debt
parent: cde
---

Duplicated test fixtures across the resolver tests:

- `spawn_mock_udp` (a tokio UDP responder driven by a `FnMut(Message) -> Option<Message>` handler) is copy-pasted **3×**: `upstream/forward.rs:152`, `upstream/pool.rs:292`, `pipeline/forward.rs:290`.
- `stock_question()` 2× (`upstream/forward.rs:182`, `upstream/pool.rs:344`); the positive-A / NXDOMAIN-with-SOA mock handlers are rebuilt inline in `pipeline/forward.rs` too.
- `build_a_query`-style wire builders appear in ~7 files (`pipeline/{mod,layers,forward,middleware,listener}.rs`, plus variants in `codec/{message,synth}.rs`).

**Change:** grow `test_support` (it's `#[cfg(test)]`-only) with:
- `mock_udp_upstream(handler) -> SocketAddr` plus the two stock handlers (`positive_a`, `nxdomain_with_soa`),
- a wire-format query builder (`a_query(id, name)` / `aaaa_query(id, name)` or a tiny builder),
- `stock_question()`.

Migrate the call sites; while touching those tests, drop the needless `req.clone()`s flagged by nursery `redundant_clone` in `upstream/forward.rs`, `upstream/pool.rs`, `pipeline/forward.rs`, `resolver/cache.rs` tests. The codec modules' local builders may stay if importing test_support would invert the dependency direction — judge per file.

Commit: `test: consolidate mock-upstream and wire-query fixtures in test_support`