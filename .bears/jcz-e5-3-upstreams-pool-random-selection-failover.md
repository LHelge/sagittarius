---
id: jcz
title: 'E5.3 · Upstreams pool: random selection + failover'
status: done
priority: P1
created: 2026-05-29T07:23:26.848297884Z
updated: 2026-05-29T15:43:48.587616794Z
tags:
- upstream
- dns
depends_on:
- z9g
- bfx
parent: tbk
---

An upstream pool that spreads load randomly and fails over on error/timeout. See SPEC §7.

## Deliverables
- `cargo add rand`. An `Upstreams` / `UpstreamPool` type holding the configured clients (built via E5.1, queried via E5.2).
- **Random** upstream selection per query; on error/timeout, **fail over** to another randomly chosen upstream — up to a configurable retry budget (**default 1 failover**, i.e. at most 2 upstreams tried); when all fail, return a typed all-fail error (the pipeline maps it to SERVFAIL). This keeps the default outer pipeline timeout comfortably above the worst-case upstream timeout budget.
- Forwarding returns E5.2's **`ForwardResult`** (raw bytes + `negative_ttl` + `is_negative`) — propagate it, don't reduce to just bytes.
- Selection behind a small **trait** (e.g. `UpstreamSelector`) so future strategies (fastest, weighted) drop in without churn.
- Spawn/hold the background driver futures (from E5.1) on the runtime's **TaskTracker** (E1.4) so they drain on graceful shutdown.
- Expose a typed upstream-pool handle that E8.9 can rebuild/swap after upstream settings change. Existing in-flight queries may finish on the old pool; new queries use the new snapshot.

## Design notes
- Behaviour on the pool type; the selector trait is the extension seam.
- Connection reuse: keep clients alive across queries. Each attempt uses E5.2's per-attempt timeout (default 2 s); the default two-attempt budget fits inside E6.4's 5 s pipeline timeout.

## Validation
- Random spread across multiple upstreams (statistical check over many calls).
- First upstream fails → a second is tried and succeeds; the `ForwardResult` is returned intact.
- All upstreams fail (within the retry budget) → typed all-fail error.
- The selector trait is swappable (a deterministic test selector).
- Swapping the upstream pool changes which upstreams new queries use without restarting the process.
