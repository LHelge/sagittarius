---
id: cde
title: Refactoring round 2 — cleanups from the 2026-06-13 whole-project review
type: epic
status: open
priority: P3
created: "2026-05-31T18:34:52.879217300Z"
updated: "2026-06-12T23:02:34.591646742Z"
tags:
  - refactor
  - tech-debt
---

A focused cleanup pass: pure refactors (behaviour unchanged), full gate (`cargo fmt` / `clippy` / `test`) per change, one conventional commit per cleanup, each child small and independently reviewable.

## Round 1 — already shipped (discovered during the 2026-06-13 review)

The original ten seed items of this epic were **implemented directly after the E10 merge but bears was never updated**. They map 1:1 to commits on `main`:

| Seed item | Commit |
|---|---|
| 1. strum for string-token enums | `bd5b06d` |
| 2. Unify Qtype rendering | `ac50f3c` (+ `d04c6ce` well-known names) |
| 3. Centralize day/ms time constants on `Clock` | `1fd528d` |
| 4. `Db` repo accessors | `f67ffae` |
| 5. Handler `Result<_, WebError>` + `?` | `897c462`, `33e1398` |
| 6. HTTP `TestServer` harness | `d79f3c7` |
| 7. `datastar_response` helper | `0c3fd27` |
| 8. `counts_since` SQL-token guard test | `d80cb08` |
| 9. Shared `test_support::temp_db()` | `d260474` |
| 10. Repo trait doc boilerplate | `9b7a733` (impl Future refactor) |

All verified present in the code during the review below.

## Round 2 — findings from the whole-project review (2026-06-13)

Full read-through of all modules (codec, resolver, storage, telemetry, blocklist, web, app/cli/config). No correctness bugs found; baseline clippy clean. The codebase is in good shape — the items below are duplication, dead code, hot-path waste, and doc drift. Broken into child subtasks; review them before starting.

1. **EDNS scan once per query (hot path).** `EdnsInfo::scan` walks every RR section and runs up to 4× per forwarded UDP query: `listener::handle_datagram`, `ServeLoop::run_service`, `DecisionStack::call`, and `ForwardService::call` (SERVFAIL path). Scan once at request construction and carry the `Option<EdnsInfo>` on `DnsRequest`. **Medium (perf + clarity).**

2. **Dead byte-cap in `Name::skip_rr` + comment rewrite.** The `MAX_SKIP_BYTES` (512) check at `name.rs:372` is unreachable: `total_label_bytes > MAX_NAME_WIRE_LEN` (255) errors first, since the counter grows ≤63/step. Docs claim "two independent caps". Reconcile (keep one cap, fix docs). Also rewrite the two confusing comments: the wire_len accounting note (~`name.rs:176`) and the meandering pointer-validation note (~`name.rs:316`). **Low (correctness-adjacent doc/logic mismatch).**

3. **Dead UDP framing helpers.** `framing::udp::{wrap,unwrap}_datagram` are identity functions used only by their own tests — no production call sites. Remove (keep the module-doc note that datagram boundary = message boundary). **Low.**

4. **Generic hot-swap primitive.** `MatchSet` and `AttributedSet` (`matchset.rs`) duplicate an identical ArcSwap surface (`new/empty/contains/snapshot/load_full/len/is_empty/store/store_arc/Default/Debug/FromIterator`); `LocalMatcher` and `SharedUpstreamPool` repeat the same pattern smaller. Extract a generic core (e.g. `HotSwap<T>`) or build `AttributedSet` over the generic and keep both public types as thin wrappers. Decide scope at task start: at minimum merge MatchSet/AttributedSet; touching LocalMatcher/SharedUpstreamPool is optional. **Medium.**

5. **Small idiomatic nits (single pass).**
   - `ResolverState::hydrate`: 4× `.map_err(resolver::Error::Storage)` redundant — `Error` already has `#[from] storage::Error`, plain `?` suffices (`state.rs:266,281,289,301`).
   - `ParseError::id()` accessor duplicates the public `id` field (`message.rs:270`) — drop one.
   - Misindented block inside the `tokio::select!` arm in `listener.rs:413-420` (rustfmt skips macro bodies).
   **Very low.**

6. **Finish temp-DB helper migration.** Four modules still define their own `open_temp_db()` instead of `test_support::temp_db()`: `resolver/state.rs:397`, `resolver/pipeline/layers.rs:240`, `resolver/pipeline/forward.rs:249`, `storage/mod.rs:196`. **Low (test hygiene).**

7. **Shared DNS test fixtures.** `spawn_mock_udp` is copy-pasted 3× (`upstream/forward.rs`, `upstream/pool.rs`, `pipeline/forward.rs`), `stock_question` 2×, the positive-A/NXDOMAIN mock handlers 2×, and `build_a_query`-style wire builders ~7×. Extend `test_support` (or a `#[cfg(test)]` codec/upstream test-util) with a query builder and mock-upstream spawner; clean the nursery-level redundant `req.clone()`s in those tests while there. **Medium (test ergonomics).**

8. **Docs drift sweep.**
   - `blocklist/scheduler.rs` module + `refresh_once` docs still say the blocklist is a `MatchSet`; it's an `AttributedSet` since E11.
   - `engine.rs:171-188`: the `TryFrom<&Upstream>` mapping description is attached to the `UnmappableUpstream` struct doc.
   - `# Safety` rustdoc headings on safe fns (`Name::from_normalized`, comment in `Query::question_wire`) — rename to "Invariants" (Safety implies `unsafe`).
   - tracing fields render qtype via Debug (`qtype = ?…` in `event.rs:112` `QueryEvent::emit`, `forward.rs:166`) — use the canonical Display from `ac50f3c`.
   **Low.**

### Explicitly considered, not queued

- `insert_batch` per-row INSERT loop: fine for SQLite-with-WAL at this batch size; multi-row VALUES would complicate the compile-time macro for no measured win.
- `Header` set_/with_ builder boilerplate: macro-izing would hurt readability more than the repetition does.
- `settings.rs` `narrow_u32/u64` helpers: only used in one module; leave until a second consumer appears.
- pedantic/nursery clippy wholesale: gate stays default clippy; individual valuable hits are folded into the tasks above.