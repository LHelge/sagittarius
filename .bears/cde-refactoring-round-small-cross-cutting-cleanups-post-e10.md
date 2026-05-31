---
id: cde
title: Refactoring round — small cross-cutting cleanups (post-E10)
type: epic
status: open
priority: P3
created: 2026-05-31T18:34:52.879217300Z
updated: 2026-05-31T19:10:21.554285911Z
tags:
- refactor
- tech-debt
---

A focused cleanup pass the user wants to run **right after PR #15 (E10) merges** (now merged, main @ `77bde0e`), before resuming the v0.2 feature epics (E11–E15) — confirm ordering with the user. Goal: reduce error-prone boilerplate and inconsistencies. Keep each change small and independently reviewable; pure refactors (behaviour unchanged), full gate per change, one commit per cleanup. When the round starts, break the items below into child subtasks.

## Seed candidates (noted during E10)

1. **Adopt `strum` for the string-token enums.** `Outcome` (pipeline), `Transport` (upstreams), `BlockingMode` (settings), `RecordType` (local_records), `BlocklistFormat` (blocklists) hand-roll `as_str`/`Display`/`FromStr` + bespoke errors.
   - Derive `EnumString` + `IntoStaticStr` (+ `EnumIter`); `EnumIter` removes the manual `ALL_OUTCOMES` array in `pipeline/mod.rs` tests (the one spot the compiler doesn't police).
   - **`Outcome` keeps its hand-written `Display`** (human labels) separate from the persistence token. Preserve value-carrying parse errors (strum yields a valueless `ParseError::VariantNotFound`; `.map_err` into `Error::Decode`). Leave the numeric codec enums (`Qtype`/`Qclass`/`Rcode`) hand-rolled — strum doesn't fit.

2. **Unify `Qtype` rendering.** `web/live_log.rs:203` uses `format!("{:?}", ev.qtype)` → `Aaaa`/`Other(15)`, while history uses `QueryLogRecord::qtype_text` → `AAAA`/`TYPE15` (RFC 3597). Give `Qtype` one canonical `Display`/`as_str` and use it in both. (Confirmed in review: qtype is the *only* Debug-as-display site.)

3. **Centralize day/ms time constants** (`MS_PER_DAY`, dashboard `WINDOW_MS`, auth `IDLE_SECS`/`ABSOLUTE_SECS`, blocklists `86_400`).
   - **No `chrono`** (decided): we store epoch INTEGER columns; SQLite has no native temporal type (sqlx would map chrono as TEXT, losing the integer `WHERE ts < cutoff` purge + `idx_query_log_ts` scan); compile-time mapping is Postgres-only; these are rolling fixed windows (no calendar math).
   - **Home it on `time::Clock`, split by kind:** generic "now ± offset" helpers on `Clock` (`millis_ago(Duration)`, `secs_from_now(Duration)`, maybe a `const fn days(n) -> Duration`); policy windows stay as typed `Duration` consts in their owning subsystem (auth/dashboard/purge/blocklists). Prefer `std::time::Duration` over raw-`i64` unit consts (units are mixed ms vs secs). Keep epoch-`i64` at the DB boundary.
   - **Retention unit stays days** (reviewed): operator-facing policy knob, matches the settings convention (`blocklist_refresh_interval` is seconds, not ms); the ms is event-precision, unrelated. The smell is the bare multiply, cured by the `Clock::millis_ago(Duration…)` helper above, not by changing the column unit.
   - **Watch-list:** revisit `chrono`/`jiff` when the deferred **time-series charts** land (timezone-aware bucketing + axis formatting).

4. **Repo construction churn.** `SomeRepo::new(self.db.pool().clone())` appears ~60× across `web/*`. Thin accessors (e.g. `Db::query_log()`/`Db::settings()`, or helpers on `AppState`) to cut clone noise and centralize wiring.

## Found in post-merge review (2026-05-31)

5. **Collapse web handler error plumbing.** ~34 handlers across `web/{settings,lists,blocklists,records,upstreams,auth}.rs` use `match … { Ok(t) => t.into_response(), Err(e) => e.into_response() }`. `WebError` already impls `IntoResponse` + `From<storage::Error>`, and axum accepts `Result<T: IntoResponse, E: IntoResponse>`, so most handlers can return `Result<impl IntoResponse, WebError>` and use `?`. Branchy handlers (e.g. `settings_save`'s `BadRequest` re-render) stay explicit. **High value.**

6. **Extract an HTTP test harness.** The bind → `serve` → login → cookie-extract → csrf → cancel dance is copy-pasted across ~8 integration tests in `web/mod.rs` (~50 boilerplate lines each). A `TestServer` helper (`spawn(state)` + `login("admin","s3cret") -> {base, cookie, csrf, handle}`, shutdown on drop) cuts hundreds of lines and lowers the cost of future web tests. **High value (test ergonomics).**

7. **Datastar one-shot SSE response helper.** `Sse::new(async_stream::stream!{ yield … })` is duplicated (`lists.rs::toast`, `live_log.rs::query_log_older`). A `datastar_response(impl IntoIterator<Item = Event>) -> Response` centralizes the wrapping; the hand-rolled signal JSON (`format!(r#"{{"oldest":…}}"#)`) could route through `serde_json` while there. **Medium.**

8. **Guard the Outcome tokens duplicated in SQL.** `query_log.rs:296` hardcodes `'blocked-admin','blocked-blocklist'` in `counts_since`, duplicating `Outcome::as_str`/`category()`. `query!` needs literal SQL so the IN-list can't be code-parametrized, but a small test asserting the SQL's "blocked" set equals the `Outcome` variants with `category()=="blocked"` prevents silent drift — land it alongside the strum token rename (#1). **Medium (correctness-adjacent).**

9. **Shared temp-DB test helper.** ~18 modules each define their own `Db::connect(tmpdir)` helper (`open_repo`/`open_temp_db`/`state`/`setup`). A single `#[cfg(test)]` `test_support::temp_db()` would centralize it. **Low** (per-module helpers are idiomatic, but the count is high).

10. **Repo trait doc boilerplate.** 8 repos repeat an identical `#[allow(async_fn_in_trait)]` + multi-line "Note on async_fn_in_trait" doc + `pub type Result<T>`. The attribute can't be DRYed, but the duplicated doc paragraph can collapse to a one-line pointer to a canonical note. **Very low — optional.**