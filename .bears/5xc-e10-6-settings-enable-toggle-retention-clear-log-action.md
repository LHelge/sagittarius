---
id: 5xc
title: 'E10.6 · Settings: enable toggle, retention, clear-log action'
status: done
priority: P2
created: 2026-05-30T19:32:19.319060564Z
updated: 2026-05-31T15:50:56.268801129Z
tags:
- web
depends_on:
- pcm
- 6f3
parent: 55z
---

Expose the query-log controls in settings and thread them into the hot-path snapshot.

## Storage / settings model (`src/storage/settings.rs`)
- Extend `Settings`, the private `SettingsRow` projection, and the read/update queries to include `query_log_enabled: bool` and `query_log_retention_days: u32`.

## RuntimeSettings (`src/resolver/state.rs`)
- Add `query_log_enabled` and `query_log_retention_days` to `RuntimeSettings` and `From<&Settings>`, so the writer (E10.4) can gate cheaply on the hot path and the purge task (E10.5) can read retention from the live snapshot.

## Web (`src/web/settings.rs` + template)
- Settings form: a checkbox for **Enable query logging** and a number input for **Retention (days)**. On save, persist then `state.store_settings(...)`.
- **Clear query log now**: a CSRF-protected `POST` action calling `SqliteQueryLogRepo::clear_all` (E10.3), with a confirming toast. (Depends on E10.3 at integration time — note the repo call; can stub if E10.3 lands later, but prefer ordering after it.)

## Tests
- Settings round-trip including the two new fields; defaults (enabled=true, 30) read correctly.
- `RuntimeSettings::from(&Settings)` carries the new fields.
- Settings page renders the toggle + retention input; clear-log POST is wired and CSRF-protected.