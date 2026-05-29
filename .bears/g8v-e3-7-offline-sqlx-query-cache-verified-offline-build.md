---
id: g8v
title: E3.7 · Offline .sqlx query cache + verified offline build
status: done
priority: P1
created: 2026-05-29T06:55:49.139262691Z
updated: 2026-05-29T13:03:21.445604013Z
tags:
- storage
- ci
depends_on:
- beg
- y72
- dyd
- nuj
parent: hga
---

Commit the sqlx offline query cache so the project compiles with no live database, and verify it in CI. Depends on the repositories so all `query!`/`query_as!` invocations are captured. See SPEC §2 (compile-time-checked queries).

## Deliverables
- Document the dev workflow (e.g. in README/CONTRIBUTING): set `DATABASE_URL` to a dev SQLite file, run migrations, then `cargo sqlx prepare --workspace --all-targets` (the `--all-targets` so queries in tests are captured too).
- Commit the generated `.sqlx/` directory to version control.
- Update CI from E1.5 to set `SQLX_OFFLINE=true` and add `cargo sqlx prepare --check` so drift between queries/schema and the cache fails the build.

## Design notes
- `SQLX_OFFLINE=true` makes builds use `.sqlx/` and ignore any stray `DATABASE_URL`/`.env`; `cargo sqlx prepare` still connects to refresh the cache.

## Validation
- `SQLX_OFFLINE=true cargo build` (and `cargo test --no-run`) succeed with no database present.
- `cargo sqlx prepare --check` passes in CI; an intentionally stale `.sqlx` fails it (verify once).
