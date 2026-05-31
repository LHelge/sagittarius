---
id: nuj
title: E1.5 · CI workflow & pre-commit hooks
status: done
priority: P1
created: 2026-05-29T06:00:36.643424636Z
updated: 2026-05-29T10:39:01.478112963Z
tags:
- foundation
- ci
depends_on:
- bfx
parent: p3k
---

Enforce the CLAUDE.md quality gate (`cargo fmt`, `cargo clippy`, `cargo test`) both locally (pre-commit) and in CI.

## Deliverables
### CI (GitHub Actions)
- Workflow running, on push/PR:
  - `cargo fmt --check`
  - `cargo clippy --all-targets -- -D warnings`
  - `cargo test`
- Stable Rust toolchain with edition-2024 support; dependency/build caching (e.g. `Swatinem/rust-cache`).
- Do **not** set `SQLX_OFFLINE=true` yet. E3.7 will add the `.sqlx/` cache, enable `SQLX_OFFLINE=true`, and add `cargo sqlx prepare --check` once all compile-time sqlx queries exist. This avoids breaking intermediate E3 tasks before the offline cache is generated.

### Pre-commit hooks
- Local pre-commit hook(s) running the same three checks (`cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`) before a commit is accepted.
- Use a mechanism that is committed to the repo and easy to enable (e.g. a `pre-commit` config, or a tracked git hook + a one-line install step). Document how to enable it in the README/CONTRIBUTING.
- Keep it fast enough to not be painful (e.g. fmt + clippy on commit; document if test is gated to pre-push instead — call out the decision).

## Design notes
- The CI and local hooks should run the **same** commands so "green locally" implies "green in CI".
- The sqlx offline gate is intentionally staged later in E3.7; until then CI remains the Rust-only quality gate.

## Validation
- CI workflow runs green on a PR.
- A deliberate fmt/clippy violation fails both the hook and the CI job (verify once).
- The hook install step works from a fresh clone and is documented.
