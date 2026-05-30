---
id: 6v2
title: E9.4 · Release workflow skeleton + tag/version gate
status: open
priority: P2
created: 2026-05-30T13:09:30.586656102Z
updated: 2026-05-30T13:09:30.586656102Z
tags:
- release
- ci
depends_on:
- pyd
parent: 8wg
---

Foundation for the tag-triggered release pipeline. Establishes the workflow file, trigger, permissions model, and a fail-fast version gate that every downstream job hangs off. See SPEC §10, §12.

## Deliverables
- New `.github/workflows/release.yml` triggered **only on semver tags**:
  ```yaml
  on:
    push:
      tags: ['v[0-9]+.[0-9]+.[0-9]+*']   # v0.1.0, v1.2.3-rc1
  ```
- Top-level least-privilege `permissions: {}`; each job opts into exactly what it needs (later jobs add `contents: write`, `packages: write`).
- `concurrency` group keyed on the tag so re-pushed tags don't race.
- A `verify` job (the gate the rest `needs:`) that:
  - extracts the version from `${{ github.ref_name }}` (strip leading `v`),
  - asserts it **equals** the `version` in `Cargo.toml` — fail loudly on drift,
  - runs the standard `fmt --check` + `clippy -D warnings` + `cargo test` with `SQLX_OFFLINE=true` (mirror the CI workflow) so a tag can't ship a red tree.

## Design notes
- Hand-rolled + git-cliff approach (no cargo-dist / release-plz). This task is purely the scaffold; changelog/binaries/crates.io/docker land in E9.5–E9.7 as sibling jobs gated on `verify`.
- Reuse the existing `Swatinem/rust-cache` + `dtolnay/rust-toolchain` patterns from `ci.yml` for consistency.

## Validation
- Pushing a `vX.Y.Z` tag whose number matches `Cargo.toml` runs `verify` green; a mismatched tag fails the gate before anything is published.
