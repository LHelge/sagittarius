---
id: jfy
title: E9.6 · Publish to crates.io
status: done
priority: P2
created: 2026-05-30T13:09:39.403741541Z
updated: 2026-05-30T13:55:27.313394060Z
tags:
- release
- ci
depends_on:
- wjp
parent: 8wg
---

Publish the crate so `cargo install sagittarius` works. See SPEC §10, §12.

## Deliverables
- A `publish-crate` job (`needs: verify`) that runs `cargo publish` using the **`CARGO_REGISTRY_TOKEN`** repo secret, with `SQLX_OFFLINE=true`.
- Pre-publish sanity: `cargo publish --dry-run` (or `cargo package --list`) to confirm the packaged crate includes the **migrations**, **embedded UI assets**, and **license files**, and excludes junk (dev DBs, `.sqlx` not required at install since builds are offline-checked, but verify it compiles from the packaged tarball).
- Round out `Cargo.toml` publish metadata if missing: `keywords`, `categories`, `documentation`, `homepage` (name/description/license/repository/readme already set).

## Design notes
- Crate name **`sagittarius` is currently available** on crates.io (verified — does not exist yet). First publish reserves it.
- Operator prerequisite (documented in E9.8): the `CARGO_REGISTRY_TOKEN` secret must be added to the repo before the first tagged release.
- Publishing is **irreversible per-version** — `cargo publish --dry-run` in the gate keeps a bad version from being burned.

## Validation
- `cargo publish --dry-run` passes in CI; after a real tag the version appears on crates.io and `cargo install sagittarius` builds a working binary.
