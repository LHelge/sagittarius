---
id: '783'
title: E1.1 · Crate scaffolding, module layout & error strategy
status: open
priority: P0
created: 2026-05-29T05:59:59.079930525Z
updated: 2026-05-29T05:59:59.079930525Z
tags:
- foundation
parent: p3k
---

Turn the hello-world binary into a `lib + bin` crate with the module skeleton every later epic plugs into, the foundational dependency baseline, and the project-wide error convention. Produces a runnable but inert crate.

See SPEC §2 (stack, single crate to start), CLAUDE.md (behaviour on types; `cargo add` for deps).

## Deliverables
- Split into `src/lib.rs` (library) + `src/main.rs` (thin bin that calls into the lib). Edition 2024.
- Stub modules with doc comments, no logic yet: `config`, `codec`, `resolver`, `storage`, `web`, `app` (the runtime that will own shared state and wire subsystems).
- Dependency baseline added via **`cargo add`** (never hand-edit `Cargo.toml`):
  - `tokio` (features: `rt-multi-thread`, `macros`, `net`, `signal`, `time`, `sync`)
  - `tracing`, `tracing-subscriber` (features: `env-filter`, `fmt`)
  - `clap` (features: `derive`, `env`)
  - `thiserror`, `anyhow`
  - `tokio-util` (features needed for `CancellationToken` + `TaskTracker`)
- Error strategy:
  - Per-module typed errors with `thiserror`.
  - A crate-level `error` module exposing an `Error` enum and a `Result<T>` alias.
  - `anyhow` reserved for the `main.rs` boundary only.
  - Document the convention in a short doc comment.

## Design notes
- Keep everything in a single crate (modules) for now — workspace split is not in scope.
- Behaviour lives on types/traits; avoid free functions where a method fits (CLAUDE.md).
- Stubs should reference the error types from at least one place so the convention compiles end-to-end.

## Out of scope
- Real DNS/storage/web logic (their own epics) — only the skeleton, deps, and error scaffolding.

## Validation
- `cargo build` and `cargo test` succeed (stub/empty tests OK).
- `cargo clippy --all-targets -- -D warnings` clean; `cargo fmt --check` clean.
- Module tree compiles with the documented `error::Result` referenced from at least one stub.