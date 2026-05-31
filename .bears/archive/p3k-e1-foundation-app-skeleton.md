---
id: p3k
title: E1 · Foundation & app skeleton
type: epic
status: done
priority: P0
created: 2026-05-28T22:37:53.795402437Z
updated: 2026-05-29T10:39:01.478283597Z
tags:
- foundation
---

Establish the binary's structural backbone and cross-cutting concerns so every later epic plugs into a consistent foundation. This epic produces a runnable (but inert) `sagittarius` binary.

**Scope**
- Module layout (single crate to start): `config`, `codec`, `resolver`, `storage`, `web`, plus a small `app`/runtime that owns shared state and wires subsystems.
- Error-handling strategy: `thiserror` for typed library errors, `anyhow` at the binary boundary; shared `Result` aliases.
- `clap` (derive) CLI + config resolution with precedence **flag > env > default**:
  - `--dns-addr` (default `0.0.0.0:53`, repeatable for dual-stack `[::]:53`)
  - `--admin-addr` (default `127.0.0.1:8080`)
  - `--db-path` (default `sagittarius.db`)
  - `--session-cookie-secure` (`auto | always | never`, default `auto`)
- `tracing` + `tracing-subscriber` init to stdout; level via `EnvFilter`/`RUST_LOG`.
- Graceful-shutdown harness: catch SIGTERM/SIGINT, broadcast a shutdown signal, drain in-flight work within a bounded timeout, close resources, exit 0.
- CI workflow: `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`.

**Design notes**
- Behaviour on types: `Config` built via `TryFrom`/builder; avoid free functions (CLAUDE.md).
- SPEC §2 (stack), §10 (CLI/deploy).

**Out of scope**
- Real DNS handling, storage, and web logic — those are their own epics; here only the skeleton, wiring, and stubs/traits they slot into.

**Validation**
- `--help` lists flags with documented defaults; bad args rejected with helpful errors.
- Process starts, logs a startup line, and exits cleanly on SIGTERM/SIGINT within the drain timeout.
- Unit tests for config precedence (flag/env/default) and address parsing.
- CI green (fmt, clippy with denied warnings, test).
