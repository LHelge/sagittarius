---
id: 3t7
title: E1.3 · Tracing / logging initialization
status: open
priority: P1
created: 2026-05-29T06:00:14.828714036Z
updated: 2026-05-29T06:00:14.828714036Z
tags:
- foundation
- logging
depends_on:
- '783'
parent: p3k
---

Structured logging to stdout with verbosity controlled via `RUST_LOG` / `EnvFilter`. See SPEC §2, §11.

## Deliverables
- `tracing-subscriber` initialization:
  - `fmt` layer to stdout.
  - `EnvFilter` with a sensible default (e.g. `info`), overridable by `RUST_LOG`.
- A single init entry point (a method on a `Telemetry`/logging type) called once from the runtime; safe against double-init (use `try_init` semantics so tests don't panic).
- Emit a structured startup line once logging is up: binary name + version + resolved bind addresses (DNS + admin) + db path.

## Design notes
- Verbosity is operator-configurable (SPEC §11). Keep the format compact and structured.
- This is the logging backbone; the per-query structured event + live-log buffer belong to E6, not here.

## Validation
- Test that the filter honours `RUST_LOG` (e.g. parsing a directive) and that init is idempotent (second call does not panic).
- Manual: running the binary prints a structured startup line at `info`.