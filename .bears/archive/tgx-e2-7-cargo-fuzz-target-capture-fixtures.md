---
id: tgx
title: E2.7 · cargo-fuzz target & capture fixtures
status: done
priority: P1
created: 2026-05-29T06:24:59.550225823Z
updated: 2026-05-29T12:02:18.758807384Z
tags:
- codec
- dns
- fuzz
depends_on:
- qr4
- x5f
- gmv
parent: rjw
---

Continuously prove the parser is panic/UB-free on adversarial input. See SPEC §12 (v0.1 checklist), §11.

## Deliverables
- `fuzz/` sub-workspace via `cargo fuzz init`; a `fuzz_target!` driving the shallow parse (E2.4) and TTL scan (E2.6) over arbitrary bytes. Consider an `arbitrary`-derived structured input for deeper coverage.
- A small set of committed real-capture fixtures (A/AAAA query + response, EDNS, NXDOMAIN, multi-RR) used as the fuzz seed corpus **and** shared with the unit tests in E2.4/E2.5/E2.6.
- Document how to run: `cargo +nightly fuzz run <target>`; note the nightly + libfuzzer + LLVM-sanitizer requirement. (CI integration is optional / forward-looking.)

## Design notes — keep fuzzing isolated from release builds
- Keep the `fuzz/` crate as its **own isolated workspace** (the empty `[workspace]` table that `cargo fuzz init` generates) so it is **not** a member of the root workspace.
- Consequence: stable release builds and root-level `cargo build` / `cargo test` / `cargo clippy --all-targets` never compile the fuzz crate and never pull in nightly or `libfuzzer-sys`. Nightly is a fuzzing-time-only requirement.
- Add `fuzz/target`, `fuzz/corpus`, `fuzz/artifacts` to `.gitignore` as appropriate.

## Validation
- Fuzz target builds and runs locally; a short run surfaces no panics; malformed inputs consistently return errors (no UB under ASan).
- Fixtures load and parse as expected from the unit tests.
- `cargo build --release` from the repo root succeeds on **stable** with `fuzz/` present (proves the isolation holds).