# Fuzz targets for Sagittarius DNS codec

This crate contains `cargo-fuzz` targets for the DNS wire-format codec in
`src/codec/`.  It is an **isolated workspace** (`[workspace]` in `Cargo.toml`)
so it is never compiled by a normal `cargo build` or `cargo test` from the repo
root — it only builds when you explicitly invoke `cargo fuzz`.

## Targets

| Target | File | What it covers |
|---|---|---|
| `parse` | `fuzz_targets/parse.rs` | Raw-bytes entry: `Query::try_from`, `TtlScan::scan`, `EdnsInfo::scan` |
| `parse_structured` | `fuzz_targets/parse_structured.rs` | Structured DNS-shaped input via `arbitrary` — reaches deeper parser paths |

## Prerequisites

You need:

1. **Nightly Rust toolchain** — libfuzzer-sys requires nightly:
   ```sh
   rustup toolchain install nightly
   ```

2. **`cargo-fuzz`** — the fuzzing harness:
   ```sh
   cargo install cargo-fuzz
   ```

3. **LLVM/clang with sanitizer support** — required by libfuzzer on Linux.
   On Arch/Ubuntu this is usually `clang` + `compiler-rt`.

## Running the fuzzer

From the **repo root**:

```sh
# Run the raw-bytes target:
cargo +nightly fuzz run parse

# Run the structured target:
cargo +nightly fuzz run parse_structured

# With a time limit (e.g. 60 seconds):
cargo +nightly fuzz run parse -- -max_total_time=60

# List targets:
cargo +nightly fuzz list
```

## Seeding the corpus from fixtures

The `fixtures/` directory at the repo root contains hand-authored DNS
wire-format messages.  **Copy** them into the target's corpus directory to seed
it — do **not** pass `fixtures/` as a positional argument to `cargo fuzz run`,
because libFuzzer treats the corpus directory as **writable** and would dump its
generated corpus into your committed `fixtures/`:

```sh
# Seed the raw-bytes target (one-time), then run:
mkdir -p fuzz/corpus/parse
cp fixtures/*.bin fuzz/corpus/parse/
cargo +nightly fuzz run parse

# Seed the structured target the same way:
mkdir -p fuzz/corpus/parse_structured
cp fixtures/*.bin fuzz/corpus/parse_structured/
cargo +nightly fuzz run parse_structured
```

The corpus directories (`fuzz/corpus/<target>/`) are git-ignored, so both the
copied seeds and any inputs discovered during a run stay out of version control.

## Reproducing a crash

When the fuzzer finds a crash, it saves the input to
`fuzz/artifacts/<target>/crash-<hash>`.  Reproduce it with:

```sh
cargo +nightly fuzz run parse fuzz/artifacts/parse/crash-<hash>
```

## CI integration

Continuous fuzzing runs in `.github/workflows/fuzz.yml` on every push to `main`
and every pull request. A matrix job fuzzes each target for a short time budget
(60 s by default) on nightly, seeding from the committed `fixtures/` and caching
`fuzz/corpus/<target>/` so coverage **compounds across runs**. A crash fails the
job and uploads the reproducer from `fuzz/artifacts/<target>/` as a CI artifact.

For a longer ad-hoc run, trigger the workflow manually (Actions → Fuzz → "Run
workflow") and override the per-target `duration` input.

The build isolation guarantee (the `[workspace]` table in `Cargo.toml`) means
this nightly/libfuzzer job is fully separate from the stable `CI` workflow —
adding this crate does **not** break stable CI.

## Stability on stable Rust

The fuzz crate itself cannot be compiled on stable Rust (libfuzzer-sys requires
nightly).  However, the **root crate** is fully unaffected:

```sh
# These all work unchanged on stable, even with fuzz/ present:
cargo build --release
cargo test
cargo clippy --all-targets -- -D warnings
```
