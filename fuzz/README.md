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

Running the fuzzer in CI (e.g. GitHub Actions) is optional/forward-looking.
A typical setup runs each target for a fixed time budget (e.g. 60–300 s) on
nightly, then uploads the corpus as a CI artifact.

The build isolation guarantee (the `[workspace]` table in `Cargo.toml`) means
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
