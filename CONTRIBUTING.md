# Contributing to Sagittarius

Thank you for your interest in contributing! This document covers the quality
gate, local tooling setup, and the branch/PR workflow.

## Quality gate

Every change must pass these three commands before it can be merged:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Run them manually before opening a PR, or let the git hooks (below) do it for
you automatically.

## Git hooks

The repository ships ready-to-use hooks in the tracked `.githooks/` directory.
Enable them once after cloning:

```sh
git config core.hooksPath .githooks
```

Or use the convenience script:

```sh
sh scripts/install-hooks.sh
```

### What each hook runs — and why the split

| Hook | Commands | Rationale |
|---|---|---|
| `pre-commit` | `cargo fmt --all --check`, `cargo clippy --all-targets -- -D warnings` | Formatting and static analysis are fast (seconds); catching them at commit time keeps the history clean without slowing down local iteration. |
| `pre-push` | `cargo test` | The test suite can take longer, especially as the project grows. Running it on push ensures tests are always green before code reaches the remote, without adding latency to every individual commit in a local branch. |

This is a conscious trade-off: **fmt + clippy on commit, tests on push**.

## Branch and PR workflow

- **Work on feature branches.** Never commit directly to `main`.
- **Open a pull request** for every change. PRs are reviewed and rebased onto
  `main` (fast-forward, no merge commits) to keep history linear.
- **Commit messages follow [Conventional Commits](https://www.conventionalcommits.org).**
  Use a type and optional scope, for example:
  - `feat(codec): add bounded TTL scan`
  - `fix(cache): clamp negative TTL`
  - `chore`, `docs`, `test`, `refactor`
- **Discuss substantial changes** by opening an issue first, before investing
  time in implementation.

## Database & the SQLx offline cache

Sagittarius stores its configuration in a single SQLite file and uses SQLx with
**compile-time-checked** queries (`query!` / `query_as!`). Those queries are
verified at build time against the committed **`.sqlx/` offline cache**, so:

- **Just building or testing needs no database.** `cargo build` / `cargo test`
  use `.sqlx/` automatically; CI sets `SQLX_OFFLINE=true` to enforce this.
- **Changing a query or a migration** means you must regenerate the cache. Point
  SQLx at a local dev database, apply the migrations, then re-prepare:

  ```sh
  cp .env.example .env                 # sets DATABASE_URL=sqlite://dev.db
  cargo sqlx database create           # one-time
  cargo sqlx migrate run               # apply migrations/
  cargo sqlx prepare -- --all-targets  # regenerate .sqlx/ (incl. test queries)
  ```

  Commit the updated `.sqlx/` directory alongside your change. CI's `sqlx-cache`
  job runs `cargo sqlx prepare --check` and fails if the cache is stale.

`.env` and the local `dev.db` are git-ignored; `cargo install sqlx-cli` provides
the `cargo sqlx` subcommands.

## License

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed under Apache-2.0 and MIT, without any additional terms or
conditions.
