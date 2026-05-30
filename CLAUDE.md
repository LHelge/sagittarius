# CLAUDE.md

Guidance for working in this repository.

## Project

Sagittarius is a self-hosted DNS sinkhole (like Pi-hole / AdGuard Home), written
in Rust and shipped as a **single self-contained binary** — DNS engine, storage,
and web admin UI all included.

- **[`SPEC.md`](SPEC.md)** is the source of truth for design and architecture.
  Read it before making non-trivial changes, and keep it in sync when decisions
  change.
- **[`README.md`](README.md)** is the user-facing overview. Keep it aligned with
  the spec.

Stack at a glance (see `SPEC.md` §2 for the full table and rationale): `tokio` +
`tower`, a custom lazy DNS codec over `bytes`, `hickory` for upstream transport
(DoT/DoH), SQLite via `sqlx`, `moka` cache, `arc-swap` for hot-path state,
`axum` + `askama` + Datastar (SSE) + Pico CSS, `tracing` to stdout, `clap` CLI.

## Task tracking — use bears

This project uses [bears](https://github.com/LHelge/bea-rs) for task tracking.

- Manage tasks through the **bears MCP server** (active in this project), not the
  `bea` CLI — the CLI is installed but **must not be used** for task operations.
- Tasks are plain markdown files in the repo. It is fine to **edit a task file
  directly** after it was created via the MCP.
- **Mark tasks completed before committing** the changes that finish them.
- **Do not** use the tool `get_graph` it is buggy on projects with this many dependencies

### Agent loop

Follow the canonical bears workflow:

1. `list_ready` → pick the highest-priority unblocked task.
2. `start_task(id)` → mark it `in_progress`.
3. `get_task(id)` → read the full description.
4. …do the work…
5. `complete_task(id)` → mark it done.
6. `list_ready` → repeat.

Dependencies automatically gate availability, so `list_ready` only surfaces work
that is actually unblocked.

### Epics & dependencies

- Break a feature into dependent subtasks grouped under an **epic** via the
  `parent` parameter. Epics never appear in `list_ready` and auto-close when all
  their children complete.
- Encode ordering constraints as **explicit dependencies** (`add_dependency`)
  rather than relying on priority alone.

### Best practices

- Always begin with `list_ready` to respect priority and dependency order; use
  `tag` to narrow scope (e.g. `list_ready(tag="codec")`) and `limit` to manage
  context.
- Keep tasks **small and completable in a focused session**.

## Engineering conventions

- **Idiomatic Rust** wherever possible.
- **Behavior lives on types and traits.** Avoid free-standing functions; prefer
  methods, `impl` blocks, and trait implementations.
- **Prefer the standard traits** when they fit — e.g. `From`/`TryFrom`,
  `FromStr`, `Display`, `Default`, `Iterator` — instead of bespoke equivalents.
- **Test to lock in behavior.** Write unit tests and, where possible, end-to-end
  tests. Treat tests as the executable specification of intended behavior.

## Dependencies

- Add/upgrade crates with **`cargo add`** (not by hand-editing `Cargo.toml`) so
  versions resolve fresh and no stale versions creep in.

## Database migrations

- Create migrations with **`sqlx migrate add -r <name>`** (not by hand-creating
  files). The `-r` makes them **reversible** — it generates a paired
  `<timestamp>_<name>.up.sql` and `<timestamp>_<name>.down.sql` — and the
  timestamp prefix keeps versions monotonic without manual numbering.
- Always write the **`.down.sql`** as the true inverse of the `.up.sql` (drop
  what it created, in reverse FK order; delete what it inserted).
- Migrations are **additive and never edited once merged** — fix mistakes with a
  new migration.
- After adding or changing a migration (or any compile-time query), run
  `cargo sqlx prepare` and commit the updated `.sqlx/` (see *Before committing*).

## Git workflow

- **Develop on feature branches**, never directly on `main`. Open a **pull
  request** for every change.
- Keep history **linear**: PRs are **rebased onto `main`** (rebase/fast-forward,
  no merge commits).
- **Commit messages follow [Conventional Commits](https://www.conventionalcommits.org)**
  — e.g. `feat(codec): add bounded TTL scan`, `fix(cache): clamp negative TTL`,
  `chore`, `docs`, `test`, `refactor`. Use a scope when it adds clarity.

## Before committing

Always run, and ensure they pass:

```sh
cargo fmt
cargo clippy
cargo test
```

If you added or changed any compile-time `sqlx` query (`query!` / `query_as!`)
or a migration, also run `cargo sqlx prepare` and commit the updated `.sqlx/`
directory — otherwise the offline build (`SQLX_OFFLINE=true`) and CI will fail.

Also mark any finished bears tasks as completed first (see above).

## Shell & tooling

Keep shell usage minimal so routine work doesn't trip permission prompts:

- **Edit files with the editor tools** (Read / Write / Edit), never with shell
  text manglers. No `sed`, `awk`, or `echo >` / heredocs to create or rewrite
  files.
- **One command, one job.** Don't chain steps with `&&`/`;` unless the later
  step genuinely depends on the earlier one. Skip throwaway `echo` banners,
  status prints, and "let me check" probes — run the command you actually need.
- **Prefer dedicated tools over shell** when one fits (Read instead of `cat`,
  the search tools instead of `grep`/`find` pipelines).
- Keep commands short and predictable; reserve long pipelines for when they're
  the clearest way to express a real task.

## When in doubt

If anything is unclear or underspecified, **ask questions rather than guessing**.
Don't jump to conclusions on ambiguous requirements — confirm the intent first.
