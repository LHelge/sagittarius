---
id: 7nu
title: E1.2 · CLI arguments & config resolution
status: done
priority: P1
created: 2026-05-29T06:00:09.165746932Z
updated: 2026-05-29T10:09:00.298482544Z
tags:
- foundation
- cli
depends_on:
- '783'
parent: p3k
---

A `clap` derive CLI plus a typed `Config` with precedence **flag > env > default**. See SPEC §10.

## Deliverables
- `clap` derive `Cli` struct with these flags (each with env fallback + documented default):
  - `--dns-addr` — default `0.0.0.0:53`, **repeatable** → `Vec<SocketAddr>` (e.g. add `[::]:53` for dual-stack IPv6). Empty → default applied once.
  - `--admin-addr` — default `127.0.0.1:8080`.
  - `--db-path` — default `sagittarius.db`.
  - `--session-cookie-secure` — default `auto`, accepted values `auto | always | never`. This is an operational setting because Sagittarius serves plain HTTP behind an optional TLS-terminating reverse proxy (SPEC §9, §10).
- **Pinned env var fallbacks:** `SAGITTARIUS_DNS_ADDR`, `SAGITTARIUS_ADMIN_ADDR`, `SAGITTARIUS_DB_PATH`, `SAGITTARIUS_SESSION_COOKIE_SECURE`.
- A typed `Config` built from `Cli` via `TryFrom` (or builder), parsing/validating addresses; precedence handled by clap's `env` + `default_value`.
- A `SessionCookieSecurePolicy` enum on `Config` (`Auto`, `Always`, `Never`) used by E8.2.
- `--help` / `--version` wired; invalid addresses rejected with a clear, typed error (from E1.1's `error` module).

## Design notes
- Application config (upstreams, lists, records) lives in SQLite, NOT flags — only operational settings are flags (SPEC §10). Cookie secure policy is operational because it depends on deployment topology, not resolver behaviour.
- `Config` is the value the `app` runtime (E1.4) is built from.

## Validation
- Unit tests for precedence: flag overrides env overrides default, for each flag.
- Address-parsing tests: IPv4, IPv6 (`[::]:53`), the repeatable `--dns-addr` case, and a malformed address → error.
- Cookie-policy parsing tests for `auto`, `always`, `never`, invalid values, and flag-over-env-over-default precedence.
- `--help` lists every flag with its documented default.
- Bad args produce a non-zero exit with a helpful message (test via clap `try_parse_from`).
