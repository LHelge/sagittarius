# Changelog

All notable changes to Sagittarius are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Entries are grouped by [Conventional Commit](https://www.conventionalcommits.org)
type; from the first tagged release this file is generated from the commit
history by [git-cliff](https://git-cliff.org).

## [Unreleased]

First milestone (v0.1) — a self-hosted DNS sinkhole in a single binary. Not yet
released.

### Added

- **DNS engine** — a custom lazy wire codec (shallow header + question parse,
  raw-bytes passthrough, EDNS/OPT-aware response synthesis, bounded TTL scan)
  driven by tokio UDP/TCP listeners and a `tower` pipeline (per-client rate
  limiting, load shedding, timeouts).
- **Filtering** — admin blacklist / allowlist plus aggregated third-party
  blocklists (hosts and domain-list formats), with exact-domain matching and a
  null-IP / NXDOMAIN sinkhole. Allowlist bypasses blocklists; the admin
  blacklist is unconditional.
- **Local records** — A/AAAA records for your own network, including
  `*.wildcard` names, answered authoritatively (with RFC-correct NODATA on
  qtype mismatch).
- **Upstream resolution** — random selection with failover, forwarding over
  UDP/TCP and encrypted **DoT / DoH** transports.
- **Caching** — a `moka` raw-bytes cache with per-entry TTL offset patching and
  RFC 2308 negative caching.
- **Web admin** — an `axum` + `askama` + Datastar (SSE) interface: dashboard,
  live query log with one-click allow/deny, and management screens for lists,
  local records, upstreams, and blocklist sources. Argon2id authentication,
  custom sessions, CSRF protection, and a one-step first-run wizard.
- **Storage** — SQLite via `sqlx` with embedded, reversible migrations that seed
  working defaults (Cloudflare upstreams) on first start.
- **Operations** — single self-contained binary with embedded UI assets,
  `clap` CLI flags with env fallbacks, structured `tracing` logs, and graceful
  shutdown that drains in-flight queries.

[Unreleased]: https://github.com/LHelge/sagittarius/commits/main
