---
id: beg
title: E3.4 · Settings & upstreams repositories
status: done
priority: P1
created: 2026-05-29T06:55:28.445738242Z
updated: 2026-05-29T12:46:53.021691170Z
tags:
- storage
depends_on:
- '294'
- wus
parent: hga
---

Typed repositories for global settings and upstream resolver definitions. See SPEC §4, §7.

## Deliverables
- A `SettingsRepository` **trait** with `async fn` members (read the single settings row seeded by E3.3, update fields) and a SQLite-backed impl. Typed `Settings` model — lean on Rust types (enums for blocking mode, typed TTL bounds + negative-TTL cap), `FromRow`/`TryFrom` mapping; compile-time-checked `query_as!`.
- An `UpstreamRepository` **trait** + SQLite impl: list, insert, update, delete, enable/disable; `Upstream` model with a `transport` enum (udp/tcp/dot/doh) and optional `tls_server_name`. Bulk `list_enabled` for E5 to load from.
- Behaviour on types; traits keep a mock seam open but tests use ephemeral DBs.

## Validation
- CRUD round-trips against an ephemeral SQLite DB.
- Settings update persists and re-reads with correct types; blocking-mode enum maps both ways.
- Upstream insert/list/update/delete; transport enum round-trips; `list_enabled` filters correctly.
