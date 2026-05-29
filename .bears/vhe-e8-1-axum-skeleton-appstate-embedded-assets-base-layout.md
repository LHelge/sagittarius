---
id: vhe
title: E8.1 · axum skeleton, AppState, embedded assets & base layout
status: open
priority: P1
created: 2026-05-29T07:56:54.067798159Z
updated: 2026-05-29T07:56:54.067798159Z
tags:
- web
depends_on:
- bfx
- zcf
parent: p6b
---

The web admin foundation: an axum server with shared state, embedded assets, and the base template layer. See SPEC §9, §10.

## Deliverables
- `cargo add axum`, `askama`, `askama_web` (feature `axum-0.8`), `datastar`; optionally `tower-http` for admin-side tracing/compression.
- `axum` server bound to `--admin-addr` (loopback default), sharing `tower` middleware and honouring the E1 graceful-shutdown signal.
- An `AppState` (shared via `Arc`) holding the handles later subtasks need: `Db` (E3), `Arc<ResolverState>` (E4.4), the E6 telemetry handles, and the E7 refresh trigger. (Fields added as wired.)
- **Embedded assets** via `include_str!` / `include_bytes!`: Datastar JS, Pico CSS, a thin custom stylesheet, favicon/images — served from an `/assets` route. No CDN, no Node build.
- **Pin Datastar versions:** the vendored Datastar **JS asset** and the `datastar` **Rust crate** must be the same major/API version (E8.6 uses the v1 `PatchElements` / `PatchSignals` API). Record the pinned version next to the vendored asset so SDK ↔ asset drift can't silently break the SSE UI.
- Base Askama layout (`#[derive(WebTemplate)]` → `IntoResponse`) with Pico CSS + Datastar wired; a placeholder index page.

## Design notes
- Handlers as methods on typed router/state modules, not free functions (CLAUDE.md).
- Plain HTTP behind a reverse proxy for TLS (SPEC §9); bind loopback by default.

## Validation
- Server starts on an ephemeral admin port and stops cleanly on shutdown.
- The base page renders with Pico styling; assets are served from the binary (verify no network fetch).