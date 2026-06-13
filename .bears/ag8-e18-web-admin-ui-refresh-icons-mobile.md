---
id: ag8
title: E18 — Web admin UI refresh (icons + mobile)
type: epic
status: done
priority: P2
created: "2026-06-13T14:58:34.280065163Z"
updated: "2026-06-13T17:07:17.232127947Z"
tags:
  - web
  - ui
---

Moderate visual polish of the admin UI (axum + askama + Datastar + Pico CSS, all
embedded in the single binary): add Lucide icons to nav / dashboard cards / table
headers / action buttons, replace the wrap-menu with a proper hamburger drawer on
mobile, and add real responsive breakpoints + touch-friendly sizing — keeping the
Pico "pumpkin" identity and the hard constraint that every browser asset is
vendored and compiled into the binary (no CDN, no Node build step).

Standalone epic, independent of E13/E14 (0.2.0); targetable after 0.2.0.

## Confirmed decisions
- **Icons:** keep `icondata_lu` (Lucide) as the source but pull only the handful
  used and serve them via Axum as a single generated SVG sprite, rendered
  server-side from `icondata_core::IconData` (themeable via `currentColor`).
- **Mobile menu:** Datastar hamburger toggle (Datastar already loaded → no new JS).
- **Scope:** moderate polish.

## Icon mechanism
`IconData` exposes `data` (inner SVG markup) + optional `view_box`, `fill`,
`stroke`, `stroke_width`, `stroke_linecap`, `stroke_linejoin`. Render selected
constants into `<symbol id=...>` entries in one `LazyLock<String>` sprite served
at `GET /assets/icons.svg` (immutable cache, mirroring `Assets::serve` in
`src/web/assets.rs:60-95`). Reference via an askama macro:
`<svg class="sgt-icon" aria-hidden="true"><use href="/assets/icons.svg#name"/></svg>`.
Lucide defaults (`stroke="currentColor"`) make icons inherit text color → theme
with light/dark and the active-link accent automatically.

## Verification
Per CLAUDE.md: `cargo fmt` / `cargo clippy` / `cargo test` before each commit
(no sqlx changes expected). Run the binary, check `/assets/icons.svg`, and test
the UI at ~375px and wide viewports (hamburger drawer, icon theming, touch
targets). Branch `feat/e18-web-ui-refresh`, one PR for the epic.

Full plan: ~/.claude/plans/i-want-to-plan-replicated-otter.md