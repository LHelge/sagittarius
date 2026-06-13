---
id: vj4
title: E18.1 — Icon infrastructure (icondata_lu sprite + Axum route + askama macro)
status: done
priority: P2
created: "2026-06-13T14:58:46.206650171Z"
updated: "2026-06-13T16:31:41.416186941Z"
tags:
  - web
  - ui
parent: ag8
---

Foundation for all icon work. No deps.

- `cargo add icondata_lu icondata_core` (do NOT bundle the full icon set — only
  the handful referenced are emitted).
- New `src/web/icons.rs`:
  - A curated registry `&[(name: &str, IconData)]` of the icons we use (see epic
    mapping table). Confirm exact `icondata_lu` const identifiers on docs.rs.
  - A renderer that builds one SVG sprite string (`<svg style="display:none">` of
    `<symbol id=name viewBox=… fill="none" stroke="currentColor" stroke-width="2"
    stroke-linecap="round" stroke-linejoin="round">{data}</symbol>`) into a
    `LazyLock<String>`.
  - An `Icons` handler unit struct serving `GET /assets/icons.svg` with the same
    immutable cache headers as `Assets::serve` (`src/web/assets.rs:60-95`).
  - `LUCIDE_VERSION` const; a test mirroring the `assets.rs` tests (sprite
    non-empty + contains expected `<symbol id="dashboard"` etc.).
- Wire the route in `src/web/mod.rs:250-254`.
- New `templates/_macros.html`: `{% macro icon(name) %}<svg class="sgt-icon"
  aria-hidden="true"><use href="/assets/icons.svg#{{ name }}"/></svg>{% endmacro %}`.
- `assets/app.css`: `.sgt-icon` base rule (≈1em square, `vertical-align`,
  inherits color).

Verify: `curl localhost:8080/assets/icons.svg` returns the sprite; `cargo test`.