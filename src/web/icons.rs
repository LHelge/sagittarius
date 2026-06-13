//! Embedded SVG icon sprite (Lucide, via `icondata_lu`).
//!
//! The admin UI uses a small, fixed set of [Lucide](https://lucide.dev) icons.
//! Rather than vendoring each SVG by hand or bundling the whole icon set, we
//! pull only the handful we reference from the [`icondata_lu`] crate (each icon
//! is an [`icondata_core::IconData`] static) and render them — once — into a
//! single inline-`<symbol>` sprite served at `GET /assets/icons.svg`.
//!
//! This keeps faith with the project's asset philosophy (see [`super::assets`]):
//! everything the browser loads is compiled into the binary, with no CDN and no
//! Node build step. Templates reference an icon by its stable id via the `icon`
//! askama macro (`templates/_macros.html`), e.g.
//! `<svg class="sgt-icon"><use href="/assets/icons.svg#dashboard"/></svg>`.
//! Lucide icons stroke with `currentColor`, so they inherit the surrounding
//! text colour and theme automatically (light/dark, active-link accent).
//!
//! [`ICONS`] is the single source of truth for which icons are embedded; it
//! grows as later subtasks introduce new icons.

use std::sync::LazyLock;

use axum::response::Response;

use crate::web::assets::Assets;

/// Version of the `icondata_lu` crate that supplies the Lucide icon data.
///
/// Pinned here next to the sprite — mirroring the asset version table in
/// [`super::assets`] — so the icon source is visible in one place.
pub const ICONDATA_LU_VERSION: &str = "0.1.0";

/// Stable sprite id → Lucide icon. The single source of truth for which icons
/// are embedded; templates reference these ids via the `icon` askama macro.
///
/// Grows as later subtasks add icons. Keep ids short, kebab-case, and named for
/// the *role* (e.g. `add`, `remove`) rather than the glyph, so a future icon
/// swap is a one-line change here.
const ICONS: &[(&str, &icondata_core::IconData)] = &[
    // Navigation sections.
    ("dashboard", icondata_lu::LuLayoutDashboard),
    ("log", icondata_lu::LuScrollText),
    ("blacklist", icondata_lu::LuShieldBan),
    ("allowlist", icondata_lu::LuShieldCheck),
    ("local", icondata_lu::LuServer),
    ("blocklists", icondata_lu::LuListChecks),
    ("upstreams", icondata_lu::LuGlobe),
    ("forwarding", icondata_lu::LuRouter),
    ("settings", icondata_lu::LuSettings),
    // Chrome controls.
    ("menu", icondata_lu::LuMenu),
    ("close", icondata_lu::LuX),
    ("pause", icondata_lu::LuPause),
    ("logout", icondata_lu::LuLogOut),
    // Common row / form actions.
    ("add", icondata_lu::LuPlus),
    ("remove", icondata_lu::LuTrash2),
    ("refresh", icondata_lu::LuRefreshCw),
    ("save", icondata_lu::LuSave),
    ("toggle", icondata_lu::LuPower),
    ("older", icondata_lu::LuChevronDown),
    // Dashboard section headings.
    ("live", icondata_lu::LuActivity),
    ("system", icondata_lu::LuServer),
    ("history", icondata_lu::LuHistory),
    ("health", icondata_lu::LuHeartPulse),
    ("talkers", icondata_lu::LuTrendingUp),
    // Dashboard stat-card metrics.
    ("queries", icondata_lu::LuActivity),
    ("blocked", icondata_lu::LuBan),
    ("ratio", icondata_lu::LuPercent),
    ("cached", icondata_lu::LuDatabase),
    ("forwarded", icondata_lu::LuForward),
    ("domains", icondata_lu::LuList),
    ("clients", icondata_lu::LuUsers),
    ("version", icondata_lu::LuTag),
    ("uptime", icondata_lu::LuClock),
    ("qps", icondata_lu::LuGauge),
    ("memory", icondata_lu::LuMemoryStick),
];

/// The rendered sprite, built once on first request and cached for the process
/// lifetime (the icon set is fixed per build).
static SPRITE: LazyLock<String> = LazyLock::new(Icons::build_sprite);

/// Namespace for the icon-sprite route handler and its builder.
///
/// A unit struct (rather than free functions) per the repository convention
/// that behaviour lives on types.
pub struct Icons;

impl Icons {
    /// `GET /assets/icons.svg` — the generated Lucide sprite, served with the
    /// same immutable-cache headers as every other vendored asset.
    pub async fn sprite() -> Response {
        Assets::serve(SPRITE.as_bytes(), "image/svg+xml; charset=utf-8")
    }

    /// Render every icon in [`ICONS`] into one hidden `<svg>` of `<symbol>`s.
    fn build_sprite() -> String {
        let mut out =
            String::from(r#"<svg xmlns="http://www.w3.org/2000/svg" style="display:none">"#);
        for (id, icon) in ICONS {
            Self::push_symbol(&mut out, id, icon);
        }
        out.push_str("</svg>");
        out
    }

    /// Append a single `<symbol id="…">` carrying the icon's own presentation
    /// attributes (viewBox, stroke, fill, …) so it renders identically whether
    /// referenced inline or via `<use>`.
    fn push_symbol(out: &mut String, id: &str, icon: &icondata_core::IconData) {
        use std::fmt::Write;

        let _ = write!(out, r#"<symbol id="{id}""#);
        for (attr, value) in [
            ("viewBox", icon.view_box),
            ("fill", icon.fill),
            ("stroke", icon.stroke),
            ("stroke-width", icon.stroke_width),
            ("stroke-linecap", icon.stroke_linecap),
            ("stroke-linejoin", icon.stroke_linejoin),
        ] {
            if let Some(value) = value {
                let _ = write!(out, r#" {attr}="{value}""#);
            }
        }
        let _ = write!(out, ">{}</symbol>", icon.data);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{StatusCode, header};

    #[test]
    fn sprite_is_well_formed() {
        let sprite = Icons::build_sprite();
        assert!(sprite.starts_with("<svg"), "sprite must open with <svg>");
        assert!(
            sprite.ends_with("</svg>"),
            "sprite must close the root <svg>"
        );
        // Lucide strokes with currentColor — the property that lets icons
        // inherit text colour and theme automatically.
        assert!(sprite.contains("currentColor"));
    }

    #[test]
    fn every_registered_icon_emits_a_symbol() {
        let sprite = Icons::build_sprite();
        for (id, _) in ICONS {
            assert!(
                sprite.contains(&format!(r#"<symbol id="{id}""#)),
                "sprite missing symbol for {id:?}"
            );
        }
    }

    #[tokio::test]
    async fn sprite_route_sets_svg_content_type_and_cache() {
        let resp = Icons::sprite().await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "image/svg+xml; charset=utf-8"
        );
        assert!(
            resp.headers()
                .get(header::CACHE_CONTROL)
                .is_some_and(|v| v.to_str().unwrap().contains("immutable")),
            "sprite must be served with an immutable cache header"
        );
    }
}
