//! Embedded frontend assets.
//!
//! Every byte the browser loads — the Datastar JS runtime, the Pico CSS theme,
//! the thin custom stylesheet, and the favicon/logo — is vendored into the
//! repository under `assets/` and compiled into the binary via
//! [`include_bytes!`].  There are **no** CDN fetches at runtime and no Node
//! build step (SPEC §9).
//!
//! # Pinned versions
//!
//! The vendored Datastar JS **must** stay on the same major/API version as the
//! `datastar` Rust crate (SPEC: E8.1), because the SSE UI (E8.6) speaks the v1
//! `PatchElements` / `PatchSignals` protocol that both sides implement.  The
//! pinned versions are recorded here next to the assets so SDK ↔ asset drift
//! is visible in one place:
//!
//! | Asset | Upstream version | Rust counterpart |
//! |---|---|---|
//! | `datastar.js` | [`DATASTAR_VERSION`] (`1.0.1`) | `datastar` crate `0.3.x` (v1 protocol) |
//! | `pico.pumpkin.min.css` | [`PICO_VERSION`] (`2.1.1`, [`PICO_PRESET`]) | — |
//!
//! Assets are served with a long, immutable `Cache-Control` since their
//! content is fixed for the lifetime of a given build.

use axum::{
    http::{HeaderValue, header},
    response::{IntoResponse, Response},
};

// ── Pinned upstream versions ────────────────────────────────────────────────

/// Vendored Datastar JS bundle version (`assets/datastar.js`).
///
/// Keep in lockstep with the `datastar` crate's protocol version.
pub const DATASTAR_VERSION: &str = "1.0.1";

/// Vendored Pico CSS version (`assets/pico.pumpkin.min.css`).
pub const PICO_VERSION: &str = "2.1.1";

/// The Pico CSS colour preset in use — chosen to match the logo's warm orange.
pub const PICO_PRESET: &str = "pumpkin";

// ── Embedded bytes ──────────────────────────────────────────────────────────

const DATASTAR_JS: &[u8] = include_bytes!("../../assets/datastar.js");
const PICO_CSS: &[u8] = include_bytes!("../../assets/pico.pumpkin.min.css");
const APP_CSS: &[u8] = include_bytes!("../../assets/app.css");
const ICON_PNG: &[u8] = include_bytes!("../../assets/icon.png");

/// `Cache-Control` applied to every vendored asset.  The content is fixed for
/// the lifetime of the build, so we allow long-lived immutable caching.
const IMMUTABLE: &str = "public, max-age=31536000, immutable";

// ── Assets handler namespace ────────────────────────────────────────────────

/// Namespace for the static-asset route handlers.
///
/// Implemented as associated functions on a unit struct (rather than free
/// functions) per the repository convention that behaviour lives on types.
pub struct Assets;

impl Assets {
    /// `GET /assets/datastar.js` — the Datastar JS runtime.
    pub async fn datastar_js() -> Response {
        Self::serve(DATASTAR_JS, "text/javascript; charset=utf-8")
    }

    /// `GET /assets/pico.pumpkin.min.css` — the Pico CSS theme.
    pub async fn pico_css() -> Response {
        Self::serve(PICO_CSS, "text/css; charset=utf-8")
    }

    /// `GET /assets/app.css` — the thin custom stylesheet.
    pub async fn app_css() -> Response {
        Self::serve(APP_CSS, "text/css; charset=utf-8")
    }

    /// `GET /assets/icon.png` (and `/favicon.ico`) — the logo / favicon.
    pub async fn icon_png() -> Response {
        Self::serve(ICON_PNG, "image/png")
    }

    /// Build a cacheable response for a static byte slice with a fixed
    /// content type.
    fn serve(body: &'static [u8], content_type: &'static str) -> Response {
        (
            [
                (header::CONTENT_TYPE, HeaderValue::from_static(content_type)),
                (header::CACHE_CONTROL, HeaderValue::from_static(IMMUTABLE)),
            ],
            body,
        )
            .into_response()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    #[test]
    fn assets_are_non_empty() {
        assert!(!DATASTAR_JS.is_empty(), "datastar.js must be embedded");
        assert!(!PICO_CSS.is_empty(), "pico css must be embedded");
        assert!(!APP_CSS.is_empty(), "app.css must be embedded");
        assert!(!ICON_PNG.is_empty(), "icon.png must be embedded");
    }

    #[test]
    fn datastar_asset_matches_pinned_version() {
        // The vendored bundle starts with a `// Datastar vX.Y.Z` banner; guard
        // that it matches the version we claim so an accidental re-vendor of a
        // different version is caught.
        let head = std::str::from_utf8(&DATASTAR_JS[..64]).unwrap_or("");
        assert!(
            head.contains(DATASTAR_VERSION),
            "datastar.js banner must contain {DATASTAR_VERSION}, got: {head:?}"
        );
    }

    #[test]
    fn pico_asset_matches_pinned_version() {
        let head = std::str::from_utf8(&PICO_CSS[..160]).unwrap_or("");
        assert!(
            head.contains(PICO_VERSION),
            "pico css banner must contain {PICO_VERSION}"
        );
    }

    #[tokio::test]
    async fn serve_sets_content_type_and_cache_headers() {
        let resp = Assets::app_css().await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/css; charset=utf-8"
        );
        assert_eq!(
            resp.headers().get(header::CACHE_CONTROL).unwrap(),
            IMMUTABLE
        );
    }
}
