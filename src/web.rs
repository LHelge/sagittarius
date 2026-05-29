//! Web administration interface.
//!
//! An [`axum`] HTTP server sharing the tokio runtime with the DNS engine.
//! Renders HTML with [`askama`] compile-time templates and drives
//! interactivity via [Datastar](https://data-star.dev/) (SSE-based fragments
//! and reactive signals) — no JavaScript build step.  Styling is
//! [Pico CSS](https://picocss.com/) plus a thin custom layer, both vendored
//! into the binary (see [`assets`]).
//!
//! All routes are authenticated; state-changing requests carry CSRF
//! protection.  See SPEC §9 for the full capability list and security model.
//!
//! # Shared state
//!
//! [`AppState`] bundles the handles the admin handlers need — the database,
//! the shared [`ResolverState`], the telemetry sink, and the blocklist refresh
//! trigger — and is cloned into every request via axum's [`State`] extractor.
//! Fields are added as later subtasks wire them in.

pub mod assets;

use std::{net::SocketAddr, sync::Arc};

use askama::Template;
use askama_web::WebTemplate;
use axum::{Router, extract::State, response::IntoResponse, routing::get};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::{
    blocklist::scheduler::RefreshTrigger,
    config::SessionCookieSecurePolicy,
    resolver::state::ResolverState,
    storage::{
        Db,
        settings::{SettingsRepository, SqliteSettingsRepo},
    },
    telemetry::TelemetrySink,
    web::assets::Assets,
};

// ── Errors ──────────────────────────────────────────────────────────────────

/// Errors that can occur in the web administration server.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The admin HTTP server failed to bind its listen address.
    #[error("failed to bind admin listener on {addr}: {source}")]
    Bind {
        addr: std::net::SocketAddr,
        #[source]
        source: std::io::Error,
    },

    /// An internal server error occurred while handling a request.
    #[error("internal error: {0}")]
    Internal(String),
}

// ── Chrome ──────────────────────────────────────────────────────────────────

/// Per-request page chrome shared by every template via the base layout.
///
/// Carrying these fields in one struct (rather than repeating them on every
/// page template) keeps `base.html` stable as the epic grows: the layout reads
/// `chrome.theme`, highlights the active nav item, and conditionally renders
/// the authenticated controls.
#[derive(Debug, Clone)]
pub struct Chrome {
    /// `data-theme` value driving Pico's colour scheme (`auto` / `light` / `dark`).
    pub theme: String,
    /// Key of the active nav section, e.g. `"dashboard"` — used to mark the
    /// current link and as a fallback page title.
    pub active: &'static str,
    /// Whether to render the top navigation bar (hidden on login / wizard).
    pub show_nav: bool,
    /// Whether an admin session is active (controls the logout control).
    pub authenticated: bool,
    /// Anti-CSRF token embedded in forms (populated from E8.3; empty until then).
    pub csrf_token: String,
}

// ── AppState ──────────────────────────────────────────────────────────────────

/// Shared state handed to every admin request handler.
///
/// Cheap to clone — the database pool and the `Arc`-wrapped handles are all
/// reference-counted.  Cloned into handlers through axum's [`State`] extractor.
#[derive(Clone)]
pub struct AppState {
    /// Durable configuration store (SPEC §4).
    pub db: Db,
    /// Hot-path resolver state shared with the DNS engine (SPEC §3.1).
    pub resolver: Arc<ResolverState>,
    /// Live-log + runtime-stats sink for the dashboard and SSE log (E6.6).
    pub telemetry: Arc<TelemetrySink>,
    /// On-demand blocklist refresh trigger (E7.4).
    pub refresh: RefreshTrigger,
    /// Operational session-cookie `Secure` policy (SPEC §9, §10).
    pub cookie_policy: SessionCookieSecurePolicy,
}

impl AppState {
    /// Read the configured UI theme, falling back to `auto` if the settings
    /// row cannot be read.
    async fn ui_theme(&self) -> String {
        match SqliteSettingsRepo::new(self.db.pool().clone()).get().await {
            Ok(settings) => settings.ui_theme,
            Err(e) => {
                warn!(error = %e, "failed to read ui_theme; defaulting to auto");
                "auto".to_owned()
            }
        }
    }

    /// Build the page [`Chrome`] for an authenticated, full-navigation page.
    async fn chrome(&self, active: &'static str) -> Chrome {
        Chrome {
            theme: self.ui_theme().await,
            active,
            show_nav: true,
            // Auth lands in E8.2; until then the UI renders unauthenticated.
            authenticated: false,
            csrf_token: String::new(),
        }
    }

    /// Assemble the admin [`Router`] with all routes and the shared state.
    fn router(self) -> Router {
        Router::new()
            .route("/", get(Self::index))
            // Embedded static assets (no CDN, no Node build).
            .route("/assets/datastar.js", get(Assets::datastar_js))
            .route("/assets/pico.pumpkin.min.css", get(Assets::pico_css))
            .route("/assets/app.css", get(Assets::app_css))
            .route("/assets/icon.png", get(Assets::icon_png))
            .route("/favicon.ico", get(Assets::icon_png))
            .with_state(self)
    }

    /// `GET /` — placeholder landing page (the real dashboard arrives in E8.5).
    async fn index(State(state): State<AppState>) -> impl IntoResponse {
        IndexTemplate {
            chrome: state.chrome("dashboard").await,
        }
    }
}

// ── Templates ───────────────────────────────────────────────────────────────

/// Placeholder landing page rendered at `/`.
#[derive(Template, WebTemplate)]
#[template(path = "index.html")]
struct IndexTemplate {
    chrome: Chrome,
}

// ── AdminServer ─────────────────────────────────────────────────────────────

/// A bound-but-not-yet-serving admin HTTP server.
///
/// Mirrors the DNS listener's `bind` → `serve` split so a bad
/// `--admin-addr` surfaces as a startup error (via [`AdminServer::bind`])
/// rather than failing silently inside a spawned task.
pub struct AdminServer {
    listener: TcpListener,
    router: Router,
}

impl AdminServer {
    /// Bind the admin listener on `addr` and build the router around `state`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Bind`] if the address cannot be bound.
    pub async fn bind(addr: SocketAddr, state: AppState) -> Result<Self, Error> {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|source| Error::Bind { addr, source })?;
        Ok(Self {
            listener,
            router: state.router(),
        })
    }

    /// The actual bound address (useful when binding an ephemeral `:0` port in
    /// tests).
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Serve requests until `token` is cancelled, then drain gracefully.
    pub async fn serve(self, token: CancellationToken) {
        let Self { listener, router } = self;
        let shutdown = async move { token.cancelled().await };
        if let Err(e) = axum::serve(listener, router)
            .with_graceful_shutdown(shutdown)
            .await
        {
            tracing::error!(error = %e, "admin server terminated with error");
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        blocklist::{fetch::Fetcher, scheduler::BlocklistScheduler},
        storage::blocklists::SqliteBlocklistRepo,
        telemetry::{LiveLog, Stats},
    };
    use tempfile::TempDir;

    #[test]
    fn error_variants_display() {
        let e = Error::Internal("unexpected state".into());
        assert!(e.to_string().contains("unexpected state"));
    }

    /// Build an [`AppState`] backed by a fresh temp database for tests.
    async fn test_state() -> (TempDir, AppState) {
        let dir = TempDir::new().expect("temp dir");
        let db = Db::connect(dir.path().join("test.db"))
            .await
            .expect("connect db");
        let resolver = ResolverState::hydrate(&db).await.expect("hydrate");
        let telemetry = Arc::new(TelemetrySink::new(
            Arc::new(LiveLog::default()),
            Arc::new(Stats::new()),
        ));
        let scheduler = BlocklistScheduler::new(
            SqliteBlocklistRepo::new(db.pool().clone()),
            Arc::clone(&resolver),
            Fetcher::new(),
        );
        let state = AppState {
            db,
            resolver,
            telemetry,
            refresh: scheduler.trigger(),
            cookie_policy: SessionCookieSecurePolicy::Never,
        };
        (dir, state)
    }

    #[tokio::test]
    async fn index_page_renders_with_pico_and_datastar() {
        let (_dir, state) = test_state().await;
        let chrome = state.chrome("dashboard").await;
        let html = IndexTemplate { chrome }.render().expect("render index");

        // Base layout wired the vendored assets and the brand.
        assert!(html.contains("/assets/pico.pumpkin.min.css"));
        assert!(html.contains("/assets/datastar.js"));
        assert!(html.contains("sagittarius"));
        // Dashboard nav item is marked current.
        assert!(html.contains("aria-current=\"page\""));
    }

    #[tokio::test]
    async fn bind_serves_and_shuts_down_cleanly() {
        let (_dir, state) = test_state().await;
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server = AdminServer::bind(addr, state).await.expect("bind");
        let bound = server.local_addr().expect("local addr");

        let token = CancellationToken::new();
        let token2 = token.clone();
        let handle = tokio::spawn(async move { server.serve(token2).await });

        // The index page is served from the embedded assets (no network fetch).
        let body = reqwest::get(format!("http://{bound}/"))
            .await
            .expect("request index")
            .text()
            .await
            .expect("body");
        assert!(body.contains("sagittarius"));

        // Assets are served from the binary.
        let css = reqwest::get(format!("http://{bound}/assets/app.css"))
            .await
            .expect("request css");
        assert_eq!(css.status(), 200);

        // Cancellation drains the server promptly.
        token.cancel();
        tokio::time::timeout(std::time::Duration::from_secs(5), handle)
            .await
            .expect("server did not shut down in time")
            .expect("server task panicked");
    }
}
