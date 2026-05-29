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
pub mod auth;
pub mod csrf;
pub mod dashboard;
pub mod live_log;
pub mod origin;
pub mod render;
pub mod wizard;

use std::{
    net::SocketAddr,
    sync::{Arc, atomic::AtomicBool},
};

use axum::{
    Router, middleware,
    routing::{get, post},
};

use crate::web::auth::CurrentUser;
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
    /// Per-process key for deriving session-bound CSRF tokens (E8.3).
    ///
    /// Random at startup; outstanding page tokens are invalidated on restart
    /// (the user simply reloads to obtain a fresh one).
    pub csrf_key: Arc<[u8; 32]>,
    /// Fast-path flag for the first-run wizard (E8.4): set once an admin user
    /// is observed, after which the wizard is permanently closed.
    pub setup_done: Arc<AtomicBool>,
}

/// Generate a fresh random key for signing session-bound CSRF tokens.
///
/// Called once at startup; see [`AppState::csrf_key`].
pub fn random_csrf_key() -> Arc<[u8; 32]> {
    use rand::Rng;
    let mut key = [0u8; 32];
    rand::rng().fill_bytes(&mut key);
    Arc::new(key)
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
    ///
    /// Only reached from handlers gated by the [`CurrentUser`] extractor, so
    /// `authenticated` is always `true`.  The session-bound CSRF token is
    /// embedded so forms and Datastar actions on the page can authorise their
    /// mutations (E8.3).
    async fn chrome(&self, active: &'static str, user: &CurrentUser) -> Chrome {
        Chrome {
            theme: self.ui_theme().await,
            active,
            show_nav: true,
            authenticated: true,
            csrf_token: self.csrf_token(&user.session_id),
        }
    }

    /// Build a bare [`Chrome`] (no navigation) for the login page and wizard.
    async fn bare_chrome(&self) -> Chrome {
        Chrome {
            theme: self.ui_theme().await,
            active: "",
            show_nav: false,
            authenticated: false,
            csrf_token: String::new(),
        }
    }

    /// Assemble the admin [`Router`] with all routes and the shared state.
    fn router(self) -> Router {
        Router::new()
            .route("/", get(Self::dashboard))
            // Live query log + the shared SSE stream (log + dashboard counters).
            .route("/log", get(Self::query_log))
            .route("/events", get(Self::events))
            // First-run wizard (public; gated by the wizard layer below).
            .route("/setup", get(wizard::setup_form).post(wizard::setup_submit))
            // Authentication (public).
            .route("/login", get(auth::login_form).post(auth::login_submit))
            .route("/logout", post(auth::logout))
            // Embedded static assets (no CDN, no Node build).
            .route("/assets/datastar.js", get(Assets::datastar_js))
            .route("/assets/pico.pumpkin.min.css", get(Assets::pico_css))
            .route("/assets/app.css", get(Assets::app_css))
            .route("/assets/icon.png", get(Assets::icon_png))
            .route("/favicon.ico", get(Assets::icon_png))
            // CSRF protection wraps every route; it self-skips safe methods and
            // pre-auth (no-session) mutations (E8.3).
            .layer(middleware::from_fn_with_state(self.clone(), csrf::guard))
            // The wizard gate is outermost (E8.4): until the first admin exists
            // it forces all UI traffic to /setup; afterwards it closes /setup.
            .layer(middleware::from_fn_with_state(self.clone(), wizard::guard))
            .with_state(self)
    }
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
        auth::warn_if_insecure(state.cookie_policy, addr);
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
            csrf_key: random_csrf_key(),
            setup_done: Arc::new(AtomicBool::new(false)),
        };
        (dir, state)
    }

    /// Extract the session id (the `id` component) from a `name=id.token` cookie.
    fn session_id_of(cookie: &str) -> String {
        cookie
            .split_once('=')
            .unwrap()
            .1
            .split_once('.')
            .unwrap()
            .0
            .to_owned()
    }

    #[tokio::test]
    async fn auth_flow_end_to_end() {
        use crate::{
            storage::admin_users::{AdminUserRepository, SqliteAdminUserRepo},
            web::auth::hash_password,
        };
        use reqwest::redirect::Policy;

        let (_dir, state) = test_state().await;
        let pool = state.db.pool().clone();

        // Seed an admin account.
        SqliteAdminUserRepo::new(pool.clone())
            .create("admin", &hash_password("s3cret").expect("hash"))
            .await
            .expect("create admin");

        // Keep a clone to derive CSRF tokens for mutating requests in the test.
        let app = state.clone();
        let server = AdminServer::bind("127.0.0.1:0".parse().unwrap(), state)
            .await
            .expect("bind");
        let base = format!("http://{}", server.local_addr().unwrap());
        let token = CancellationToken::new();
        let token2 = token.clone();
        let handle = tokio::spawn(async move { server.serve(token2).await });

        // A client that does NOT auto-follow redirects, so we can inspect them.
        let client = reqwest::Client::builder()
            .redirect(Policy::none())
            .build()
            .unwrap();

        // Unauthenticated access to a protected route redirects to /login.
        let r = client.get(format!("{base}/")).send().await.unwrap();
        assert_eq!(r.status(), 303);
        assert_eq!(r.headers().get("location").unwrap(), "/login");

        // Wrong password is rejected (re-renders the form with an error).
        let r = client
            .post(format!("{base}/login"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body("username=admin&password=wrong")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        assert!(
            r.text()
                .await
                .unwrap()
                .contains("Invalid username or password")
        );

        // Correct credentials establish a session and set the cookie.
        let r = client
            .post(format!("{base}/login"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body("username=admin&password=s3cret")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 303);
        assert_eq!(r.headers().get("location").unwrap(), "/");
        let set_cookie = r
            .headers()
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        assert!(set_cookie.contains("sgt_session="));
        assert!(set_cookie.contains("HttpOnly"));
        assert!(set_cookie.contains("SameSite=Strict"));
        // The cookie value to echo back on subsequent requests.
        let cookie = set_cookie.split(';').next().unwrap().to_owned();

        // The session authorizes the protected route.
        let r = client
            .get(format!("{base}/"))
            .header("cookie", &cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        let dash = r.text().await.unwrap();
        // The dashboard renders inside the base layout with the vendored assets,
        // the active nav marker, and the session-bound CSRF token.
        assert!(dash.contains("/assets/pico.pumpkin.min.css"));
        assert!(dash.contains("/assets/datastar.js"));
        assert!(dash.contains("aria-current=\"page\""));
        assert!(dash.contains(&app.csrf_token(&session_id_of(&cookie))));

        // Expire the session server-side: the same cookie no longer authorizes.
        sqlx::query("UPDATE sessions SET expires_at = 0")
            .execute(&pool)
            .await
            .unwrap();
        let r = client
            .get(format!("{base}/"))
            .header("cookie", &cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 303, "expired session must redirect to login");
        assert_eq!(r.headers().get("location").unwrap(), "/login");

        // Re-login, then logout: the cookie is cleared and the session deleted.
        let r = client
            .post(format!("{base}/login"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body("username=admin&password=s3cret")
            .send()
            .await
            .unwrap();
        let cookie = r
            .headers()
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();

        // The logout mutation requires the session-bound CSRF token. Derive it
        // from the session id (the cookie's `id` component).
        let csrf = app.csrf_token(&session_id_of(&cookie));

        // Without the token the mutation is rejected.
        let r = client
            .post(format!("{base}/logout"))
            .header("cookie", &cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(
            r.status(),
            403,
            "logout without CSRF token must be rejected"
        );

        // A cross-origin request (mismatched Origin) is rejected even with a
        // valid token.
        let r = client
            .post(format!("{base}/logout"))
            .header("cookie", &cookie)
            .header("x-csrf-token", &csrf)
            .header("origin", "http://evil.example.com")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 403, "cross-origin mutation must be rejected");

        // With the token (via the X-CSRF-Token header) it succeeds.
        let r = client
            .post(format!("{base}/logout"))
            .header("cookie", &cookie)
            .header("x-csrf-token", &csrf)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 303);
        assert_eq!(r.headers().get("location").unwrap(), "/login");
        assert!(
            r.headers()
                .get("set-cookie")
                .unwrap()
                .to_str()
                .unwrap()
                .contains("Max-Age=0"),
            "logout must clear the cookie"
        );
        // The invalidated session no longer authorizes.
        let r = client
            .get(format!("{base}/"))
            .header("cookie", &cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 303);

        token.cancel();
        tokio::time::timeout(std::time::Duration::from_secs(5), handle)
            .await
            .expect("shutdown")
            .expect("task");
    }

    #[tokio::test]
    async fn first_run_wizard_flow() {
        use crate::storage::admin_users::{AdminUserRepository, SqliteAdminUserRepo};
        use reqwest::redirect::Policy;

        // Fresh state: no admin user exists yet.
        let (_dir, state) = test_state().await;
        let pool = state.db.pool().clone();
        let server = AdminServer::bind("127.0.0.1:0".parse().unwrap(), state)
            .await
            .expect("bind");
        let base = format!("http://{}", server.local_addr().unwrap());
        let token = CancellationToken::new();
        let token2 = token.clone();
        let handle = tokio::spawn(async move { server.serve(token2).await });

        let client = reqwest::Client::builder()
            .redirect(Policy::none())
            .build()
            .unwrap();

        // Any UI route redirects to the wizard while admin_users is empty.
        let r = client.get(format!("{base}/")).send().await.unwrap();
        assert_eq!(r.status(), 303);
        assert_eq!(r.headers().get("location").unwrap(), "/setup");

        // Even /login bounces to /setup before an admin exists.
        let r = client.get(format!("{base}/login")).send().await.unwrap();
        assert_eq!(r.headers().get("location").unwrap(), "/setup");

        // The wizard renders.
        let r = client.get(format!("{base}/setup")).send().await.unwrap();
        assert_eq!(r.status(), 200);
        assert!(r.text().await.unwrap().contains("Welcome"));

        // Mismatched passwords are rejected.
        let r = client
            .post(format!("{base}/setup"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body("username=admin&password=longenough&confirm=different")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        assert!(r.text().await.unwrap().contains("do not match"));
        assert_eq!(
            SqliteAdminUserRepo::new(pool.clone())
                .count()
                .await
                .unwrap(),
            0,
            "no admin created on validation failure"
        );

        // A valid submission creates the admin and unlocks the UI.
        let r = client
            .post(format!("{base}/setup"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body("username=admin&password=longenough&confirm=longenough")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 303);
        assert_eq!(r.headers().get("location").unwrap(), "/login");
        assert_eq!(
            SqliteAdminUserRepo::new(pool.clone())
                .count()
                .await
                .unwrap(),
            1
        );

        // The wizard is now closed.
        let r = client.get(format!("{base}/setup")).send().await.unwrap();
        assert_eq!(r.status(), 303);
        assert_eq!(r.headers().get("location").unwrap(), "/login");

        // And the freshly created admin can log in.
        let r = client
            .post(format!("{base}/login"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body("username=admin&password=longenough")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 303);
        assert_eq!(r.headers().get("location").unwrap(), "/");

        token.cancel();
        tokio::time::timeout(std::time::Duration::from_secs(5), handle)
            .await
            .expect("shutdown")
            .expect("task");
    }

    #[tokio::test]
    async fn live_query_log_streams_over_sse() {
        use crate::{
            codec::{message::Qtype, name::Name},
            resolver::pipeline::Outcome,
            storage::admin_users::{AdminUserRepository, SqliteAdminUserRepo},
            telemetry::QueryEvent,
            web::auth::hash_password,
        };
        use reqwest::redirect::Policy;
        use std::time::Duration;

        let (_dir, state) = test_state().await;
        SqliteAdminUserRepo::new(state.db.pool().clone())
            .create("admin", &hash_password("s3cret").unwrap())
            .await
            .unwrap();
        let app = state.clone();
        let server = AdminServer::bind("127.0.0.1:0".parse().unwrap(), state)
            .await
            .unwrap();
        let base = format!("http://{}", server.local_addr().unwrap());
        let cancel = CancellationToken::new();
        let c2 = cancel.clone();
        let handle = tokio::spawn(async move { server.serve(c2).await });

        let client = reqwest::Client::builder()
            .redirect(Policy::none())
            .build()
            .unwrap();

        // Log in and capture the session cookie.
        let r = client
            .post(format!("{base}/login"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body("username=admin&password=s3cret")
            .send()
            .await
            .unwrap();
        let cookie = r
            .headers()
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();

        // The log page renders, seeded and wired for the SSE stream.
        let log = client
            .get(format!("{base}/log"))
            .header("cookie", &cookie)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(log.contains("Query log"));
        assert!(log.contains("id=\"log-body\""));
        assert!(log.contains("@get('/events')"));

        // Open the SSE stream.
        let mut resp = client
            .get(format!("{base}/events"))
            .header("cookie", &cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert!(
            resp.headers()
                .get("content-type")
                .unwrap()
                .to_str()
                .unwrap()
                .contains("text/event-stream")
        );

        // Helper: read chunks until `needle` appears (bounded by a timeout).
        async fn read_until(resp: &mut reqwest::Response, needle: &str) -> String {
            let mut buf = String::new();
            loop {
                let chunk = tokio::time::timeout(Duration::from_secs(5), resp.chunk())
                    .await
                    .expect("sse read timed out")
                    .expect("chunk error");
                match chunk {
                    Some(bytes) => {
                        buf.push_str(&String::from_utf8_lossy(&bytes));
                        if buf.contains(needle) {
                            return buf;
                        }
                    }
                    None => return buf,
                }
            }
        }

        // The stream opens with the dashboard counter signals.
        let head = read_until(&mut resp, "queries").await;
        assert!(head.contains("datastar-patch-signals"));

        // Publish a live query; it must arrive as a prepended log row.
        app.telemetry.record(
            QueryEvent::new(
                "10.1.2.3:4000".parse().unwrap(),
                "sse-row.example.com".parse::<Name>().unwrap(),
                Qtype::A,
                Outcome::BlockedByBlocklist,
            )
            .with_latency(Duration::from_millis(3)),
        );
        let body = read_until(&mut resp, "sse-row.example.com").await;
        assert!(body.contains("datastar-patch-elements"));
        assert!(body.contains("log-body"));
        assert!(body.contains("sgt-badge--blocked"));

        drop(resp);
        cancel.cancel();
        tokio::time::timeout(std::time::Duration::from_secs(5), handle)
            .await
            .expect("shutdown")
            .expect("task");
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
