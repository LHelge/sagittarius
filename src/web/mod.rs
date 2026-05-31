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
pub mod blocklists;
pub mod crypto;
pub mod csrf;
pub mod dashboard;
pub mod lists;
pub mod live_log;
pub mod origin;
pub mod records;
pub mod render;
pub mod settings;
pub mod upstreams;
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
    resolver::{state::ResolverState, upstream::SharedUpstreamPool},
    storage::{Db, settings::SettingsRepository},
    telemetry::TelemetrySink,
    web::assets::Assets,
};
use tokio_util::task::TaskTracker;

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
    /// Hot-swappable upstream pool shared with the DNS engine (E5); rebuilt and
    /// swapped when the operator edits upstreams (E8.9).
    pub upstream_pool: Arc<SharedUpstreamPool>,
    /// The app task tracker, used to register the background drivers of a
    /// rebuilt upstream pool (E8.9).
    pub tracker: TaskTracker,
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
        match self.db.settings().get().await {
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
            csrf_token: self.csrf_token(&user.session_id).into_string(),
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
            .route("/log/older", get(Self::query_log_older))
            .route("/events", get(Self::events))
            // One-click block / unblock actions from the live log.
            .route("/log/block", post(Self::log_block))
            .route("/log/unblock", post(Self::log_unblock))
            // Manual list + local-record management (E8.8).
            .route("/blacklist", get(Self::blacklist_page))
            .route("/blacklist/add", post(Self::blacklist_add))
            .route("/blacklist/remove", post(Self::blacklist_remove))
            .route("/allowlist", get(Self::allowlist_page))
            .route("/allowlist/add", post(Self::allowlist_add))
            .route("/allowlist/remove", post(Self::allowlist_remove))
            .route("/local", get(Self::local_page))
            .route("/local/add", post(Self::local_add))
            .route("/local/remove", post(Self::local_remove))
            // Upstream resolvers + settings (E8.9).
            .route("/upstreams", get(Self::upstreams_page))
            .route("/upstreams/add", post(Self::upstream_add))
            .route("/upstreams/remove", post(Self::upstream_remove))
            .route("/upstreams/toggle", post(Self::upstream_toggle))
            .route(
                "/settings",
                get(Self::settings_page).post(Self::settings_save),
            )
            .route("/settings/clear-log", post(Self::settings_clear_log))
            // Blocklist source management + manual refresh (E8.10).
            .route("/blocklists", get(Self::blocklists_page))
            .route("/blocklists/add", post(Self::blocklist_add))
            .route("/blocklists/remove", post(Self::blocklist_remove))
            .route("/blocklists/toggle", post(Self::blocklist_toggle))
            .route("/blocklists/refresh", post(Self::blocklist_refresh))
            // First-run wizard (public; gated by the wizard layer below).
            .route("/setup", get(Self::setup_form).post(Self::setup_submit))
            // Authentication (public).
            .route("/login", get(Self::login_form).post(Self::login_submit))
            .route("/logout", post(Self::logout))
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
        auth::SessionCookie::warn_if_insecure(state.cookie_policy, addr);
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

// ── Test support ──────────────────────────────────────────────────────────────

#[cfg(test)]
impl AppState {
    /// Build an [`AppState`] over `db` with defaults suitable for tests: an
    /// empty upstream pool, fresh telemetry, loopback cookie policy, and the
    /// wizard gate left to the live `admin_users` count.
    pub(crate) async fn for_test(db: Db) -> AppState {
        use crate::{
            blocklist::{fetch::Fetcher, scheduler::BlocklistScheduler},
            resolver::upstream::{
                DEFAULT_FAILOVER_BUDGET, DEFAULT_QUERY_TIMEOUT, RandomSelector, UpstreamPool,
            },
            telemetry::{LiveLog, Stats},
        };

        let resolver = ResolverState::hydrate(&db).await.expect("hydrate");
        let telemetry = Arc::new(TelemetrySink::new(
            Arc::new(LiveLog::default()),
            Arc::new(Stats::new()),
        ));
        let tracker = TaskTracker::new();
        let upstream_pool = Arc::new(SharedUpstreamPool::new(
            UpstreamPool::connect(
                &[],
                &tracker,
                Arc::new(RandomSelector),
                DEFAULT_FAILOVER_BUDGET,
                DEFAULT_QUERY_TIMEOUT,
            )
            .await,
        ));
        let scheduler =
            BlocklistScheduler::new(db.blocklists(), Arc::clone(&resolver), Fetcher::new());
        AppState {
            db,
            resolver,
            telemetry,
            refresh: scheduler.trigger(),
            cookie_policy: SessionCookieSecurePolicy::Never,
            csrf_key: random_csrf_key(),
            setup_done: Arc::new(AtomicBool::new(false)),
            upstream_pool,
            tracker,
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
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
        let state = AppState::for_test(db).await;
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

    /// A bound, serving admin server with a seeded admin and an authenticated
    /// session, for the feature integration tests.
    ///
    /// Collapses the repeated bind → spawn → login → cookie/CSRF dance. Tests
    /// that exercise the auth or first-run-wizard flows themselves do **not** use
    /// this (they drive those flows manually).
    struct TestServer {
        /// A clone of the served state, for asserting on the DB / live snapshot.
        app: AppState,
        base: String,
        client: reqwest::Client,
        /// The `name=id.token` session cookie for the logged-in admin.
        cookie: String,
        /// The session-bound CSRF token for that cookie.
        csrf: String,
        cancel: CancellationToken,
        handle: tokio::task::JoinHandle<()>,
        _dir: TempDir,
    }

    impl TestServer {
        /// Spawn a server, seed an `admin`/`s3cret` account, and log in.
        async fn login() -> Self {
            use crate::{storage::admin_users::AdminUserRepository, web::auth::Password};
            use reqwest::redirect::Policy;

            let (dir, state) = test_state().await;
            state
                .db
                .admin_users()
                .create("admin", Password::hash("s3cret").unwrap().as_str())
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
            let r = client
                .post(format!("{base}/login"))
                .header("content-type", "application/x-www-form-urlencoded")
                .header("origin", &base)
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
            let csrf = app.csrf_token(&session_id_of(&cookie)).into_string();

            Self {
                app,
                base,
                client,
                cookie,
                csrf,
                cancel,
                handle,
                _dir: dir,
            }
        }

        /// Absolute URL for `path` (e.g. `ts.url("/settings")`).
        fn url(&self, path: &str) -> String {
            format!("{}{}", self.base, path)
        }

        /// Cancel the server and wait for it to drain.
        async fn shutdown(self) {
            self.cancel.cancel();
            tokio::time::timeout(std::time::Duration::from_secs(5), self.handle)
                .await
                .expect("server shut down within 5s")
                .expect("server task panicked");
        }
    }

    #[tokio::test]
    async fn auth_flow_end_to_end() {
        use crate::{storage::admin_users::AdminUserRepository, web::auth::Password};
        use reqwest::redirect::Policy;

        let (_dir, state) = test_state().await;
        let pool = state.db.pool().clone();

        // Seed an admin account.
        state
            .db
            .admin_users()
            .create("admin", Password::hash("s3cret").expect("hash").as_str())
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

        // Pre-auth mutations require an origin signal.
        let r = client
            .post(format!("{base}/login"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body("username=admin&password=s3cret")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 403);

        // Wrong password is rejected (re-renders the form with an error).
        let r = client
            .post(format!("{base}/login"))
            .header("content-type", "application/x-www-form-urlencoded")
            .header("origin", &base)
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
            .header("origin", &base)
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
        assert!(dash.contains(app.csrf_token(&session_id_of(&cookie)).as_str()));

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
            .header("origin", &base)
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
        let csrf = app.csrf_token(&session_id_of(&cookie)).into_string();

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
        use crate::storage::admin_users::AdminUserRepository;
        use reqwest::redirect::Policy;

        // Fresh state: no admin user exists yet. Keep a DB handle alive past the
        // move into the server, to assert admin counts during the wizard flow.
        let (_dir, state) = test_state().await;
        let db = state.db.clone();
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

        // Pre-auth setup also requires an origin signal.
        let r = client
            .post(format!("{base}/setup"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body("username=admin&password=longenough&confirm=longenough")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 403);

        // Mismatched passwords are rejected.
        let r = client
            .post(format!("{base}/setup"))
            .header("content-type", "application/x-www-form-urlencoded")
            .header("origin", &base)
            .body("username=admin&password=longenough&confirm=different")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        assert!(r.text().await.unwrap().contains("do not match"));
        assert_eq!(
            db.admin_users().count().await.unwrap(),
            0,
            "no admin created on validation failure"
        );

        // A valid submission creates the admin and unlocks the UI.
        let r = client
            .post(format!("{base}/setup"))
            .header("content-type", "application/x-www-form-urlencoded")
            .header("origin", &base)
            .body("username=admin&password=longenough&confirm=longenough")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 303);
        assert_eq!(r.headers().get("location").unwrap(), "/login");
        assert_eq!(db.admin_users().count().await.unwrap(), 1);

        // The wizard is now closed.
        let r = client.get(format!("{base}/setup")).send().await.unwrap();
        assert_eq!(r.status(), 303);
        assert_eq!(r.headers().get("location").unwrap(), "/login");

        // And the freshly created admin can log in.
        let r = client
            .post(format!("{base}/login"))
            .header("content-type", "application/x-www-form-urlencoded")
            .header("origin", &base)
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
            telemetry::QueryEvent,
        };
        use std::time::Duration;

        let ts = TestServer::login().await;

        // The log page renders, seeded and wired for the SSE stream.
        let log = ts
            .client
            .get(ts.url("/log"))
            .header("cookie", &ts.cookie)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(log.contains("Query log"));
        assert!(log.contains("id=\"log-body\""));
        // The page opens the SSE stream on load via Datastar's data-init.
        assert!(log.contains("data-init=\"@get('/events')\""));

        // Open the SSE stream.
        let mut resp = ts
            .client
            .get(ts.url("/events"))
            .header("cookie", &ts.cookie)
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
        ts.app.telemetry.record(
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
        ts.shutdown().await;
    }

    #[tokio::test]
    async fn dashboard_shows_persisted_window_excluding_old_rows() {
        use crate::{
            resolver::pipeline::Outcome,
            storage::query_log::{QueryLogRecord, QueryLogRepository},
            time::Clock,
        };

        let ts = TestServer::login().await;

        let now = Clock::now_millis();
        let row = |ts: i64, name: &str, outcome: Outcome| QueryLogRecord {
            id: 0,
            ts,
            client: "10.0.0.5".to_owned(),
            qname: name.to_owned(),
            qtype: "A".to_owned(),
            outcome,
            rcode: Some(0),
            upstream: None,
            latency_ms: 1,
        };
        // In-window rows plus one well outside the 24h window.
        ts.app
            .db
            .query_log()
            .insert_batch(&[
                row(now - 1_000, "inwin.test.", Outcome::Forwarded),
                row(now - 2_000, "inwin.test.", Outcome::Forwarded),
                row(now - 3_000, "blocked.test.", Outcome::BlockedByAdmin),
                row(now - 48 * 3_600 * 1_000, "old.test.", Outcome::Forwarded),
            ])
            .await
            .unwrap();

        let page = ts
            .client
            .get(ts.url("/"))
            .header("cookie", &ts.cookie)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();

        assert!(page.contains("Last 24 hours (persisted)"));
        // In-window domains/clients are surfaced; the out-of-window row is not.
        assert!(page.contains("inwin.test"));
        assert!(page.contains("blocked.test"));
        assert!(
            !page.contains("old.test"),
            "rows older than 24h are excluded"
        );

        ts.shutdown().await;
    }

    #[tokio::test]
    async fn query_log_history_seeds_from_db_and_scrolls_back() {
        use crate::{
            resolver::pipeline::Outcome,
            storage::query_log::{QueryLogRecord, QueryLogRepository},
        };

        let ts = TestServer::login().await;

        // Seed three persisted rows; ascending ts → ascending ids (1, 2, 3).
        let repo = ts.app.db.query_log();
        for (row_ts, name) in [(1, "a.test."), (2, "b.test."), (3, "c.test.")] {
            repo.insert_batch(&[QueryLogRecord {
                id: 0,
                ts: row_ts,
                client: "10.0.0.9".to_owned(),
                qname: name.to_owned(),
                qtype: "A".to_owned(),
                outcome: Outcome::Forwarded,
                rcode: Some(0),
                upstream: None,
                latency_ms: 1,
            }])
            .await
            .unwrap();
        }

        // The initial page renders all three rows from the DB, newest-first, and
        // seeds the scroll-back cursor with the smallest id (1).
        let page = ts
            .client
            .get(ts.url("/log"))
            .header("cookie", &ts.cookie)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(page.contains("a.test"));
        assert!(page.contains("c.test"));
        let c_pos = page.find("c.test").unwrap();
        let a_pos = page.find("a.test").unwrap();
        assert!(c_pos < a_pos, "newest (c) must render before oldest (a)");
        assert!(page.contains("oldest: 1"), "cursor seeded to smallest id");
        assert!(page.contains("Load older"));

        // Scroll back from id 2 → only the older row (id 1, a.test) appended.
        let older = ts
            .client
            .get(ts.url("/log/older?before=2"))
            .header("cookie", &ts.cookie)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(older.contains("datastar-patch-elements"));
        assert!(older.contains("log-body"));
        assert!(older.contains("a.test"));
        assert!(!older.contains("b.test"), "no overlap with the seen page");
        assert!(!older.contains("c.test"));
        assert!(older.contains(r#""oldest":1"#), "cursor advances to id 1");

        // Past the start: nothing to append, cursor resets to 0 (hides control).
        let empty = ts
            .client
            .get(ts.url("/log/older?before=1"))
            .header("cookie", &ts.cookie)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(empty.contains(r#""oldest":0"#));
        assert!(!empty.contains("datastar-patch-elements"));

        ts.shutdown().await;
    }

    #[tokio::test]
    async fn one_click_whitelist_persists_and_swaps() {
        use crate::{codec::name::Name, storage::lists::AllowlistRepository};

        let ts = TestServer::login().await;

        let dom: Name = "ads.example.com".parse().unwrap();
        assert!(!ts.app.resolver.allowlist().contains(&dom));

        // Without the CSRF token the mutation is rejected.
        let r = ts
            .client
            .post(ts.url("/log/unblock?domain=ads.example.com"))
            .header("cookie", &ts.cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 403);

        // With the token it succeeds and returns a Datastar toast patch. The
        // domain is not admin-blacklisted, so Unblock allowlists it.
        let r = ts
            .client
            .post(ts.url("/log/unblock?domain=ads.example.com"))
            .header("cookie", &ts.cookie)
            .header("x-csrf-token", &ts.csrf)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        let body = r.text().await.unwrap();
        assert!(body.contains("datastar-patch-elements"));
        assert!(body.contains("Unblocked"));

        // Persisted to the DB and swapped into the live set.
        assert!(ts.app.resolver.allowlist().contains(&dom));
        let names = ts.app.db.allowlist().load_all().await.unwrap();
        assert!(names.contains(&dom));

        // The real Datastar path: token in the JSON signal body (no header).
        // Block adds the resolved domain to the blacklist; the response is just
        // the toast — the button is not toggled.
        let dom2: Name = "ads2.example.com".parse().unwrap();
        let r = ts
            .client
            .post(ts.url("/log/block?domain=ads2.example.com"))
            .header("cookie", &ts.cookie)
            .header("content-type", "application/json")
            .body(format!("{{\"csrf\":\"{}\",\"f_text\":\"\"}}", ts.csrf))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        let body = r.text().await.unwrap();
        assert!(body.contains("Blocked"));
        assert!(!body.contains("act-"), "button must not be toggled");
        assert!(ts.app.resolver.blacklist().contains(&dom2));

        ts.shutdown().await;
    }

    #[tokio::test]
    async fn management_blacklist_form_roundtrip() {
        use crate::codec::name::Name;

        let ts = TestServer::login().await;
        let dom: Name = "ads.example.com".parse().unwrap();

        // Add via the management form (CSRF token travels as a form field).
        let r = ts
            .client
            .post(ts.url("/blacklist/add"))
            .header("cookie", &ts.cookie)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(format!("csrf_token={}&domain=ads.example.com", ts.csrf))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 303);
        assert_eq!(r.headers().get("location").unwrap(), "/blacklist");
        assert!(ts.app.resolver.blacklist().contains(&dom));

        // The page lists the entry, shown without the canonical trailing dot.
        let page = ts
            .client
            .get(ts.url("/blacklist"))
            .header("cookie", &ts.cookie)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(page.contains("ads.example.com"));
        assert!(!page.contains("ads.example.com."));

        // A form missing the CSRF token is rejected.
        let r = ts
            .client
            .post(ts.url("/blacklist/add"))
            .header("cookie", &ts.cookie)
            .header("content-type", "application/x-www-form-urlencoded")
            .body("domain=evil.example.com")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 403);

        // Remove round-trips the in-memory set too.
        let r = ts
            .client
            .post(ts.url("/blacklist/remove"))
            .header("cookie", &ts.cookie)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(format!("csrf_token={}&domain=ads.example.com", ts.csrf))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 303);
        assert!(!ts.app.resolver.blacklist().contains(&dom));

        ts.shutdown().await;
    }

    #[tokio::test]
    async fn settings_form_saves_over_http() {
        use crate::codec::synth::BlockMode;

        let ts = TestServer::login().await;

        // Seed defaults use null-ip; switch to nxdomain over the form.
        assert_eq!(ts.app.resolver.settings().block_mode, BlockMode::null_ip());
        let body = format!(
            "csrf_token={}&cache_min_ttl=10&cache_max_ttl=3600&cache_negative_ttl_cap=300\
             &cache_capacity=50000&blocking_mode=nxdomain&custom_block_ipv4=&custom_block_ipv6=\
             &blocklist_refresh_interval=7200&ui_theme=dark\
             &query_log_enabled=1&query_log_retention_days=30",
            ts.csrf
        );
        let r = ts
            .client
            .post(ts.url("/settings"))
            .header("cookie", &ts.cookie)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        assert!(r.text().await.unwrap().contains("Settings saved"));

        // The live runtime snapshot reflects the change immediately.
        assert_eq!(ts.app.resolver.settings().block_mode, BlockMode::NxDomain);
        assert_eq!(ts.app.resolver.settings().cache_max_ttl, 3600);

        ts.shutdown().await;
    }

    #[tokio::test]
    async fn query_log_controls_render_and_clear_over_http() {
        use crate::{
            resolver::pipeline::Outcome,
            storage::query_log::{QueryLogRecord, QueryLogRepository},
        };

        let ts = TestServer::login().await;

        // The settings page renders the query-log toggle and retention input.
        let page = ts
            .client
            .get(ts.url("/settings"))
            .header("cookie", &ts.cookie)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(page.contains("name=\"query_log_enabled\""));
        assert!(page.contains("name=\"query_log_retention_days\""));
        assert!(page.contains("/settings/clear-log"));

        // Seed a query-log row to be cleared.
        ts.app
            .db
            .query_log()
            .insert_batch(&[QueryLogRecord {
                id: 0,
                ts: 1,
                client: "10.0.0.1".to_owned(),
                qname: "x.test.".to_owned(),
                qtype: "A".to_owned(),
                outcome: Outcome::Forwarded,
                rcode: Some(0),
                upstream: None,
                latency_ms: 1,
            }])
            .await
            .unwrap();

        // Without the CSRF token the clear action is rejected.
        let r = ts
            .client
            .post(ts.url("/settings/clear-log"))
            .header("cookie", &ts.cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 403, "clear-log without CSRF must be rejected");

        // With the token it succeeds and empties the log.
        let r = ts
            .client
            .post(ts.url("/settings/clear-log"))
            .header("cookie", &ts.cookie)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(format!("csrf_token={}", ts.csrf))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        assert!(r.text().await.unwrap().contains("Query log cleared"));

        let remaining = ts.app.db.query_log().page(None, 10).await.unwrap();
        assert!(remaining.is_empty(), "clear-log must empty the table");

        ts.shutdown().await;
    }

    #[tokio::test]
    async fn blocklist_sources_manage_over_http() {
        use crate::storage::blocklists::BlocklistRepository;

        let ts = TestServer::login().await;

        // Add a source via the form.
        let r = ts
            .client
            .post(ts.url("/blocklists/add"))
            .header("cookie", &ts.cookie)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(format!(
                "csrf_token={}&url=https://example.com/hosts.txt&format=hosts",
                ts.csrf
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 303);
        let sources = ts.app.db.blocklists().list().await.unwrap();
        assert_eq!(sources.len(), 1);

        // The page lists it.
        let page = ts
            .client
            .get(ts.url("/blocklists"))
            .header("cookie", &ts.cookie)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(page.contains("https://example.com/hosts.txt"));

        // The "Refresh now" button fires the trigger and reports it.
        let r = ts
            .client
            .post(ts.url("/blocklists/refresh"))
            .header("cookie", &ts.cookie)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(format!("csrf_token={}", ts.csrf))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        assert!(r.text().await.unwrap().contains("Refresh started"));

        ts.shutdown().await;
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
