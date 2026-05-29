//! Application runtime.
//!
//! Owns the shared state that all subsystems read and write, and is
//! responsible for wiring them together at startup:
//!
//! 1. Open the SQLite database and run migrations ([`storage`]).
//! 2. Load configuration into in-memory structures.
//! 3. Spawn the DNS listeners and query pipeline ([`resolver`]).
//! 4. Spawn the web administration server ([`web`]).
//! 5. Spawn background tasks (blocklist refresh scheduler, etc.).
//! 6. Await a shutdown signal (`SIGTERM` / `SIGINT`) and drain in-flight
//!    work via a [`tokio_util::sync::CancellationToken`] +
//!    [`tokio_util::task::TaskTracker`] before returning.
//!
//! See SPEC §3, §10 for the architecture overview and deployment model.

use std::{future::Future, num::NonZeroUsize, sync::Arc, time::Duration};

use tokio::time::timeout;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{info, warn};

use crate::{
    config::Config,
    error::Result,
    resolver::{
        pipeline::{
            engine::{build_engine, upstream_config_from_row},
            listener::DnsListeners,
            middleware::ProtectiveConfig,
        },
        state::ResolverState,
        upstream::{
            DEFAULT_FAILOVER_BUDGET, DEFAULT_QUERY_TIMEOUT, RandomSelector, SharedUpstreamPool,
            UpstreamPool,
        },
    },
    storage::{
        Db,
        upstreams::{SqliteUpstreamRepo, UpstreamRepository},
    },
    telemetry::{LiveLog, Stats, TelemetrySink},
};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Default amount of time to wait for in-flight tasks to drain before giving
/// up and returning anyway.
pub const DEFAULT_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

// ── App ───────────────────────────────────────────────────────────────────────

/// The top-level application handle.
///
/// Created once in `main`, holds all shared state, and drives the entire
/// service lifetime.
///
/// # Lifecycle
///
/// ```text
/// App::new(config) → run() → [signal] → cancel → drain → return Ok(())
/// ```
///
/// Subsystems (DNS listener, web admin, background scheduler) are spawned via
/// the [`TaskTracker`] and receive a clone of the [`CancellationToken`]. When
/// a shutdown signal arrives the token is cancelled and all well-behaved tasks
/// exit; the tracker drains them within [`drain_timeout`](App::drain_timeout).
pub struct App {
    /// Resolved operational configuration.
    config: Config,
    /// Broadcast cancellation signal to all spawned tasks.
    shutdown_token: CancellationToken,
    /// Tracks all spawned tasks so we can wait for them to finish.
    tracker: TaskTracker,
    /// Maximum time to wait for tasks to drain after cancellation.
    drain_timeout: Duration,
}

impl App {
    /// Construct a new [`App`] from the given [`Config`].
    ///
    /// No I/O or spawning happens here — call [`run`](Self::run) to start.
    pub fn new(config: Config) -> Self {
        Self {
            config,
            shutdown_token: CancellationToken::new(),
            tracker: TaskTracker::new(),
            drain_timeout: DEFAULT_DRAIN_TIMEOUT,
        }
    }

    /// Override the drain timeout (useful for tests).
    ///
    /// The default is [`DEFAULT_DRAIN_TIMEOUT`] (10 seconds).
    pub fn with_drain_timeout(mut self, timeout: Duration) -> Self {
        self.drain_timeout = timeout;
        self
    }

    /// Return the configured drain timeout.
    pub fn drain_timeout(&self) -> Duration {
        self.drain_timeout
    }

    /// Return a clone of the [`CancellationToken`].
    ///
    /// Callers (subsystems or tests) can cancel this token to initiate
    /// shutdown programmatically without sending an OS signal.
    pub fn cancellation_token(&self) -> CancellationToken {
        self.shutdown_token.clone()
    }

    /// Spawn a named subsystem task via the [`TaskTracker`].
    ///
    /// The task receives a clone of the shutdown token. This is the seam that
    /// later epics (E5, E6, E7, E8) use to plug real subsystems in without
    /// changing the harness.
    ///
    /// The closure receives a [`CancellationToken`] and must return a
    /// [`Future`] whose output is `()`.
    fn spawn_subsystem<F, Fut>(&self, name: &'static str, f: F)
    where
        F: FnOnce(CancellationToken) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let token = self.shutdown_token.clone();
        self.tracker.spawn(async move {
            tracing::debug!(subsystem = name, "subsystem started");
            f(token).await;
            tracing::debug!(subsystem = name, "subsystem stopped");
        });
    }

    /// Run the application to completion, blocking until a shutdown signal is
    /// received (or `shutdown` resolves), then draining all tasks.
    ///
    /// The `shutdown` future is how the caller injects the shutdown trigger.
    /// In production [`run`](Self::run) passes the real OS-signal future; in
    /// tests a simple `token.cancelled()` or `async {}` is used instead.
    async fn run_until_shutdown(self, shutdown: impl Future<Output = ()>) -> Result<()> {
        // ── Real DNS engine startup ────────────────────────────────────────────
        let db = Db::connect(&self.config.db_path).await?;
        let state = ResolverState::hydrate(&db).await?;

        let rows = SqliteUpstreamRepo::new(db.pool().clone())
            .list_enabled()
            .await?;

        let configs: Vec<_> = rows
            .iter()
            .filter_map(|r| {
                let c = upstream_config_from_row(r);
                if c.is_none() {
                    tracing::warn!(addr = %r.address, "skipping unmappable upstream");
                }
                c
            })
            .collect();

        let pool = Arc::new(SharedUpstreamPool::new(
            UpstreamPool::connect(
                &configs,
                &self.tracker,
                Arc::new(RandomSelector),
                DEFAULT_FAILOVER_BUDGET,
                DEFAULT_QUERY_TIMEOUT,
            )
            .await,
        ));

        let telemetry = Arc::new(TelemetrySink::new(
            Arc::new(LiveLog::default()),
            Arc::new(Stats::new()),
        ));

        let engine = build_engine(state, pool, telemetry, &ProtectiveConfig::default());

        let udp_sockets_per_addr = std::thread::available_parallelism()
            .map(NonZeroUsize::get)
            .unwrap_or(1);
        let listeners = DnsListeners::bind(&self.config.dns_addrs, udp_sockets_per_addr)?;
        listeners.serve(engine, self.shutdown_token.clone(), &self.tracker);

        // ── Placeholder subsystem tasks ───────────────────────────────────────
        self.spawn_subsystem("web-admin", |token| async move {
            token.cancelled().await;
        });

        self.spawn_subsystem("background", |token| async move {
            token.cancelled().await;
        });

        // Close the tracker so `wait()` knows the spawn set is complete once
        // existing tasks finish.  New tasks cannot be spawned after this point.
        self.tracker.close();

        // Wait for the shutdown trigger.
        info!(
            dns_addrs = ?self.config.dns_addrs,
            admin_addr = %self.config.admin_addr,
            "runtime ready, awaiting shutdown signal",
        );
        shutdown.await;

        // Signal all subsystems to stop.
        info!("shutdown signal received, draining…");
        self.shutdown_token.cancel();

        // Wait for all tasks to finish, bounded by the drain timeout.
        match timeout(self.drain_timeout, self.tracker.wait()).await {
            Ok(()) => {
                info!("all tasks drained cleanly");
            }
            Err(_elapsed) => {
                warn!(
                    drain_timeout = ?self.drain_timeout,
                    "drain timeout elapsed; some tasks may still be running — forcing exit",
                );
            }
        }

        Ok(())
    }

    /// Run the application to completion.
    ///
    /// Spawns subsystem tasks, then blocks until `SIGTERM` or `SIGINT` is
    /// received, then cancels the shutdown token and drains tasks within
    /// [`drain_timeout`](Self::drain_timeout).
    ///
    /// Returns `Ok(())` whether the drain completed cleanly or timed out —
    /// the process should always exit 0.
    pub async fn run(self) -> Result<()> {
        let signal = make_shutdown_signal();
        self.run_until_shutdown(signal).await
    }
}

impl From<Config> for App {
    fn from(config: Config) -> Self {
        Self::new(config)
    }
}

// ── OS signal helpers ─────────────────────────────────────────────────────────

/// Build a future that resolves when `SIGTERM` or `SIGINT` arrives.
///
/// On Unix both signals are awaited via `tokio::signal::unix`; the first one
/// to fire wins.
#[cfg(unix)]
async fn make_shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigterm = signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");
    let mut sigint = signal(SignalKind::interrupt()).expect("failed to register SIGINT handler");

    tokio::select! {
        _ = sigterm.recv() => {
            info!("received SIGTERM");
        }
        _ = sigint.recv() => {
            info!("received SIGINT");
        }
    }
}

/// Fallback for non-Unix targets: only `Ctrl-C` / `SIGINT`.
#[cfg(not(unix))]
async fn make_shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for Ctrl-C");
    info!("received Ctrl-C");
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, path::PathBuf, time::Duration};

    use tempfile::TempDir;

    use super::*;
    use crate::config::{Config, SessionCookieSecurePolicy};

    /// Build a minimal [`Config`] for tests that calls `run_until_shutdown`.
    ///
    /// Uses a real temp-file DB (so sqlx migrations run correctly) and binds
    /// the DNS listener on an ephemeral port (`:0`) to avoid port conflicts.
    async fn run_config() -> (TempDir, Config) {
        let dir = TempDir::new().expect("temp dir");
        let db_path = dir.path().join("test.db");
        // Pre-create the database so startup is fast.
        let _ = Db::connect(&db_path).await.expect("create test db");
        let config = Config {
            dns_addrs: vec!["127.0.0.1:0".parse::<SocketAddr>().unwrap()],
            admin_addr: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            db_path,
            session_cookie_secure: SessionCookieSecurePolicy::Never,
        };
        (dir, config)
    }

    /// Build a minimal [`Config`] suitable for tests that do NOT call
    /// `run_until_shutdown` (constructor/accessor tests).
    fn test_config() -> Config {
        Config {
            dns_addrs: vec!["127.0.0.1:5353".parse::<SocketAddr>().unwrap()],
            admin_addr: "127.0.0.1:18080".parse::<SocketAddr>().unwrap(),
            db_path: PathBuf::from(":memory:"),
            session_cookie_secure: SessionCookieSecurePolicy::Never,
        }
    }

    // ── Constructor & accessors ───────────────────────────────────────────

    #[test]
    fn new_sets_default_drain_timeout() {
        let app = App::new(test_config());
        assert_eq!(app.drain_timeout(), DEFAULT_DRAIN_TIMEOUT);
    }

    #[test]
    fn with_drain_timeout_overrides() {
        let app = App::new(test_config()).with_drain_timeout(Duration::from_millis(50));
        assert_eq!(app.drain_timeout(), Duration::from_millis(50));
    }

    #[test]
    fn from_config_builds_app() {
        let cfg = test_config();
        let app = App::from(cfg);
        assert_eq!(app.drain_timeout(), DEFAULT_DRAIN_TIMEOUT);
    }

    #[test]
    fn cancellation_token_is_cloneable() {
        let app = App::new(test_config());
        let token1 = app.cancellation_token();
        let token2 = app.cancellation_token();
        // Cancelling one clone cancels all clones.
        token1.cancel();
        assert!(token2.is_cancelled());
    }

    // ── Clean shutdown (immediate signal) ─────────────────────────────────

    #[tokio::test]
    async fn run_with_immediate_shutdown_returns_ok() {
        let (_dir, config) = run_config().await;
        let app = App::new(config).with_drain_timeout(Duration::from_millis(500));
        // Trigger shutdown immediately — all tasks just await cancellation.
        let result = app.run_until_shutdown(async {}).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn run_with_token_shutdown_returns_ok() {
        let (_dir, config) = run_config().await;
        let app = App::new(config).with_drain_timeout(Duration::from_millis(500));
        let token = app.cancellation_token();

        // Trigger shutdown via the programmatic token after a short yield.
        let result = app
            .run_until_shutdown(async move {
                // Give the subsystem tasks a moment to start.
                tokio::task::yield_now().await;
                token.cancel();
            })
            .await;

        assert!(result.is_ok());
    }

    // ── Drain-timeout bound ───────────────────────────────────────────────
    //
    // Verify that a task which ignores cancellation and sleeps for a very long
    // time does NOT block `run` past the drain timeout — the timeout branch
    // fires and `run` still returns Ok.

    #[tokio::test]
    async fn run_returns_ok_even_when_drain_times_out() {
        use std::time::Instant;

        let (_dir, config) = run_config().await;

        // Inject a misbehaving subsystem into the App's *own* tracker via the
        // (module-private) `spawn_subsystem` seam.
        let drain_timeout = Duration::from_millis(80);
        let app = App::new(config).with_drain_timeout(drain_timeout);
        app.spawn_subsystem("rogue", |_token| async {
            tokio::time::sleep(Duration::from_secs(60)).await;
        });

        let start = Instant::now();
        let result = app.run_until_shutdown(async {}).await;
        let elapsed = start.elapsed();

        // Always returns Ok regardless of drain outcome (process exits 0).
        assert!(result.is_ok());
        // The drain timeout fired: we waited at least the timeout but nowhere
        // near the rogue task's 60s sleep.
        assert!(
            elapsed >= drain_timeout,
            "should have waited for the drain timeout, waited {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "should not have waited for the rogue task, waited {elapsed:?}"
        );
    }
}
