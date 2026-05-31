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
    blocklist::{fetch::Fetcher, scheduler::BlocklistScheduler},
    config::Config,
    error::Result,
    resolver::{
        pipeline::{engine::build_engine, listener::DnsListeners, middleware::ProtectiveConfig},
        state::ResolverState,
        upstream::{
            DEFAULT_FAILOVER_BUDGET, DEFAULT_QUERY_TIMEOUT, RandomSelector, SharedUpstreamPool,
            UpstreamConfig, UpstreamPool,
        },
    },
    storage::{Db, upstreams::UpstreamRepository},
    telemetry::{
        LiveLog, QUERY_LOG_CHANNEL_CAPACITY, QueryLogPurger, QueryLogWriter, Stats, TelemetrySink,
    },
    web::{AdminServer, AppState},
};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Default amount of time to wait for in-flight tasks to drain before giving
/// up and returning anyway.
pub const DEFAULT_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

// ── RuntimeAddrs ────────────────────────────────────────────────────────────────

/// The addresses the runtime actually bound, surfaced once every subsystem is
/// listening.
///
/// When the configuration requests an ephemeral port (`:0`) the OS picks the
/// real port; this struct reports the resolved values so callers — notably the
/// integration test harness — can reach the live DNS and admin surfaces.
#[derive(Debug, Clone)]
pub struct RuntimeAddrs {
    /// Bound UDP DNS socket addresses (one entry per bound socket).
    pub dns_udp: Vec<std::net::SocketAddr>,
    /// Bound admin HTTP server address.
    pub admin: std::net::SocketAddr,
}

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
    ///
    /// `on_ready` is invoked exactly once with the actually-bound
    /// [`RuntimeAddrs`] after every subsystem is listening and just before the
    /// shutdown trigger is awaited. It lets embedders and integration tests
    /// discover OS-chosen ephemeral ports and drive the live DNS and admin
    /// surfaces; [`run`](Self::run) passes a no-op.
    pub async fn run_until_ready(
        self,
        shutdown: impl Future<Output = ()>,
        on_ready: impl FnOnce(RuntimeAddrs),
    ) -> Result<()> {
        // ── Real DNS engine startup ────────────────────────────────────────────
        let db = Db::connect(&self.config.db_path).await?;
        let state = ResolverState::hydrate(&db).await?;

        // ── Blocklist offline start ───────────────────────────────────────────
        // Build the scheduler *before* cloning `state` into the engine so both
        // share the same `Arc<ResolverState>`.  `load_from_cache` is awaited
        // here (synchronously within run_until_shutdown) so that blocklist
        // domains are active before the DNS listener starts serving.
        let scheduler =
            BlocklistScheduler::new(db.blocklists(), Arc::clone(&state), Fetcher::new());
        scheduler.load_from_cache().await;

        let rows = db.upstreams().list_enabled().await?;

        let configs: Vec<_> = rows
            .iter()
            .filter_map(|r| match UpstreamConfig::try_from(r) {
                Ok(c) => Some(c),
                Err(_) => {
                    tracing::warn!(addr = %r.address, "skipping unmappable upstream");
                    None
                }
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

        // Persist query events off the hot path: the sink `try_send`s onto a
        // bounded channel that a dedicated writer task drains into SQLite.
        // Capture a resolver handle for the writer gate and the purge task
        // before `state` is moved into the engine below.
        let query_log_state = Arc::clone(&state);
        let (query_log_tx, query_log_rx) = tokio::sync::mpsc::channel(QUERY_LOG_CHANNEL_CAPACITY);
        let telemetry = Arc::new(
            TelemetrySink::new(Arc::new(LiveLog::default()), Arc::new(Stats::new()))
                .with_query_log(query_log_tx, Arc::clone(&query_log_state)),
        );

        // ── Web admin shared state ────────────────────────────────────────────
        // Built from clones before the originals are moved into the engine, so
        // the DNS engine and the admin UI share the same `ResolverState`,
        // telemetry sink, and blocklist refresh trigger.
        let app_state = AppState {
            db: db.clone(),
            resolver: Arc::clone(&state),
            telemetry: Arc::clone(&telemetry),
            refresh: scheduler.trigger(),
            cookie_policy: self.config.session_cookie_secure,
            csrf_key: crate::web::random_csrf_key(),
            setup_done: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            upstream_pool: Arc::clone(&pool),
            tracker: self.tracker.clone(),
        };

        let engine = build_engine(state, pool, telemetry, &ProtectiveConfig::default());

        let udp_sockets_per_addr = std::thread::available_parallelism()
            .map(NonZeroUsize::get)
            .unwrap_or(1);
        let listeners = DnsListeners::bind(&self.config.dns_addrs, udp_sockets_per_addr)?;
        // Capture the actually-bound UDP addresses before `serve` consumes the
        // listener set; with `:0` these carry the OS-chosen ports.
        let dns_udp = listeners.udp_local_addrs();
        listeners.serve(engine, self.shutdown_token.clone(), &self.tracker);

        // ── Web admin server ──────────────────────────────────────────────────
        // Bind here (not inside the spawned task) so a bad --admin-addr fails
        // startup, mirroring the DNS listener's bind → serve split.
        let admin = AdminServer::bind(self.config.admin_addr, app_state).await?;
        let admin_addr = admin.local_addr()?;

        // ── Subsystem tasks ───────────────────────────────────────────────────
        self.spawn_subsystem("web-admin", move |token| async move {
            admin.serve(token).await;
        });

        self.spawn_subsystem("blocklist-refresh", move |token| async move {
            scheduler.run(token).await;
        });

        // Drain persisted query events into SQLite, decoupled from the hot path.
        // The writer also resolves the primary blocklist source for blocked
        // events from the shared state (E11.3).
        let query_log_writer =
            QueryLogWriter::new(query_log_rx, db.query_log(), Arc::clone(&query_log_state));
        self.spawn_subsystem("query-log-writer", move |token| async move {
            query_log_writer.run(token).await;
        });

        // Enforce the query-log retention window hourly and reclaim disk pages.
        let query_log_purger = QueryLogPurger::new(db.query_log(), query_log_state);
        self.spawn_subsystem("query-log-purge", move |token| async move {
            query_log_purger.run(token).await;
        });

        // Close the tracker so `wait()` can complete once tracked tasks drain.
        // `TaskTracker` still tracks later spawns, such as rebuilt upstream
        // drivers, but no more startup subsystem tasks are registered here.
        self.tracker.close();

        // All subsystems are bound and serving — log the resolved addresses and
        // hand them to the readiness seam before blocking on the trigger.
        // The UDP set holds one entry per `SO_REUSEPORT` socket, so collapse
        // duplicates for a readable log line.
        let unique_dns: std::collections::BTreeSet<_> = dns_udp.iter().copied().collect();
        info!(
            dns_addrs = ?unique_dns,
            admin_addr = %admin_addr,
            "runtime ready, awaiting shutdown signal",
        );
        on_ready(RuntimeAddrs {
            dns_udp,
            admin: admin_addr,
        });

        // Wait for the shutdown trigger.
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

    /// Run until `shutdown` resolves, discarding the readiness addresses.
    ///
    /// Thin wrapper over [`run_until_ready`](Self::run_until_ready) for callers
    /// and tests that don't need the bound addresses.
    async fn run_until_shutdown(self, shutdown: impl Future<Output = ()>) -> Result<()> {
        self.run_until_ready(shutdown, |_| {}).await
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

    // ── Full-stack assembly (E9.1 capstone) ───────────────────────────────
    //
    // Prove the assembled binary brings up all three subsystems together and,
    // *before any admin account exists*, the first-run wizard is reachable over
    // HTTP **and** the DNS listener answers a query authoritatively. The query
    // targets a seeded local record so the assertion needs no upstream/network.

    #[tokio::test]
    async fn full_stack_serves_dns_and_wizard_before_admin_exists() {
        use tokio::net::UdpSocket;
        use tokio::sync::oneshot;

        use crate::codec::{header::Header, name::Name, writer::Writer};
        use crate::storage::local_records::{LocalRecordRepository, NewLocalRecord, RecordType};

        // Seed a local A record so DNS can answer with no upstream/network.
        let dir = TempDir::new().expect("temp dir");
        let db_path = dir.path().join("test.db");
        let db = Db::connect(&db_path).await.expect("create db");
        db.local_records()
            .add(NewLocalRecord {
                name: "router.home.lan".to_string(),
                record_type: RecordType::A,
                value: "192.168.1.1".to_string(),
                ttl: 300,
            })
            .await
            .expect("seed local record");
        drop(db);

        let config = Config {
            dns_addrs: vec!["127.0.0.1:0".parse::<SocketAddr>().unwrap()],
            admin_addr: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            db_path,
            session_cookie_secure: SessionCookieSecurePolicy::Never,
        };

        // Launch the fully-assembled App on a background task; the readiness
        // seam hands back the OS-chosen ephemeral ports.
        let app = App::new(config).with_drain_timeout(Duration::from_secs(2));
        let (ready_tx, ready_rx) = oneshot::channel::<RuntimeAddrs>();
        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            app.run_until_ready(
                async move {
                    let _ = stop_rx.await;
                },
                move |addrs| {
                    let _ = ready_tx.send(addrs);
                },
            )
            .await
        });

        let addrs = timeout(Duration::from_secs(5), ready_rx)
            .await
            .expect("startup within 5s")
            .expect("ready signal");

        // 1) First-run wizard is reachable while admin_users is empty.
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let base = format!("http://{}", addrs.admin);

        let root = client.get(format!("{base}/")).send().await.expect("GET /");
        assert_eq!(root.status(), 303, "root redirects while no admin exists");
        assert_eq!(root.headers().get("location").unwrap(), "/setup");

        let setup = client
            .get(format!("{base}/setup"))
            .send()
            .await
            .expect("GET /setup");
        assert_eq!(setup.status(), 200, "wizard must render");
        assert!(
            setup.text().await.unwrap().contains("Welcome"),
            "wizard page content",
        );

        // 2) DNS answers the seeded local record authoritatively.
        let server = addrs.dns_udp[0];
        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("client socket");
        sock.connect(server).await.expect("connect");

        let mut w = Writer::with_capacity(64);
        Header::new(0xBEEF)
            .with_qdcount(1)
            .with_rd(true)
            .write(&mut w);
        let qname: Name = "router.home.lan.".parse().expect("name");
        qname.write(&mut w);
        w.write_u16(1u16); // QTYPE A
        w.write_u16(1u16); // QCLASS IN
        sock.send(&w.finish()).await.expect("send query");

        let mut buf = vec![0u8; 512];
        let n = timeout(Duration::from_secs(5), sock.recv(&mut buf))
            .await
            .expect("response within 5s")
            .expect("recv");
        let resp = &buf[..n];

        assert_eq!(u16::from_be_bytes([resp[0], resp[1]]), 0xBEEF, "txn id");
        assert_ne!(resp[2] & 0x80, 0, "QR bit must be set (response)");
        assert_eq!(resp[3] & 0x0f, 0, "RCODE must be NOERROR");
        let ancount = u16::from_be_bytes([resp[6], resp[7]]);
        assert!(ancount >= 1, "at least one answer record");
        assert!(
            resp.windows(4).any(|bytes| bytes == [192, 168, 1, 1]),
            "answer must carry the seeded A address",
        );

        // Clean shutdown drains every subsystem and exits Ok.
        let _ = stop_tx.send(());
        let result = timeout(Duration::from_secs(5), handle)
            .await
            .expect("App shuts down within 5s")
            .expect("join");
        assert!(result.is_ok());
    }
}
