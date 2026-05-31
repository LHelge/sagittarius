//! Telemetry module — structured logging initialisation and runtime diagnostics.
//!
//! This module owns the one-time setup of the [`tracing`] global subscriber
//! (an `fmt` layer writing to stdout filtered by [`EnvFilter`]) as well as the
//! per-query event type, live-log ring buffer, and runtime statistics added in
//! E6.6.
//!
//! # Usage
//!
//! ```rust,ignore
//! // In main / app startup (E1.4 wires this):
//! let outcome = Telemetry::init();
//! Telemetry::log_startup(&config);
//! ```
//!
//! # Idempotency
//!
//! [`Telemetry::init`] uses `try_init()` semantics: it installs the subscriber
//! only if none has been set yet and returns [`InitOutcome`] to communicate
//! what happened. A second call (from another test or a double-init) never
//! panics — it returns [`InitOutcome::AlreadyInitialised`] and is a no-op.
//!
//! This is the right choice for a library/binary hybrid: tests share a
//! process, and the global subscriber can only be set once per process. Using
//! `try_init` instead of `init` lets every test call [`Telemetry::init`]
//! safely without coordinating who goes first.

// ── Submodules ────────────────────────────────────────────────────────────────

pub mod event;
pub mod live_log;
pub mod query_log_purge;
pub mod query_log_writer;
pub mod stats;

// ── Re-exports ────────────────────────────────────────────────────────────────

pub use event::{QUERY_LOG_CHANNEL_CAPACITY, QueryEvent, TelemetrySink};
pub use live_log::LiveLog;
pub use query_log_purge::QueryLogPurger;
pub use query_log_writer::QueryLogWriter;
pub use stats::{Stats, StatsSnapshot};

// ── Imports ───────────────────────────────────────────────────────────────────

use tracing::info;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, registry, util::SubscriberInitExt};

use crate::config::Config;

// ── InitOutcome ───────────────────────────────────────────────────────────────

/// The result of calling [`Telemetry::init`].
///
/// The caller can inspect this to decide whether to log a warning, but the
/// common case is to simply ignore it — the important property is that the
/// call never panics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitOutcome {
    /// The subscriber was freshly installed; this is the first call.
    Initialised,
    /// A global subscriber was already set (e.g. a previous call in the same
    /// process or another test). The new subscriber was **not** installed.
    AlreadyInitialised,
}

// ── Telemetry ─────────────────────────────────────────────────────────────────

/// Handle for the logging/telemetry subsystem.
///
/// All methods are associated functions rather than instance methods because
/// the underlying state (the `tracing` global subscriber) is process-global.
/// There is nothing to store in an instance. Using a unit struct gives us a
/// namespaced API (`Telemetry::init`, `Telemetry::log_startup`) that is easy
/// to `use` or call without losing the module identity.
pub struct Telemetry;

impl Telemetry {
    /// Build an [`EnvFilter`] from an optional explicit directive string.
    ///
    /// - If `directive` is `Some(s)` and parses successfully, that filter is
    ///   returned.
    /// - If `directive` is `None` or the string fails to parse, the default
    ///   `info` level is used.
    ///
    /// This is factored out from [`init`](Self::init) so that tests can verify
    /// filter-construction logic **without** touching the process-global
    /// `RUST_LOG` env variable (which would be racy in parallel test runs).
    pub fn build_filter(directive: Option<&str>) -> EnvFilter {
        directive
            .and_then(|d| EnvFilter::try_new(d).ok())
            .unwrap_or_else(|| EnvFilter::new("info"))
    }

    /// Initialise the global [`tracing`] subscriber.
    ///
    /// Sets up an `fmt` layer writing structured log lines to **stdout**,
    /// filtered by [`EnvFilter`]:
    ///
    /// - If `RUST_LOG` is set in the environment, its value is used as the
    ///   filter directive.
    /// - Otherwise, the filter defaults to `info`.
    ///
    /// The function is **idempotent**: calling it a second time returns
    /// [`InitOutcome::AlreadyInitialised`] without panicking. This is
    /// implemented by using `try_init()` on the registry, which returns an
    /// `Err` (rather than panicking) when a subscriber is already installed.
    pub fn init() -> InitOutcome {
        // Route through `build_filter` so the env-driven path is the same code
        // the unit tests exercise. `RUST_LOG` is the conventional directive var.
        let directive = std::env::var("RUST_LOG").ok();
        let filter = Self::build_filter(directive.as_deref());

        let result = registry()
            .with(filter)
            .with(fmt::layer().with_writer(std::io::stdout))
            .try_init();

        match result {
            Ok(()) => InitOutcome::Initialised,
            Err(_) => InitOutcome::AlreadyInitialised,
        }
    }

    /// Emit a structured startup log line at `info` level.
    ///
    /// Logs the binary name and version (from the package metadata compiled
    /// into the binary via `env!`) together with the resolved operational
    /// configuration: DNS bind addresses, admin bind address, and database
    /// path.
    ///
    /// Call this once after [`init`](Self::init) returns.
    pub fn log_startup(cfg: &Config) {
        info!(
            name = env!("CARGO_PKG_NAME"),
            version = env!("CARGO_PKG_VERSION"),
            dns_addrs = ?cfg.dns_addrs,
            admin_addr = %cfg.admin_addr,
            db_path = ?cfg.db_path,
            "starting sagittarius",
        );
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Idempotency ───────────────────────────────────────────────────────────
    //
    // The global tracing subscriber can only be installed once per process.
    // Tests run in parallel and share the same process, so we cannot assert
    // which specific `InitOutcome` the first call produces — it depends on
    // which test (or the binary itself) happens to call `Telemetry::init`
    // first.
    //
    // What we *can* assert is that neither call panics, and that the second
    // call (which happens sequentially *within this test*) always returns
    // `AlreadyInitialised`.

    #[test]
    fn init_is_idempotent_no_panic() {
        // First call — outcome is indeterminate (another test may have gone first).
        let _first = Telemetry::init();

        // Second call in the same test — must not panic and must return
        // `AlreadyInitialised` because we just ensured one is set.
        let second = Telemetry::init();
        assert_eq!(second, InitOutcome::AlreadyInitialised);
    }

    // ── EnvFilter construction ────────────────────────────────────────────────
    //
    // We test filter construction via `build_filter` rather than by mutating
    // the process-global `RUST_LOG` environment variable. Mutating env vars in
    // parallel tests is inherently racy (another test might read or write
    // `RUST_LOG` concurrently), so we avoid it entirely.

    #[test]
    fn build_filter_none_yields_info_default() {
        // Without any directive, the filter should accept `info`-level events.
        let filter = Telemetry::build_filter(None);
        // EnvFilter's Display implementation shows the active directives; an
        // `info` default renders as "info".
        assert_eq!(filter.to_string(), "info");
    }

    #[test]
    fn build_filter_explicit_directive_parses() {
        // A valid directive string is accepted without error.
        let filter = Telemetry::build_filter(Some("sagittarius=debug"));
        // The directive round-trips through Display.
        assert_eq!(filter.to_string(), "sagittarius=debug");
    }

    #[test]
    fn build_filter_invalid_directive_falls_back_to_info() {
        // An unparseable directive string falls back to the `info` default.
        let filter = Telemetry::build_filter(Some("this=is=not=valid====="));
        assert_eq!(filter.to_string(), "info");
    }

    #[test]
    fn build_filter_multiple_directives() {
        // Multiple directives separated by commas are accepted.
        let filter = Telemetry::build_filter(Some("warn,sagittarius=debug"));
        let s = filter.to_string();
        assert!(
            s.contains("sagittarius=debug"),
            "expected directive in: {s}"
        );
    }

    // ── log_startup smoke test ────────────────────────────────────────────────

    #[test]
    fn log_startup_does_not_panic() {
        use crate::config::SessionCookieSecurePolicy;
        use std::net::SocketAddr;
        use std::path::PathBuf;

        // Ensure a subscriber is installed so the tracing event is dispatched
        // (or swallowed) without panicking.
        let _ = Telemetry::init();

        let cfg = Config {
            dns_addrs: vec!["0.0.0.0:53".parse::<SocketAddr>().unwrap()],
            admin_addr: "127.0.0.1:8080".parse::<SocketAddr>().unwrap(),
            db_path: PathBuf::from("sagittarius.db"),
            session_cookie_secure: SessionCookieSecurePolicy::Auto,
        };

        // Must not panic.
        Telemetry::log_startup(&cfg);
    }
}
