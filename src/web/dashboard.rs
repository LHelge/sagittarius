//! Dashboard page — since-startup runtime figures (SPEC §9).
//!
//! Renders the in-memory E6.6 runtime counters (total queries, blocked count
//! and ratio, cached, forwarded, top domains, top clients) plus the current
//! in-memory aggregated **blocklist set size** read from the shared
//! [`ResolverState`](crate::resolver::state::ResolverState).
//!
//! The four scalar counters are seeded into Datastar **signals** and formatted
//! client-side, so the live SSE stream (E8.6) can update them with a single
//! `PatchSignals` event without re-rendering the page.  The top-N tables and
//! the blocklist size are server-rendered and refresh on navigation.
//!
//! v0.1 figures are since-startup and non-persistent.

use askama::Template;
use askama_web::WebTemplate;
use axum::{extract::State, response::IntoResponse};

use crate::{
    storage::query_log::{QueryLogCounts, QueryLogRepository, SqliteQueryLogRepo},
    telemetry::StatsSnapshot,
    time::Clock,
    web::{AppState, Chrome, auth::CurrentUser, render::DomainDisplay},
};

/// How many entries to show in the top-domains / top-clients tables.
const TOP_N: usize = 10;

/// The persisted-figures window: the last 24 hours, in milliseconds.
const WINDOW_MS: i64 = 24 * 3_600 * 1_000;

impl AppState {
    /// `GET /` — the dashboard.
    ///
    /// Combines the live since-startup counters (in-memory, streamed over SSE)
    /// with a restart-surviving 24-hour window read from the `query_log` table.
    pub async fn dashboard(user: CurrentUser, State(state): State<AppState>) -> impl IntoResponse {
        let snapshot = state.telemetry.stats.snapshot(TOP_N);
        let blocklist_size = state.resolver.blocklist().len();

        // Persisted 24h window. On a DB error the figures degrade to zeros
        // rather than failing the whole page.
        let repo = SqliteQueryLogRepo::new(state.db.pool().clone());
        let since = Clock::now_millis() - WINDOW_MS;
        let window = WindowStats {
            counts: repo.counts_since(since).await.unwrap_or_default(),
            top_domains: repo
                .top_domains_since(since, TOP_N as i64)
                .await
                .unwrap_or_default(),
            top_clients: repo
                .top_clients_since(since, TOP_N as i64)
                .await
                .unwrap_or_default(),
        };

        DashboardTemplate::new(
            state.chrome("dashboard", &user).await,
            snapshot,
            blocklist_size,
            window,
        )
    }
}

/// Persisted, windowed aggregates read from `query_log` for the dashboard.
struct WindowStats {
    counts: QueryLogCounts,
    top_domains: Vec<(String, i64)>,
    top_clients: Vec<(String, i64)>,
}

/// The dashboard view model.
///
/// The scalar counters are raw numbers (seeded into Datastar signals and
/// formatted client-side via `toLocaleString()`); the tables and blocklist
/// size are pre-formatted strings.
#[derive(Template, WebTemplate)]
#[template(path = "dashboard.html")]
struct DashboardTemplate {
    chrome: Chrome,
    total: u64,
    blocked: u64,
    cached: u64,
    forwarded: u64,
    blocklist_size: String,
    top_domains: Vec<(String, String)>,
    top_clients: Vec<(String, String)>,
    // Persisted 24h window (pre-formatted strings; these don't stream live).
    window_total: String,
    window_blocked: String,
    window_cached: String,
    window_forwarded: String,
    window_top_domains: Vec<(String, String)>,
    window_top_clients: Vec<(String, String)>,
}

impl DashboardTemplate {
    fn new(
        chrome: Chrome,
        snap: StatsSnapshot,
        blocklist_size: usize,
        window: WindowStats,
    ) -> Self {
        Self {
            chrome,
            total: snap.total,
            blocked: snap.blocked,
            cached: snap.cached,
            forwarded: snap.forwarded,
            blocklist_size: group(blocklist_size as u64),
            top_domains: snap
                .top_domains
                .into_iter()
                .map(|(d, c)| (d.display_domain().to_owned(), group(c)))
                .collect(),
            top_clients: snap
                .top_clients
                .into_iter()
                .map(|(ip, c)| (ip.to_string(), group(c)))
                .collect(),
            window_total: group(window.counts.total.max(0) as u64),
            window_blocked: group(window.counts.blocked.max(0) as u64),
            window_cached: group(window.counts.cached.max(0) as u64),
            window_forwarded: group(window.counts.forwarded.max(0) as u64),
            window_top_domains: window
                .top_domains
                .into_iter()
                .map(|(d, c)| (d.display_domain().to_owned(), group(c.max(0) as u64)))
                .collect(),
            window_top_clients: window
                .top_clients
                .into_iter()
                .map(|(ip, c)| (ip, group(c.max(0) as u64)))
                .collect(),
        }
    }
}

/// Format an integer with `,` thousands separators (e.g. `12403` → `12,403`).
pub(crate) fn group(n: u64) -> String {
    let digits = n.to_string();
    let len = digits.len();
    let mut out = String::with_capacity(len + len / 3);
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && (len - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_inserts_thousands_separators() {
        assert_eq!(group(0), "0");
        assert_eq!(group(42), "42");
        assert_eq!(group(1_000), "1,000");
        assert_eq!(group(12_403), "12,403");
        assert_eq!(group(1_234_567), "1,234,567");
    }

    fn test_chrome() -> Chrome {
        Chrome {
            theme: "auto".to_owned(),
            active: "dashboard",
            show_nav: true,
            authenticated: true,
            csrf_token: "tok".to_owned(),
        }
    }

    #[test]
    fn template_seeds_signals_and_tables() {
        let snap = StatsSnapshot {
            total: 1000,
            blocked: 382,
            cached: 100,
            forwarded: 518,
            blocked_ratio: 0.382,
            top_domains: vec![("ads.example.com.".to_owned(), 50)],
            top_clients: vec![("192.168.1.10".parse().unwrap(), 120)],
        };
        let window = WindowStats {
            counts: QueryLogCounts {
                total: 2400,
                blocked: 900,
                cached: 500,
                forwarded: 1000,
            },
            top_domains: vec![("win.example.com.".to_owned(), 77)],
            top_clients: vec![("10.9.8.7".to_owned(), 64)],
        };
        let html = DashboardTemplate::new(test_chrome(), snap, 65432, window)
            .render()
            .expect("render");
        // Live counters seeded as raw Datastar signal values.
        assert!(html.contains("queries: 1000"));
        assert!(html.contains("blocked: 382"));
        // Blocklist size is server-formatted.
        assert!(html.contains("65,432"));
        // Live top tables rendered without the canonical trailing dot.
        assert!(html.contains("ads.example.com"));
        assert!(!html.contains("ads.example.com."));
        assert!(html.contains("192.168.1.10"));
        // Persisted 24h window: figures (thousands-grouped) and trimmed domain.
        assert!(html.contains("Last 24 hours (persisted)"));
        assert!(html.contains("2,400"));
        assert!(html.contains("win.example.com"));
        assert!(!html.contains("win.example.com."));
        assert!(html.contains("10.9.8.7"));
    }

    #[test]
    fn template_empty_window_renders_zeros_without_panic() {
        let snap = StatsSnapshot {
            total: 0,
            blocked: 0,
            cached: 0,
            forwarded: 0,
            blocked_ratio: 0.0,
            top_domains: vec![],
            top_clients: vec![],
        };
        let window = WindowStats {
            counts: QueryLogCounts::default(),
            top_domains: vec![],
            top_clients: vec![],
        };
        let html = DashboardTemplate::new(test_chrome(), snap, 0, window)
            .render()
            .expect("render");
        assert!(html.contains("No queries in the last 24 hours."));
    }
}
