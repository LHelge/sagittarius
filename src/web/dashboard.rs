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
    telemetry::StatsSnapshot,
    web::{AppState, Chrome, auth::CurrentUser},
};

/// How many entries to show in the top-domains / top-clients tables.
const TOP_N: usize = 10;

impl AppState {
    /// `GET /` — the dashboard.
    pub async fn dashboard(user: CurrentUser, State(state): State<AppState>) -> impl IntoResponse {
        let snapshot = state.telemetry.stats.snapshot(TOP_N);
        let blocklist_size = state.resolver.blocklist().len();
        DashboardTemplate::new(
            state.chrome("dashboard", &user).await,
            snapshot,
            blocklist_size,
        )
    }
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
}

impl DashboardTemplate {
    fn new(chrome: Chrome, snap: StatsSnapshot, blocklist_size: usize) -> Self {
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
                .map(|(d, c)| (d, group(c)))
                .collect(),
            top_clients: snap
                .top_clients
                .into_iter()
                .map(|(ip, c)| (ip.to_string(), group(c)))
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
        let chrome = Chrome {
            theme: "auto".to_owned(),
            active: "dashboard",
            show_nav: true,
            authenticated: true,
            csrf_token: "tok".to_owned(),
        };
        let html = DashboardTemplate::new(chrome, snap, 65432)
            .render()
            .expect("render");
        // Counters seeded as raw Datastar signal values.
        assert!(html.contains("queries: 1000"));
        assert!(html.contains("blocked: 382"));
        // Blocklist size is server-formatted.
        assert!(html.contains("65,432"));
        // Top tables rendered.
        assert!(html.contains("ads.example.com."));
        assert!(html.contains("192.168.1.10"));
    }
}
