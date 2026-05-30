//! Live query log over SSE (SPEC §9, §3.1).
//!
//! The `/log` page renders the recent ring-buffer history server-side (newest
//! first) and then opens a single SSE stream to `/events`.  That one stream
//! drives **both** the log and the dashboard:
//!
//! - [`PatchElements`] prepends each new query as a `<tr>` into `#log-body`,
//! - [`PatchSignals`] pushes the cumulative runtime counters so the dashboard
//!   cards update live (SPEC §9: a single stream updates log + dashboard).
//!
//! Seeding history server-side (rather than replaying it over SSE) follows the
//! [`LiveLog`](crate::telemetry::LiveLog) "snapshot then subscribe" contract and
//! means an SSE reconnect resumes the live tail without duplicating history.
//!
//! Filtering is client-side: each row carries a Datastar `data-show` expression
//! evaluated against the `f_outcome` / `f_text` filter signals, so narrowing the
//! view is instant and needs no round-trip.  Each row also records its detailed
//! [`Outcome`] category, which E8.7 uses to show only effective one-click
//! actions.

use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use askama::Template;
use askama_web::WebTemplate;
use axum::{
    extract::State,
    response::{
        IntoResponse, Sse,
        sse::{Event, KeepAlive},
    },
};
use datastar::{
    consts::ElementPatchMode,
    prelude::{PatchElements, PatchSignals},
};
use tokio::sync::broadcast::error::RecvError;

use crate::{
    resolver::pipeline::Outcome,
    telemetry::{QueryEvent, Stats},
    web::{AppState, Chrome, auth::CurrentUser, render::DomainDisplay},
};

impl AppState {
    /// `GET /log` — the live query-log page, seeded with recent history.
    pub async fn query_log(user: CurrentUser, State(state): State<AppState>) -> impl IntoResponse {
        // Ring buffer is oldest-first; show newest first.
        let rows: Vec<String> = state
            .telemetry
            .live_log
            .recent()
            .iter()
            .rev()
            .filter_map(|ev| LogRowView::from_event(ev).render().ok())
            .collect();
        LogPageTemplate {
            chrome: state.chrome("log", &user).await,
            rows,
        }
    }

    /// `GET /events` — the shared SSE stream feeding the log and dashboard.
    pub async fn events(_user: CurrentUser, State(state): State<AppState>) -> impl IntoResponse {
        let mut rx = state.telemetry.live_log.subscribe();
        let stats = Arc::clone(&state.telemetry.stats);

        let stream = async_stream::stream! {
            // Send the current counters immediately so a freshly opened
            // dashboard/log corrects to the live totals.
            yield Ok::<Event, Infallible>(counters_event(&stats));

            loop {
                match rx.recv().await {
                    Ok(ev) => {
                        yield Ok(row_event(&ev));
                        yield Ok(counters_event(&stats));
                    }
                    // Drop-oldest semantics: a lagging subscriber skips the
                    // missed events and keeps streaming the latest.
                    Err(RecvError::Lagged(_)) => continue,
                    Err(RecvError::Closed) => break,
                }
            }
        };

        Sse::new(stream).keep_alive(KeepAlive::default())
    }
}

/// Build the `PatchElements` event that prepends one query row.
fn row_event(ev: &QueryEvent) -> Event {
    let html = LogRowView::from_event(ev).render().unwrap_or_default();
    PatchElements::new(html)
        .selector("#log-body")
        .mode(ElementPatchMode::Prepend)
        .write_as_axum_sse_event()
}

/// Build the `PatchSignals` event carrying the cumulative counters.
fn counters_event(stats: &Stats) -> Event {
    let s = stats.snapshot(0);
    let json = format!(
        r#"{{"queries":{},"blocked":{},"cached":{},"forwarded":{}}}"#,
        s.total, s.blocked, s.cached, s.forwarded
    );
    PatchSignals::new(json).write_as_axum_sse_event()
}

/// Map an [`Outcome`] to a filter category and a badge CSS class.
fn categorize(outcome: Outcome) -> (&'static str, &'static str) {
    match outcome {
        Outcome::BlockedByAdmin | Outcome::BlockedByBlocklist => ("blocked", "sgt-badge--blocked"),
        Outcome::Cached => ("cached", "sgt-badge--cached"),
        Outcome::Forwarded => ("forwarded", "sgt-badge--forwarded"),
        Outcome::Local | Outcome::LocalNoData => ("local", "sgt-badge--local"),
        Outcome::Refused | Outcome::Formerr | Outcome::Servfail | Outcome::Error => {
            ("other", "sgt-badge--other")
        }
    }
}

// ── Templates ───────────────────────────────────────────────────────────────

/// One rendered query-log row.  Shared by the server-side seed and the SSE
/// stream so both render identical markup.
#[derive(Template, WebTemplate)]
#[template(path = "log_row.html")]
struct LogRowView {
    client: String,
    qname: String,
    qtype: String,
    outcome_label: String,
    outcome_class: &'static str,
    outcome_cat: &'static str,
    latency_ms: u64,
    /// Lowercased "qname client" haystack for the client-side text filter.
    search: String,
    /// Pre-rendered one-click action cell (the [`ActionButton`] partial), so
    /// the seed render and the SSE stream emit identical markup.
    action_html: String,
}

/// Monotonic id for each rendered log row, so a one-click action can target the
/// exact button that was clicked (E8.7) — even for repeated queries to the same
/// domain.
static ROW_SEQ: AtomicU64 = AtomicU64::new(0);

impl LogRowView {
    fn from_event(ev: &QueryEvent) -> Self {
        let (cat, class) = categorize(ev.outcome);
        // Display the bare domain; the canonical trailing dot stays internal.
        let qname = ev.qname.to_string().display_domain().to_owned();
        let client = ev.client.ip().to_string();
        let search = format!("{} {}", qname.to_lowercase(), client);
        let action_kind = if ev.outcome.offers_whitelist() {
            "allow"
        } else if ev.outcome.offers_blacklist() {
            "deny"
        } else {
            ""
        };
        let row_id = ROW_SEQ.fetch_add(1, Ordering::Relaxed);
        let action_html = ActionButton {
            kind: action_kind,
            added: false,
            domain: qname.clone(),
            row_id,
        }
        .render()
        .unwrap_or_default();
        Self {
            client,
            qname,
            qtype: format!("{:?}", ev.qtype),
            outcome_label: ev.outcome.to_string(),
            outcome_class: class,
            outcome_cat: cat,
            latency_ms: ev.latency.as_millis() as u64,
            search,
            action_html,
        }
    }
}

/// The one-click action cell for a log row.  Toggles between the add action
/// (Whitelist / Blacklist) and the corresponding remove action once applied,
/// patched in place by the action handlers via its `act-{row_id}` id (E8.7).
#[derive(Template, WebTemplate)]
#[template(path = "log_action.html")]
pub(crate) struct ActionButton {
    /// `"allow"`, `"deny"`, or `""` (no effective action).
    pub kind: &'static str,
    /// Whether the domain is now on the list (renders the remove variant).
    pub added: bool,
    pub domain: String,
    pub row_id: u64,
}

/// The query-log page.
#[derive(Template, WebTemplate)]
#[template(path = "log.html")]
struct LogPageTemplate {
    chrome: Chrome,
    rows: Vec<String>,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{message::Qtype, name::Name};
    use std::time::Duration;

    fn event(domain: &str, outcome: Outcome) -> QueryEvent {
        let client = "192.168.1.5:5000".parse().unwrap();
        let qname: Name = domain.parse().unwrap();
        QueryEvent::new(client, qname, Qtype::A, outcome).with_latency(Duration::from_millis(7))
    }

    #[test]
    fn categorize_maps_outcomes() {
        assert_eq!(categorize(Outcome::BlockedByBlocklist).0, "blocked");
        assert_eq!(categorize(Outcome::BlockedByAdmin).0, "blocked");
        assert_eq!(categorize(Outcome::Cached).0, "cached");
        assert_eq!(categorize(Outcome::Forwarded).0, "forwarded");
        assert_eq!(categorize(Outcome::Local).0, "local");
        assert_eq!(categorize(Outcome::Servfail).0, "other");
    }

    #[test]
    fn row_renders_outcome_filter_and_search() {
        let html = LogRowView::from_event(&event("ads.example.com", Outcome::BlockedByBlocklist))
            .render()
            .expect("render row");
        // Displayed without the canonical trailing dot.
        assert!(html.contains("ads.example.com"));
        assert!(!html.contains("ads.example.com."));
        assert!(html.contains("192.168.1.5"));
        assert!(html.contains("sgt-badge--blocked"));
        // Carries the filter category and the data-show expression.
        assert!(html.contains("blocked"));
        assert!(html.contains("data-show"));
        assert!(html.contains("7 ms"));
        // A blocklist-blocked row offers the one-click Whitelist action.
        assert!(html.contains("Whitelist"));
        assert!(html.contains("/log/whitelist?domain=ads.example.com&amp;"));
    }

    #[test]
    fn row_action_varies_by_outcome() {
        // Resolved rows offer Blacklist.
        let cached = LogRowView::from_event(&event("good.example.com", Outcome::Cached))
            .render()
            .unwrap();
        assert!(cached.contains("Blacklist"));
        assert!(cached.contains("/log/blacklist?domain=good.example.com&amp;"));

        // Admin-blocked and local rows offer no one-click action.
        for o in [
            Outcome::BlockedByAdmin,
            Outcome::Local,
            Outcome::LocalNoData,
        ] {
            let html = LogRowView::from_event(&event("x.example.com", o))
                .render()
                .unwrap();
            assert!(
                !html.contains("Whitelist"),
                "{o:?} must not offer whitelist"
            );
            assert!(
                !html.contains("Blacklist"),
                "{o:?} must not offer blacklist"
            );
        }
    }

    #[test]
    fn counters_event_is_valid_signal_json() {
        let stats = Stats::new();
        stats.record(&event("a.test", Outcome::Forwarded));
        let ev = counters_event(&stats);
        // The datastar signal payload is carried in the event data lines.
        let rendered = format!("{ev:?}");
        assert!(rendered.contains("queries"));
    }
}
