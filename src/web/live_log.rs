//! Live query log over SSE (SPEC §9, §3.1).
//!
//! The `/log` page renders the newest page of **durable** history from the
//! `query_log` table server-side (newest first) and then opens a single SSE
//! stream to `/events`.  That one stream drives **both** the log and the
//! dashboard:
//!
//! - [`PatchElements`] prepends each new query as a `<tr>` into `#log-body`,
//! - [`PatchSignals`] pushes the cumulative runtime counters so the dashboard
//!   cards update live (SPEC §9: a single stream updates log + dashboard).
//!
//! # History / live seam
//!
//! History comes from the DB ([`SqliteQueryLogRepo::page`]); the live stream
//! covers "now" forward via the [`LiveLog`](crate::telemetry::LiveLog) broadcast
//! ("subscribe-then-render" semantics). The batch writer (E10.4) lags by ~1s, so
//! the very newest events appear in the broadcast tail before they reach the DB
//! — they render via the live prepend, and a later refresh shows them from the
//! DB. **Scroll-back** is served by `GET /log/older?before=<id>`, which appends
//! the next older page keyed on the smallest currently-visible row `id`.
//!
//! Filtering is client-side: each row carries a Datastar `data-show` expression
//! evaluated against the `f_outcome` / `f_text` filter signals, so narrowing the
//! view is instant and needs no round-trip.  Each row also records its detailed
//! [`Outcome`] category, which E8.7 uses to show only effective one-click
//! actions.

use std::{convert::Infallible, sync::Arc};

use askama::Template;
use askama_web::WebTemplate;
use axum::{
    extract::{Query, State},
    response::{
        IntoResponse, Response, Sse,
        sse::{Event, KeepAlive},
    },
};
use datastar::{
    consts::ElementPatchMode,
    prelude::{PatchElements, PatchSignals},
};
use serde::Deserialize;
use tokio::sync::broadcast::error::RecvError;

use crate::{
    resolver::pipeline::LogAction,
    storage::query_log::{QueryLogRecord, QueryLogRepository, SqliteQueryLogRepo},
    telemetry::{QueryEvent, Stats},
    web::{AppState, Chrome, auth::CurrentUser, render::DomainDisplay, render::WebError},
};

/// How many rows to render per page (initial seed and each scroll-back step).
const LOG_PAGE_SIZE: i64 = 100;

impl AppState {
    /// `GET /log` — the query-log page, seeded with the newest page of history.
    pub async fn query_log(user: CurrentUser, State(state): State<AppState>) -> Response {
        let records = match SqliteQueryLogRepo::new(state.db.pool().clone())
            .page(None, LOG_PAGE_SIZE)
            .await
        {
            Ok(records) => records,
            Err(e) => return WebError::from(e).into_response(),
        };
        // page() is newest-first, so the last row carries the smallest id — the
        // cursor for loading the next older page.
        let oldest = records.last().map(|r| r.id).unwrap_or(0);
        let rows: Vec<String> = records
            .iter()
            .filter_map(|r| LogRowView::from_record(r).render().ok())
            .collect();
        LogPageTemplate {
            chrome: state.chrome("log", &user).await,
            rows,
            oldest,
        }
        .into_response()
    }

    /// `GET /log/older?before=<id>` — append the next older page of history.
    ///
    /// Returns a one-shot Datastar SSE response that appends the older rows into
    /// `#log-body` and updates the `oldest` cursor signal so repeated clicks
    /// paginate further back. An empty result just sets `oldest` to 0, which
    /// hides the "Load older" control.
    pub async fn query_log_older(
        _user: CurrentUser,
        State(state): State<AppState>,
        Query(q): Query<OlderQuery>,
    ) -> Response {
        let records = match SqliteQueryLogRepo::new(state.db.pool().clone())
            .page(Some(q.before), LOG_PAGE_SIZE)
            .await
        {
            Ok(records) => records,
            Err(e) => return WebError::from(e).into_response(),
        };
        let new_oldest = records.last().map(|r| r.id).unwrap_or(0);
        let html: String = records
            .iter()
            .filter_map(|r| LogRowView::from_record(r).render().ok())
            .collect();

        let signal =
            PatchSignals::new(format!(r#"{{"oldest":{new_oldest}}}"#)).write_as_axum_sse_event();
        let rows_event = (!html.is_empty()).then(|| {
            PatchElements::new(html)
                .selector("#log-body")
                .mode(ElementPatchMode::Append)
                .write_as_axum_sse_event()
        });

        Sse::new(async_stream::stream! {
            if let Some(rows) = rows_event {
                yield Ok::<Event, Infallible>(rows);
            }
            yield Ok(signal);
        })
        .into_response()
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

// ── Templates ───────────────────────────────────────────────────────────────

/// One rendered query-log row.  Shared by the server-side seed and the SSE
/// stream so both render identical markup.
#[derive(Template, WebTemplate)]
#[template(path = "log_row.html")]
struct LogRowView {
    /// Durable DB row id (the scroll-back cursor); `0` for a live-tail row that
    /// the batch writer has not persisted yet.
    id: i64,
    client: String,
    qname: String,
    qtype: String,
    outcome_label: String,
    outcome_cat: &'static str,
    latency_ms: u64,
    /// Lowercased "qname client" haystack for the client-side text filter.
    search: String,
    /// Pre-rendered one-click action cell (the [`ActionButton`] partial), so
    /// the seed render and the SSE stream emit identical markup.
    action_html: String,
}

impl LogRowView {
    /// Build a row from a live broadcast [`QueryEvent`] (no DB id yet).
    fn from_event(ev: &QueryEvent) -> Self {
        // Display the bare domain; the canonical trailing dot stays internal.
        let qname = ev.qname.to_string().display_domain().to_owned();
        let client = ev.client.ip().to_string();
        Self::build(
            0,
            client,
            qname,
            ev.qtype.to_string(),
            ev.outcome.to_string(),
            ev.outcome.category(),
            ev.outcome.log_action(),
            ev.latency.as_millis() as u64,
        )
    }

    /// Build a row from a persisted [`QueryLogRecord`] (carries its DB id).
    fn from_record(record: &QueryLogRecord) -> Self {
        let qname = record.qname.display_domain().to_owned();
        Self::build(
            record.id,
            record.client.clone(),
            qname,
            record.qtype.clone(),
            record.outcome.to_string(),
            record.outcome.category(),
            record.outcome.log_action(),
            record.latency_ms.max(0) as u64,
        )
    }

    /// Shared constructor for both the live and history row sources.
    #[allow(clippy::too_many_arguments)]
    fn build(
        id: i64,
        client: String,
        qname: String,
        qtype: String,
        outcome_label: String,
        outcome_cat: &'static str,
        action: Option<LogAction>,
        latency_ms: u64,
    ) -> Self {
        let search = format!("{} {}", qname.to_lowercase(), client);
        let action_html = ActionButton::for_outcome(action, qname.clone())
            .render()
            .unwrap_or_default();
        Self {
            id,
            client,
            qname,
            qtype,
            outcome_label,
            outcome_cat,
            latency_ms,
            search,
            action_html,
        }
    }
}

/// Query string for the scroll-back endpoint.
#[derive(Debug, Deserialize)]
pub struct OlderQuery {
    /// Return rows with `id < before` (the smallest currently-visible row id).
    before: i64,
}

/// The one-click action cell for a log row.  The action is fixed by the row's
/// outcome (Block / Unblock / none) and does not change when clicked — the
/// toast confirms the click instead.
#[derive(Template, WebTemplate)]
#[template(path = "log_action.html")]
pub(crate) struct ActionButton {
    /// Button label (`"Block"` / `"Unblock"`); empty string renders a dash.
    label: &'static str,
    /// The endpoint the button posts to.
    endpoint: &'static str,
    /// Extra Pico button class (e.g. `"secondary"`); empty for the primary look.
    class: &'static str,
    /// The (bare) domain the action targets.
    domain: String,
}

impl ActionButton {
    /// Build the action cell for a row's [`LogAction`].
    fn for_outcome(action: Option<LogAction>, domain: String) -> Self {
        let (label, endpoint, class) = match action {
            Some(LogAction::Block) => ("Block", "/log/block", "secondary"),
            Some(LogAction::Unblock) => ("Unblock", "/log/unblock", ""),
            None => ("", "", ""),
        };
        Self {
            label,
            endpoint,
            class,
            domain,
        }
    }
}

/// The query-log page.
#[derive(Template, WebTemplate)]
#[template(path = "log.html")]
struct LogPageTemplate {
    chrome: Chrome,
    rows: Vec<String>,
    /// Smallest row id currently rendered — the scroll-back cursor (0 if empty).
    oldest: i64,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{message::Qtype, name::Name};
    use crate::resolver::pipeline::Outcome;
    use std::time::Duration;

    fn event(domain: &str, outcome: Outcome) -> QueryEvent {
        let client = "192.168.1.5:5000".parse().unwrap();
        let qname: Name = domain.parse().unwrap();
        QueryEvent::new(client, qname, Qtype::A, outcome).with_latency(Duration::from_millis(7))
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
        // A blocked row offers the one-click Unblock action.
        assert!(html.contains("Unblock"));
        assert!(html.contains("/log/unblock?domain=ads.example.com"));
    }

    #[test]
    fn row_action_is_keyed_on_outcome() {
        // Resolved rows (cached/forwarded) offer Block.
        for o in [Outcome::Cached, Outcome::Forwarded] {
            let html = LogRowView::from_event(&event("good.example.com", o))
                .render()
                .unwrap();
            assert!(html.contains("Block"), "{o:?} must offer block");
            assert!(html.contains("/log/block?domain=good.example.com"));
        }

        // Both kinds of blocked row offer Unblock.
        for o in [Outcome::BlockedByAdmin, Outcome::BlockedByBlocklist] {
            let html = LogRowView::from_event(&event("ads.example.com", o))
                .render()
                .unwrap();
            assert!(html.contains("Unblock"), "{o:?} must offer unblock");
            assert!(html.contains("/log/unblock?domain=ads.example.com"));
        }

        // Local / error rows offer no action (rendered as a dash).
        for o in [Outcome::Local, Outcome::LocalNoData, Outcome::Servfail] {
            let html = LogRowView::from_event(&event("x.example.com", o))
                .render()
                .unwrap();
            assert!(!html.contains("Block"), "{o:?} must offer no action");
            assert!(!html.contains("Unblock"), "{o:?} must offer no action");
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
