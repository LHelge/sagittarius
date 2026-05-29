//! Manual + one-click blacklist / allowlist management (SPEC §9, §5).
//!
//! This module owns the **write-through + snapshot-swap** pattern reused by all
//! list mutations: a change is persisted to SQLite (E3.5) first, then the
//! affected in-memory [`MatchSet`](crate::resolver::matchset::MatchSet) snapshot
//! is rebuilt from the database and atomically swapped into the shared
//! [`ResolverState`](crate::resolver::state::ResolverState) (E4.4), so the
//! change takes effect on the very next query.
//!
//! E8.7 wires the **one-click** actions from the live query log:
//! - a blocklist-blocked row offers *Whitelist* (add to the allowlist),
//! - a forwarded/cached resolved row offers *Blacklist* (add to the admin
//!   blacklist).
//!
//! Rows whose outcome would make the action ineffective (admin-blacklist blocks,
//! local answers) do not render an action — see
//! [`Outcome`](crate::resolver::pipeline::Outcome).
//!
//! The full management screens (add/remove/list pages) build on the same core
//! helpers in E8.8.

use std::convert::Infallible;

use axum::{
    extract::{Query, State},
    response::{IntoResponse, Response, Sse, sse::Event},
};
use datastar::prelude::PatchElements;
use serde::Deserialize;

use crate::{
    storage::lists::{
        AllowlistRepository, BlacklistRepository, SqliteAllowlistRepo, SqliteBlacklistRepo,
    },
    web::{AppState, auth::CurrentUser, render::WebError},
};

impl AppState {
    // ── Write-through + snapshot-swap core ────────────────────────────────────

    /// Rebuild the in-memory admin blacklist snapshot from the database.
    async fn reload_blacklist(&self) -> Result<(), WebError> {
        let names = SqliteBlacklistRepo::new(self.db.pool().clone())
            .load_all()
            .await?;
        self.resolver.blacklist().store(names.into_iter().collect());
        Ok(())
    }

    /// Rebuild the in-memory allowlist snapshot from the database.
    async fn reload_allowlist(&self) -> Result<(), WebError> {
        let names = SqliteAllowlistRepo::new(self.db.pool().clone())
            .load_all()
            .await?;
        self.resolver.allowlist().store(names.into_iter().collect());
        Ok(())
    }

    /// Add `domain` to the admin blacklist (write-through, then swap).
    pub(crate) async fn add_to_blacklist(&self, domain: &str) -> Result<(), WebError> {
        SqliteBlacklistRepo::new(self.db.pool().clone())
            .add(domain)
            .await?;
        self.reload_blacklist().await
    }

    /// Add `domain` to the allowlist (write-through, then swap).
    pub(crate) async fn add_to_allowlist(&self, domain: &str) -> Result<(), WebError> {
        SqliteAllowlistRepo::new(self.db.pool().clone())
            .add(domain)
            .await?;
        self.reload_allowlist().await
    }

    // ── One-click handlers (from the live log) ────────────────────────────────

    /// `POST /log/whitelist?domain=…` — allowlist a blocklist-blocked domain.
    pub async fn log_whitelist(
        _user: CurrentUser,
        State(state): State<AppState>,
        Query(q): Query<DomainQuery>,
    ) -> Response {
        match state.add_to_allowlist(&q.domain).await {
            Ok(()) => toast(format!(
                "Added {} to the allowlist — it will resolve on the next query.",
                q.domain
            )),
            Err(e) => e.into_response(),
        }
    }

    /// `POST /log/blacklist?domain=…` — blacklist a resolved domain.
    pub async fn log_blacklist(
        _user: CurrentUser,
        State(state): State<AppState>,
        Query(q): Query<DomainQuery>,
    ) -> Response {
        match state.add_to_blacklist(&q.domain).await {
            Ok(()) => toast(format!(
                "Added {} to the blacklist — it will be blocked on the next query.",
                q.domain
            )),
            Err(e) => e.into_response(),
        }
    }
}

/// `?domain=` query parameter for the one-click actions.
#[derive(Debug, Deserialize)]
pub struct DomainQuery {
    pub domain: String,
}

/// Build a one-shot Datastar SSE response that morphs the `#sgt-toast` element
/// with a success message.
fn toast(message: String) -> Response {
    let html = format!(
        r#"<div id="sgt-toast" class="sgt-toast sgt-notice--ok" role="status">{}</div>"#,
        crate::web::render::html_escape(&message)
    );
    let event = PatchElements::new(html).write_as_axum_sse_event();
    Sse::new(async_stream::stream! { yield Ok::<Event, Infallible>(event); }).into_response()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{codec::name::Name, storage::Db, telemetry::TelemetrySink};
    use std::sync::Arc;
    use tempfile::TempDir;

    async fn state() -> (TempDir, AppState) {
        let dir = TempDir::new().unwrap();
        let db = Db::connect(dir.path().join("t.db")).await.unwrap();
        let resolver = crate::resolver::state::ResolverState::hydrate(&db)
            .await
            .unwrap();
        let telemetry = Arc::new(TelemetrySink::new(
            Arc::new(crate::telemetry::LiveLog::default()),
            Arc::new(crate::telemetry::Stats::new()),
        ));
        let scheduler = crate::blocklist::scheduler::BlocklistScheduler::new(
            crate::storage::blocklists::SqliteBlocklistRepo::new(db.pool().clone()),
            Arc::clone(&resolver),
            crate::blocklist::fetch::Fetcher::new(),
        );
        let st = AppState {
            db,
            resolver,
            telemetry,
            refresh: scheduler.trigger(),
            cookie_policy: crate::config::SessionCookieSecurePolicy::Never,
            csrf_key: crate::web::random_csrf_key(),
            setup_done: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        };
        (dir, st)
    }

    fn name(s: &str) -> Name {
        s.parse().unwrap()
    }

    #[tokio::test]
    async fn add_to_blacklist_writes_through_and_swaps() {
        let (_d, st) = state().await;
        assert!(!st.resolver.blacklist().contains(&name("ads.example.com")));

        st.add_to_blacklist("ads.example.com").await.expect("add");

        // In-memory set updated immediately ...
        assert!(st.resolver.blacklist().contains(&name("ads.example.com")));
        // ... and persisted.
        let names = SqliteBlacklistRepo::new(st.db.pool().clone())
            .load_all()
            .await
            .unwrap();
        assert!(names.contains(&name("ads.example.com")));
    }

    #[tokio::test]
    async fn add_to_allowlist_writes_through_and_swaps() {
        let (_d, st) = state().await;
        st.add_to_allowlist("safe.example.com").await.expect("add");
        assert!(st.resolver.allowlist().contains(&name("safe.example.com")));
    }

    #[tokio::test]
    async fn invalid_domain_is_bad_request() {
        let (_d, st) = state().await;
        let err = st.add_to_blacklist("not..valid").await.unwrap_err();
        assert!(matches!(err, WebError::BadRequest(_)));
    }
}
