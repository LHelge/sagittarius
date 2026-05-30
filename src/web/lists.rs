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

use askama::Template;
use askama_web::WebTemplate;
use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response, Sse, sse::Event},
};
use datastar::prelude::PatchElements;
use serde::Deserialize;

use crate::{
    storage::lists::{
        AllowlistRepository, BlacklistRepository, SqliteAllowlistRepo, SqliteBlacklistRepo,
    },
    web::{
        AppState,
        auth::CurrentUser,
        live_log::ActionButton,
        render::{DomainDisplay, WebError},
    },
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

    /// Remove `domain` from the admin blacklist (write-through, then swap).
    pub(crate) async fn remove_from_blacklist(&self, domain: &str) -> Result<(), WebError> {
        SqliteBlacklistRepo::new(self.db.pool().clone())
            .remove(domain)
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

    /// Remove `domain` from the allowlist (write-through, then swap).
    pub(crate) async fn remove_from_allowlist(&self, domain: &str) -> Result<(), WebError> {
        SqliteAllowlistRepo::new(self.db.pool().clone())
            .remove(domain)
            .await?;
        self.reload_allowlist().await
    }

    // ── One-click handlers (from the live log) ────────────────────────────────

    /// `POST /log/whitelist?domain=…&row=…` — allowlist a blocklist-blocked domain.
    pub async fn log_whitelist(
        _user: CurrentUser,
        State(state): State<AppState>,
        Query(q): Query<ActionQuery>,
    ) -> Response {
        match state.add_to_allowlist(&q.domain).await {
            Ok(()) => action_sse(
                "allow",
                true,
                &q,
                format!(
                    "Added {} to the allowlist — it resolves on the next query.",
                    q.domain.display_domain()
                ),
            ),
            Err(e) => e.into_response(),
        }
    }

    /// `POST /log/unwhitelist?domain=…&row=…` — remove a domain from the allowlist.
    pub async fn log_unwhitelist(
        _user: CurrentUser,
        State(state): State<AppState>,
        Query(q): Query<ActionQuery>,
    ) -> Response {
        match state.remove_from_allowlist(&q.domain).await {
            Ok(()) => action_sse(
                "allow",
                false,
                &q,
                format!("Removed {} from the allowlist.", q.domain.display_domain()),
            ),
            Err(e) => e.into_response(),
        }
    }

    /// `POST /log/blacklist?domain=…&row=…` — blacklist a resolved domain.
    pub async fn log_blacklist(
        _user: CurrentUser,
        State(state): State<AppState>,
        Query(q): Query<ActionQuery>,
    ) -> Response {
        match state.add_to_blacklist(&q.domain).await {
            Ok(()) => action_sse(
                "deny",
                true,
                &q,
                format!(
                    "Added {} to the blacklist — it is blocked on the next query.",
                    q.domain.display_domain()
                ),
            ),
            Err(e) => e.into_response(),
        }
    }

    /// `POST /log/unblacklist?domain=…&row=…` — remove a domain from the blacklist.
    pub async fn log_unblacklist(
        _user: CurrentUser,
        State(state): State<AppState>,
        Query(q): Query<ActionQuery>,
    ) -> Response {
        match state.remove_from_blacklist(&q.domain).await {
            Ok(()) => action_sse(
                "deny",
                false,
                &q,
                format!("Removed {} from the blacklist.", q.domain.display_domain()),
            ),
            Err(e) => e.into_response(),
        }
    }
}

// ── Management screens (E8.8) ─────────────────────────────────────────────────

/// Which explicit list a management page operates on.
#[derive(Debug, Clone, Copy)]
enum ListKind {
    Blacklist,
    Allowlist,
}

impl ListKind {
    fn title(self) -> &'static str {
        match self {
            Self::Blacklist => "Blacklist",
            Self::Allowlist => "Allowlist",
        }
    }
    fn active(self) -> &'static str {
        match self {
            Self::Blacklist => "blacklist",
            Self::Allowlist => "allowlist",
        }
    }
    fn base_path(self) -> &'static str {
        match self {
            Self::Blacklist => "/blacklist",
            Self::Allowlist => "/allowlist",
        }
    }
    fn description(self) -> &'static str {
        match self {
            Self::Blacklist => {
                "Domains you explicitly block. Highest precedence — wins over the allowlist and blocklists."
            }
            Self::Allowlist => {
                "Domains you explicitly allow. An exception that suppresses blocklist matches (but not the blacklist)."
            }
        }
    }
}

impl AppState {
    async fn list_entries(&self, kind: ListKind) -> Result<Vec<String>, WebError> {
        let entries = match kind {
            ListKind::Blacklist => {
                SqliteBlacklistRepo::new(self.db.pool().clone())
                    .list()
                    .await?
            }
            ListKind::Allowlist => {
                SqliteAllowlistRepo::new(self.db.pool().clone())
                    .list()
                    .await?
            }
        };
        // Show (and round-trip on remove) the bare domain; the stored value keeps
        // its canonical trailing dot.
        Ok(entries
            .into_iter()
            .map(|e| e.domain.display_domain().to_owned())
            .collect())
    }

    async fn list_add(&self, kind: ListKind, domain: &str) -> Result<(), WebError> {
        match kind {
            ListKind::Blacklist => self.add_to_blacklist(domain).await,
            ListKind::Allowlist => self.add_to_allowlist(domain).await,
        }
    }

    async fn list_remove(&self, kind: ListKind, domain: &str) -> Result<(), WebError> {
        match kind {
            ListKind::Blacklist => self.remove_from_blacklist(domain).await,
            ListKind::Allowlist => self.remove_from_allowlist(domain).await,
        }
    }

    /// Render a list management page, optionally with an inline error banner.
    async fn render_list(
        &self,
        user: &CurrentUser,
        kind: ListKind,
        error: Option<String>,
    ) -> Result<ListPageTemplate, WebError> {
        Ok(ListPageTemplate {
            chrome: self.chrome(kind.active(), user).await,
            title: kind.title(),
            description: kind.description(),
            base_path: kind.base_path(),
            entries: self.list_entries(kind).await?,
            error,
        })
    }

    /// Shared GET handler body for a list page.
    async fn list_page(&self, user: &CurrentUser, kind: ListKind) -> Response {
        match self.render_list(user, kind, None).await {
            Ok(t) => t.into_response(),
            Err(e) => e.into_response(),
        }
    }

    /// Shared POST-add body: write through, then PRG-redirect on success or
    /// re-render with an inline error on a bad domain.
    async fn list_add_handler(&self, user: &CurrentUser, kind: ListKind, domain: &str) -> Response {
        match self.list_add(kind, domain).await {
            Ok(()) => Redirect::to(kind.base_path()).into_response(),
            Err(WebError::BadRequest(msg)) => match self.render_list(user, kind, Some(msg)).await {
                Ok(t) => (axum::http::StatusCode::BAD_REQUEST, t).into_response(),
                Err(e) => e.into_response(),
            },
            Err(e) => e.into_response(),
        }
    }

    /// Shared POST-remove body: write through, then PRG-redirect.
    async fn list_remove_handler(&self, kind: ListKind, domain: &str) -> Response {
        match self.list_remove(kind, domain).await {
            Ok(()) => Redirect::to(kind.base_path()).into_response(),
            Err(e) => e.into_response(),
        }
    }

    /// `GET /blacklist`.
    pub async fn blacklist_page(user: CurrentUser, State(state): State<AppState>) -> Response {
        state.list_page(&user, ListKind::Blacklist).await
    }
    /// `POST /blacklist/add`.
    pub async fn blacklist_add(
        user: CurrentUser,
        State(state): State<AppState>,
        axum::Form(form): axum::Form<DomainForm>,
    ) -> Response {
        state
            .list_add_handler(&user, ListKind::Blacklist, &form.domain)
            .await
    }
    /// `POST /blacklist/remove`.
    pub async fn blacklist_remove(
        _user: CurrentUser,
        State(state): State<AppState>,
        axum::Form(form): axum::Form<DomainForm>,
    ) -> Response {
        state
            .list_remove_handler(ListKind::Blacklist, &form.domain)
            .await
    }
    /// `GET /allowlist`.
    pub async fn allowlist_page(user: CurrentUser, State(state): State<AppState>) -> Response {
        state.list_page(&user, ListKind::Allowlist).await
    }
    /// `POST /allowlist/add`.
    pub async fn allowlist_add(
        user: CurrentUser,
        State(state): State<AppState>,
        axum::Form(form): axum::Form<DomainForm>,
    ) -> Response {
        state
            .list_add_handler(&user, ListKind::Allowlist, &form.domain)
            .await
    }
    /// `POST /allowlist/remove`.
    pub async fn allowlist_remove(
        _user: CurrentUser,
        State(state): State<AppState>,
        axum::Form(form): axum::Form<DomainForm>,
    ) -> Response {
        state
            .list_remove_handler(ListKind::Allowlist, &form.domain)
            .await
    }
}

/// `domain` form field (the `csrf_token` field is consumed by the CSRF layer
/// and ignored here).
#[derive(Debug, Deserialize)]
pub struct DomainForm {
    pub domain: String,
}

/// Shared management page for the blacklist and allowlist.
#[derive(Template, WebTemplate)]
#[template(path = "list_page.html")]
struct ListPageTemplate {
    chrome: crate::web::Chrome,
    title: &'static str,
    description: &'static str,
    base_path: &'static str,
    entries: Vec<String>,
    error: Option<String>,
}

/// Query parameters for the one-click actions: the target `domain` and the
/// optional originating row id (so the clicked button can be toggled in place).
#[derive(Debug, Deserialize)]
pub struct ActionQuery {
    pub domain: String,
    pub row: Option<u64>,
}

/// Build the one-shot Datastar SSE response for a one-click list action:
/// morph the originating row's button to its toggled state (when a `row` id is
/// present) and show a `#sgt-toast` confirmation.
fn action_sse(kind: &'static str, added: bool, q: &ActionQuery, message: String) -> Response {
    let mut events: Vec<Event> = Vec::new();

    if let Some(row_id) = q.row {
        let button = ActionButton {
            kind,
            added,
            domain: q.domain.clone(),
            row_id,
        }
        .render()
        .unwrap_or_default();
        events.push(PatchElements::new(button).write_as_axum_sse_event());
    }

    let toast = format!(
        r#"<div id="sgt-toast" class="sgt-toast sgt-notice--ok" role="status">{}</div>"#,
        crate::web::render::html_escape(&message)
    );
    events.push(PatchElements::new(toast).write_as_axum_sse_event());

    Sse::new(async_stream::stream! {
        for event in events {
            yield Ok::<Event, Infallible>(event);
        }
    })
    .into_response()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{codec::name::Name, storage::Db};
    use tempfile::TempDir;

    async fn state() -> (TempDir, AppState) {
        let dir = TempDir::new().unwrap();
        let db = Db::connect(dir.path().join("t.db")).await.unwrap();
        let st = AppState::for_test(db).await;
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
