//! Manual + one-click blacklist / allowlist management (SPEC §9, §5).
//!
//! This module owns the **write-through + snapshot-swap** pattern reused by all
//! list mutations: a change is persisted to SQLite (E3.5) first, then the
//! affected in-memory [`MatchSet`](crate::resolver::matchset::MatchSet) snapshot
//! is rebuilt from the database and atomically swapped into the shared
//! [`ResolverState`](crate::resolver::state::ResolverState) (E4.4), so the
//! change takes effect on the very next query.
//!
//! The **one-click** actions from the live query log are keyed purely on each
//! row's [`Outcome`](crate::resolver::pipeline::Outcome) (not on the domain's
//! current list membership):
//! - a resolved row (cached/forwarded) offers *Block* (add to the admin
//!   blacklist),
//! - a blocked row offers *Unblock* — [`AppState::unblock`] removes it from the
//!   admin blacklist if present, otherwise allowlists it to suppress a blocklist
//!   hit,
//! - every other outcome (local answers, errors) renders no action.
//!
//! The full management screens (add/remove/list pages) build on the same core
//! helpers in E8.8.

use askama::Template;
use askama_web::WebTemplate;
use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
};
use datastar::prelude::PatchElements;
use serde::Deserialize;

use crate::{
    codec::name::Name,
    storage::lists::{AllowlistRepository, BlacklistRepository},
    web::{
        AppState,
        auth::CurrentUser,
        render::{DomainDisplay, WebError, datastar_response},
    },
};

impl AppState {
    // ── Write-through + snapshot-swap core ────────────────────────────────────

    /// Rebuild the in-memory admin blacklist snapshot from the database.
    async fn reload_blacklist(&self) -> Result<(), WebError> {
        let names = self.db.blacklist().load_all().await?;
        self.resolver.blacklist().store(names.into_iter().collect());
        Ok(())
    }

    /// Rebuild the in-memory allowlist snapshot from the database.
    async fn reload_allowlist(&self) -> Result<(), WebError> {
        let names = self.db.allowlist().load_all().await?;
        self.resolver.allowlist().store(names.into_iter().collect());
        Ok(())
    }

    /// Add `domain` to the admin blacklist (write-through, then swap).
    pub(crate) async fn add_to_blacklist(&self, domain: &str) -> Result<(), WebError> {
        self.db.blacklist().add(domain).await?;
        self.reload_blacklist().await
    }

    /// Remove `domain` from the admin blacklist (write-through, then swap).
    pub(crate) async fn remove_from_blacklist(&self, domain: &str) -> Result<(), WebError> {
        self.db.blacklist().remove(domain).await?;
        self.reload_blacklist().await
    }

    /// Add `domain` to the allowlist (write-through, then swap).
    pub(crate) async fn add_to_allowlist(&self, domain: &str) -> Result<(), WebError> {
        self.db.allowlist().add(domain).await?;
        self.reload_allowlist().await
    }

    /// Remove `domain` from the allowlist (write-through, then swap).
    pub(crate) async fn remove_from_allowlist(&self, domain: &str) -> Result<(), WebError> {
        self.db.allowlist().remove(domain).await?;
        self.reload_allowlist().await
    }

    /// Make `domain` resolve again.
    ///
    /// If it sits on the admin blacklist we remove it; otherwise it was blocked
    /// by an aggregated blocklist, which the allowlist suppresses.  This keeps a
    /// single Unblock action correct for both kinds of block.
    pub(crate) async fn unblock(&self, domain: &str) -> Result<(), WebError> {
        let on_blacklist = domain
            .parse::<Name>()
            .is_ok_and(|n| self.resolver.blacklist().contains(&n));
        if on_blacklist {
            self.remove_from_blacklist(domain).await
        } else {
            self.add_to_allowlist(domain).await
        }
    }

    // ── One-click handlers (from the live log) ────────────────────────────────

    /// `POST /log/block?domain=…` — block a currently-resolving domain by adding
    /// it to the admin blacklist.
    pub async fn log_block(
        _user: CurrentUser,
        State(state): State<AppState>,
        Query(q): Query<ActionQuery>,
    ) -> Result<Response, WebError> {
        state.add_to_blacklist(&q.domain).await?;
        Ok(toast(format!(
            "Blocked {} — it is blocked on the next query.",
            q.domain.display_domain()
        )))
    }

    /// `POST /log/unblock?domain=…` — make a blocked domain resolve again.
    ///
    /// If the domain sits on the admin blacklist we remove it; otherwise it was
    /// blocked by an aggregated blocklist, which the allowlist suppresses.  This
    /// keeps a single Unblock action correct for both kinds of block.
    pub async fn log_unblock(
        _user: CurrentUser,
        State(state): State<AppState>,
        Query(q): Query<ActionQuery>,
    ) -> Result<Response, WebError> {
        state.unblock(&q.domain).await?;
        Ok(toast(format!(
            "Unblocked {} — it resolves on the next query.",
            q.domain.display_domain()
        )))
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
            ListKind::Blacklist => self.db.blacklist().list().await?,
            ListKind::Allowlist => self.db.allowlist().list().await?,
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
    async fn list_page(&self, user: &CurrentUser, kind: ListKind) -> Result<Response, WebError> {
        Ok(self.render_list(user, kind, None).await?.into_response())
    }

    /// Shared POST-add body: write through, then PRG-redirect on success or
    /// re-render with an inline error on a bad domain.
    async fn list_add_handler(
        &self,
        user: &CurrentUser,
        kind: ListKind,
        domain: &str,
    ) -> Result<Response, WebError> {
        match self.list_add(kind, domain).await {
            Ok(()) => Ok(Redirect::to(kind.base_path()).into_response()),
            // A bad domain re-renders the page with the message and a 400.
            Err(WebError::BadRequest(msg)) => {
                let page = self.render_list(user, kind, Some(msg)).await?;
                Ok((axum::http::StatusCode::BAD_REQUEST, page).into_response())
            }
            Err(e) => Err(e),
        }
    }

    /// Shared POST-remove body: write through, then PRG-redirect.
    async fn list_remove_handler(
        &self,
        kind: ListKind,
        domain: &str,
    ) -> Result<Response, WebError> {
        self.list_remove(kind, domain).await?;
        Ok(Redirect::to(kind.base_path()).into_response())
    }

    /// `GET /blacklist`.
    pub async fn blacklist_page(
        user: CurrentUser,
        State(state): State<AppState>,
    ) -> Result<Response, WebError> {
        state.list_page(&user, ListKind::Blacklist).await
    }
    /// `POST /blacklist/add`.
    pub async fn blacklist_add(
        user: CurrentUser,
        State(state): State<AppState>,
        axum::Form(form): axum::Form<DomainForm>,
    ) -> Result<Response, WebError> {
        state
            .list_add_handler(&user, ListKind::Blacklist, &form.domain)
            .await
    }
    /// `POST /blacklist/remove`.
    pub async fn blacklist_remove(
        _user: CurrentUser,
        State(state): State<AppState>,
        axum::Form(form): axum::Form<DomainForm>,
    ) -> Result<Response, WebError> {
        state
            .list_remove_handler(ListKind::Blacklist, &form.domain)
            .await
    }
    /// `GET /allowlist`.
    pub async fn allowlist_page(
        user: CurrentUser,
        State(state): State<AppState>,
    ) -> Result<Response, WebError> {
        state.list_page(&user, ListKind::Allowlist).await
    }
    /// `POST /allowlist/add`.
    pub async fn allowlist_add(
        user: CurrentUser,
        State(state): State<AppState>,
        axum::Form(form): axum::Form<DomainForm>,
    ) -> Result<Response, WebError> {
        state
            .list_add_handler(&user, ListKind::Allowlist, &form.domain)
            .await
    }
    /// `POST /allowlist/remove`.
    pub async fn allowlist_remove(
        _user: CurrentUser,
        State(state): State<AppState>,
        axum::Form(form): axum::Form<DomainForm>,
    ) -> Result<Response, WebError> {
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

/// Query parameters for the one-click log actions: just the target `domain`.
#[derive(Debug, Deserialize)]
pub struct ActionQuery {
    pub domain: String,
}

/// Build the one-shot Datastar SSE response confirming a one-click action by
/// patching the `#sgt-toast` notice.  The button itself is not touched — its
/// action is fixed by the row's outcome, and the toast is the click feedback.
fn toast(message: String) -> Response {
    let html = format!(
        r#"<div id="sgt-toast" class="sgt-toast sgt-notice--ok" role="status">{}</div>"#,
        crate::web::render::html_escape(&message)
    );
    datastar_response(vec![PatchElements::new(html).write_as_axum_sse_event()])
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
        let names = st.db.blacklist().load_all().await.unwrap();
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

    #[tokio::test]
    async fn unblock_removes_an_admin_blacklisted_domain() {
        let (_d, st) = state().await;
        st.add_to_blacklist("ads.example.com").await.expect("add");
        assert!(st.resolver.blacklist().contains(&name("ads.example.com")));

        st.unblock("ads.example.com").await.expect("unblock");

        // Removed from the blacklist; not shunted onto the allowlist.
        assert!(!st.resolver.blacklist().contains(&name("ads.example.com")));
        assert!(!st.resolver.allowlist().contains(&name("ads.example.com")));
    }

    #[tokio::test]
    async fn unblock_allowlists_a_blocklist_blocked_domain() {
        let (_d, st) = state().await;
        // Not on the admin blacklist → unblock suppresses the blocklist hit via
        // the allowlist.
        st.unblock("tracker.example.com").await.expect("unblock");
        assert!(
            st.resolver
                .allowlist()
                .contains(&name("tracker.example.com"))
        );
    }
}
