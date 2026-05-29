//! Blocklist subscription management (SPEC §9, §6).
//!
//! Add / remove / enable-disable blocklist sources (written through to E3.6),
//! and a manual **Refresh now** button that fires the E7.4 on-demand refresh
//! trigger.  Per-source entry counts and last-updated times come from the E3.6
//! metadata.
//!
//! Any change that affects which sources are active (add / remove / toggle)
//! also fires the refresh trigger so the in-memory aggregated set converges to
//! the new configuration.  The refresh runs in the background scheduler; the
//! page reflects updated counts once it completes (reload to see them).  A
//! failing source never clobbers the live set — the scheduler keeps the last
//! good snapshot (E7.4).

use std::time::{SystemTime, UNIX_EPOCH};

use askama::Template;
use askama_web::WebTemplate;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use serde::Deserialize;

use crate::{
    storage::blocklists::{
        BlocklistFormat, BlocklistRepository, NewBlocklist, SqliteBlocklistRepo,
    },
    web::{AppState, Chrome, auth::CurrentUser, dashboard::group, render::WebError},
};

impl AppState {
    async fn render_blocklists(
        &self,
        user: &CurrentUser,
        error: Option<String>,
        notice: Option<String>,
    ) -> Result<BlocklistsPageTemplate, WebError> {
        let now = now_epoch();
        let sources = SqliteBlocklistRepo::new(self.db.pool().clone())
            .list()
            .await?
            .into_iter()
            .map(|b| BlocklistView {
                id: b.id,
                url: b.url,
                format: b.format.as_str(),
                enabled: b.enabled,
                entry_count: group(b.entry_count),
                last_updated: b
                    .last_updated
                    .map_or_else(|| "never".to_owned(), |t| ago(now, t)),
            })
            .collect();
        Ok(BlocklistsPageTemplate {
            chrome: self.chrome("blocklists", user).await,
            sources,
            error,
            notice,
        })
    }

    /// `GET /blocklists`.
    pub async fn blocklists_page(user: CurrentUser, State(state): State<AppState>) -> Response {
        match state.render_blocklists(&user, None, None).await {
            Ok(t) => t.into_response(),
            Err(e) => e.into_response(),
        }
    }

    /// `POST /blocklists/add`.
    pub async fn blocklist_add(
        user: CurrentUser,
        State(state): State<AppState>,
        axum::Form(form): axum::Form<AddBlocklistForm>,
    ) -> Response {
        match state.add_blocklist(&form.url, &form.format).await {
            Ok(()) => Redirect::to("/blocklists").into_response(),
            Err(WebError::BadRequest(msg)) => {
                match state.render_blocklists(&user, Some(msg), None).await {
                    Ok(t) => (StatusCode::BAD_REQUEST, t).into_response(),
                    Err(e) => e.into_response(),
                }
            }
            Err(e) => e.into_response(),
        }
    }

    async fn add_blocklist(&self, url: &str, format: &str) -> Result<(), WebError> {
        let format: BlocklistFormat = format
            .parse()
            .map_err(|_| WebError::bad_request("Format must be hosts or domain-list."))?;
        let url = url.trim();
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            return Err(WebError::bad_request(
                "URL must start with http:// or https://.",
            ));
        }
        SqliteBlocklistRepo::new(self.db.pool().clone())
            .insert(NewBlocklist {
                url: url.to_owned(),
                format,
                enabled: true,
            })
            .await
            .map_err(|e| match e {
                crate::storage::Error::Sqlx(_) => {
                    WebError::bad_request("That URL is already subscribed.")
                }
                other => WebError::from(other),
            })?;
        // Pull the new source into the live set.
        self.refresh.trigger();
        Ok(())
    }

    /// `POST /blocklists/remove`.
    pub async fn blocklist_remove(
        _user: CurrentUser,
        State(state): State<AppState>,
        axum::Form(form): axum::Form<BlocklistIdForm>,
    ) -> Response {
        let res = async {
            SqliteBlocklistRepo::new(state.db.pool().clone())
                .remove(form.id)
                .await?;
            Ok::<(), WebError>(())
        }
        .await;
        match res {
            Ok(()) => {
                // Drop the removed source's domains from the live set.
                state.refresh.trigger();
                Redirect::to("/blocklists").into_response()
            }
            Err(e) => e.into_response(),
        }
    }

    /// `POST /blocklists/toggle`.
    pub async fn blocklist_toggle(
        _user: CurrentUser,
        State(state): State<AppState>,
        axum::Form(form): axum::Form<ToggleBlocklistForm>,
    ) -> Response {
        let res = SqliteBlocklistRepo::new(state.db.pool().clone())
            .set_enabled(form.id, form.enabled)
            .await;
        match res {
            Ok(()) => {
                state.refresh.trigger();
                Redirect::to("/blocklists").into_response()
            }
            Err(e) => WebError::from(e).into_response(),
        }
    }

    /// `POST /blocklists/refresh` — fire an on-demand refresh of all sources.
    pub async fn blocklist_refresh(user: CurrentUser, State(state): State<AppState>) -> Response {
        state.refresh.trigger();
        match state
            .render_blocklists(
                &user,
                None,
                Some(
                    "Refresh started. Entry counts and last-updated will update shortly — reload to see them."
                        .to_owned(),
                ),
            )
            .await
        {
            Ok(t) => t.into_response(),
            Err(e) => e.into_response(),
        }
    }
}

/// Current unix epoch seconds.
fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Render a coarse "… ago" string for a past epoch relative to `now`.
fn ago(now: i64, then: i64) -> String {
    let d = (now - then).max(0);
    if d < 60 {
        format!("{d}s ago")
    } else if d < 3_600 {
        format!("{}m ago", d / 60)
    } else if d < 86_400 {
        format!("{}h ago", d / 3_600)
    } else {
        format!("{}d ago", d / 86_400)
    }
}

/// Add-source form payload.
#[derive(Debug, Deserialize)]
pub struct AddBlocklistForm {
    url: String,
    format: String,
}

/// Form payload carrying just a source id.
#[derive(Debug, Deserialize)]
pub struct BlocklistIdForm {
    id: i64,
}

/// Enable/disable form payload.
#[derive(Debug, Deserialize)]
pub struct ToggleBlocklistForm {
    id: i64,
    enabled: bool,
}

/// One blocklist source row for display.
struct BlocklistView {
    id: i64,
    url: String,
    format: &'static str,
    enabled: bool,
    entry_count: String,
    last_updated: String,
}

/// The blocklist-sources management page.
#[derive(Template, WebTemplate)]
#[template(path = "blocklists.html")]
struct BlocklistsPageTemplate {
    chrome: Chrome,
    sources: Vec<BlocklistView>,
    error: Option<String>,
    notice: Option<String>,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{Db, blocklists::SqliteBlocklistRepo};
    use tempfile::TempDir;

    async fn state() -> (TempDir, AppState) {
        let dir = TempDir::new().unwrap();
        let db = Db::connect(dir.path().join("t.db")).await.unwrap();
        (dir, AppState::for_test(db).await)
    }

    #[test]
    fn ago_formats_coarsely() {
        assert_eq!(ago(1000, 990), "10s ago");
        assert_eq!(ago(10_000, 9_000), "16m ago");
        assert_eq!(ago(100_000, 90_000), "2h ago");
        assert_eq!(ago(1_000_000, 500_000), "5d ago");
        assert_eq!(ago(100, 200), "0s ago"); // clamps negatives
    }

    #[tokio::test]
    async fn add_blocklist_persists() {
        let (_d, st) = state().await;
        st.add_blocklist("https://example.com/hosts.txt", "hosts")
            .await
            .expect("add");
        let all = SqliteBlocklistRepo::new(st.db.pool().clone())
            .list()
            .await
            .unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].url, "https://example.com/hosts.txt");
        assert_eq!(all[0].format, BlocklistFormat::Hosts);
        assert!(all[0].enabled);
    }

    #[tokio::test]
    async fn add_rejects_bad_url_and_format() {
        let (_d, st) = state().await;
        assert!(matches!(
            st.add_blocklist("ftp://x/y", "hosts").await,
            Err(WebError::BadRequest(_))
        ));
        assert!(matches!(
            st.add_blocklist("https://x/y", "adblock").await,
            Err(WebError::BadRequest(_))
        ));
    }

    #[tokio::test]
    async fn duplicate_url_is_bad_request() {
        let (_d, st) = state().await;
        st.add_blocklist("https://dup.example/hosts", "hosts")
            .await
            .expect("first");
        assert!(matches!(
            st.add_blocklist("https://dup.example/hosts", "hosts").await,
            Err(WebError::BadRequest(_))
        ));
    }
}
