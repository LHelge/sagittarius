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

use askama::Template;
use askama_web::WebTemplate;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use serde::Deserialize;

use std::collections::HashMap;

use crate::{
    storage::{
        blocklists::{BlocklistFormat, BlocklistRepository, NewBlocklist},
        query_log::QueryLogRepository,
    },
    time::{self, Clock},
    web::{
        AppState, Chrome,
        auth::CurrentUser,
        dashboard::group,
        render::{WebError, WebResult},
    },
};

/// Effectiveness window: blocks counted over the last 24 hours, matching the
/// dashboard's persisted window.
const EFFECTIVENESS_WINDOW: std::time::Duration = time::days(1);

impl AppState {
    async fn render_blocklists(
        &self,
        user: &CurrentUser,
        error: Option<String>,
        notice: Option<String>,
    ) -> WebResult<BlocklistsPageTemplate> {
        let now = Clock::now_secs();
        let blocklist_sources = self.db.blocklists().list().await?;

        // Windowed per-list block counts for the effectiveness view. On a DB
        // error the figures degrade to zeros rather than failing the page.
        let since = Clock::millis_ago(EFFECTIVENESS_WINDOW);
        let counts = self
            .db
            .query_log()
            .block_counts_by_source_since(since)
            .await
            .unwrap_or_default();

        // Partition counts into live-source attributions and a "removed list"
        // bucket (ids that no longer match a source, plus NULL attributions).
        // total is the denominator for each source's share of blocklist blocks.
        let live_ids: HashMap<i64, ()> = blocklist_sources.iter().map(|b| (b.id, ())).collect();
        let mut by_id: HashMap<i64, i64> = HashMap::new();
        let mut removed_blocks: i64 = 0;
        let mut total_blocks: i64 = 0;
        for (id, n) in counts {
            total_blocks += n;
            match id {
                Some(id) if live_ids.contains_key(&id) => {
                    *by_id.entry(id).or_default() += n;
                }
                _ => removed_blocks += n,
            }
        }

        let mut sources: Vec<BlocklistView> = blocklist_sources
            .into_iter()
            .map(|b| {
                let blocked = by_id.get(&b.id).copied().unwrap_or(0);
                BlocklistView {
                    id: b.id,
                    url: b.url,
                    format: b.format.as_str(),
                    enabled: b.enabled,
                    entry_count: group(b.entry_count),
                    skipped: (b.skipped_count > 0).then(|| group(b.skipped_count)),
                    last_updated: b
                        .last_updated
                        .map_or_else(|| "never".to_owned(), |t| ago(now, t)),
                    blocked: group(blocked.max(0) as u64),
                    share: share_pct(blocked, total_blocks),
                    removed: false,
                }
            })
            .collect();

        // A single synthetic row aggregating blocks credited to lists that have
        // since been removed (or were unattributed). Shown only when non-zero.
        if removed_blocks > 0 {
            sources.push(BlocklistView {
                id: 0,
                url: "removed list".to_owned(),
                format: "—",
                enabled: false,
                entry_count: "—".to_owned(),
                skipped: None,
                last_updated: "—".to_owned(),
                blocked: group(removed_blocks.max(0) as u64),
                share: share_pct(removed_blocks, total_blocks),
                removed: true,
            });
        }

        Ok(BlocklistsPageTemplate {
            chrome: self.chrome("blocklists", user).await,
            sources,
            error,
            notice,
        })
    }

    /// `GET /blocklists`.
    pub async fn blocklists_page(
        user: CurrentUser,
        State(state): State<AppState>,
    ) -> WebResult<Response> {
        Ok(state
            .render_blocklists(&user, None, None)
            .await?
            .into_response())
    }

    /// `POST /blocklists/add`.
    pub async fn blocklist_add(
        user: CurrentUser,
        State(state): State<AppState>,
        axum::Form(form): axum::Form<AddBlocklistForm>,
    ) -> WebResult<Response> {
        match state.add_blocklist(&form.url, &form.format).await {
            Ok(()) => Ok(Redirect::to("/blocklists").into_response()),
            // A validation error re-renders the form with the message and a 400.
            Err(WebError::BadRequest(msg)) => {
                let page = state.render_blocklists(&user, Some(msg), None).await?;
                Ok((StatusCode::BAD_REQUEST, page).into_response())
            }
            Err(e) => Err(e),
        }
    }

    async fn add_blocklist(&self, url: &str, format: &str) -> WebResult<()> {
        let format: BlocklistFormat = format
            .parse()
            .map_err(|_| WebError::bad_request("Format must be hosts, domain-list, or adblock."))?;
        let url = url.trim();
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            return Err(WebError::bad_request(
                "URL must start with http:// or https://.",
            ));
        }
        self.db
            .blocklists()
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
    ) -> WebResult<Response> {
        state.db.blocklists().remove(form.id).await?;
        // Drop the removed source's domains from the live set.
        state.refresh.trigger();
        Ok(Redirect::to("/blocklists").into_response())
    }

    /// `POST /blocklists/toggle`.
    pub async fn blocklist_toggle(
        _user: CurrentUser,
        State(state): State<AppState>,
        axum::Form(form): axum::Form<ToggleBlocklistForm>,
    ) -> WebResult<Response> {
        state
            .db
            .blocklists()
            .set_enabled(form.id, form.enabled)
            .await?;
        state.refresh.trigger();
        Ok(Redirect::to("/blocklists").into_response())
    }

    /// `POST /blocklists/refresh` — fire an on-demand refresh of all sources.
    pub async fn blocklist_refresh(
        user: CurrentUser,
        State(state): State<AppState>,
    ) -> WebResult<Response> {
        state.refresh.trigger();
        Ok(state
            .render_blocklists(
                &user,
                None,
                Some(
                    "Refresh started. Entry counts and last-updated will update shortly — reload to see them."
                        .to_owned(),
                ),
            )
            .await?
            .into_response())
    }
}

/// Render `count`'s share of `total` as a rounded whole-percent string, e.g.
/// `"42%"`. A zero total (no blocklist blocks in the window) renders `"—"`.
fn share_pct(count: i64, total: i64) -> String {
    if total <= 0 {
        return "—".to_owned();
    }
    // Round to nearest whole percent.
    let pct = (count * 100 + total / 2) / total;
    format!("{pct}%")
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
    /// Recognized-but-unsupported rules the parser skipped (E19.4); `None`
    /// hides the indicator (zero skipped, or the "removed list" row).
    skipped: Option<String>,
    /// Windowed block count (last 24h), thousands-grouped.
    blocked: String,
    /// This list's share of all blocklist blocks in the window, e.g. `"42%"`.
    share: String,
    last_updated: String,
    /// `true` for the synthetic "removed list" aggregate row, which carries no
    /// management controls.
    removed: bool,
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
    use tempfile::TempDir;

    async fn state() -> (TempDir, AppState) {
        let (dir, db) = crate::test_support::temp_db().await;
        (dir, AppState::for_test(db).await)
    }

    fn test_user() -> CurrentUser {
        CurrentUser {
            user_id: 1,
            session_id: "sess".to_owned(),
        }
    }

    #[test]
    fn ago_formats_coarsely() {
        assert_eq!(ago(1000, 990), "10s ago");
        assert_eq!(ago(10_000, 9_000), "16m ago");
        assert_eq!(ago(100_000, 90_000), "2h ago");
        assert_eq!(ago(1_000_000, 500_000), "5d ago");
        assert_eq!(ago(100, 200), "0s ago"); // clamps negatives
    }

    #[test]
    fn share_pct_rounds_and_guards_zero_total() {
        assert_eq!(share_pct(2, 4), "50%");
        assert_eq!(share_pct(1, 3), "33%"); // 33.3 → 33
        assert_eq!(share_pct(2, 3), "67%"); // 66.6 → 67
        assert_eq!(share_pct(0, 10), "0%");
        assert_eq!(share_pct(5, 0), "—"); // no blocks → no share
    }

    #[tokio::test]
    async fn add_blocklist_persists() {
        let (_d, st) = state().await;
        st.add_blocklist("https://example.com/hosts.txt", "hosts")
            .await
            .expect("add");
        let all = st.db.blocklists().list().await.unwrap();
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

    // ── Effectiveness view (E11.4) ────────────────────────────────────────────

    /// Insert a blocklist-blocked query_log row attributed to `blocklist_id`.
    async fn seed_block(st: &AppState, qname: &str, blocklist_id: Option<i64>) {
        use crate::{resolver::pipeline::Outcome, storage::query_log::QueryLogRecord};
        st.db
            .query_log()
            .insert_batch(&[QueryLogRecord {
                id: 0,
                ts: Clock::now_millis(),
                client: "10.0.0.1".to_owned(),
                qname: qname.to_owned(),
                qtype: "A".to_owned(),
                outcome: Outcome::BlockedByBlocklist,
                rcode: Some(0),
                upstream: None,
                latency_ms: 1,
                blocklist_id,
            }])
            .await
            .expect("seed block row");
    }

    #[tokio::test]
    async fn effectiveness_renders_per_list_counts_and_share() {
        let (_d, st) = state().await;
        let repo = st.db.blocklists();
        let a = repo
            .insert(NewBlocklist {
                url: "https://a.example/hosts".to_owned(),
                format: BlocklistFormat::Hosts,
                enabled: true,
            })
            .await
            .expect("insert a");
        let b = repo
            .insert(NewBlocklist {
                url: "https://b.example/hosts".to_owned(),
                format: BlocklistFormat::Hosts,
                enabled: true,
            })
            .await
            .expect("insert b");

        // a blocked 2, b blocked 1 → total 3.
        seed_block(&st, "x.test.", Some(a.id)).await;
        seed_block(&st, "y.test.", Some(a.id)).await;
        seed_block(&st, "z.test.", Some(b.id)).await;

        let html = st
            .render_blocklists(&test_user(), None, None)
            .await
            .expect("render")
            .render()
            .expect("template");

        // Both lists appear with their windowed counts and rounded shares.
        assert!(html.contains("https://a.example/hosts"));
        assert!(html.contains("https://b.example/hosts"));
        assert!(html.contains("67%"), "a's share (2/3) must render");
        assert!(html.contains("33%"), "b's share (1/3) must render");
        assert!(
            !html.contains("removed list"),
            "no removed-list row when all blocks map to live sources"
        );
    }

    #[tokio::test]
    async fn effectiveness_unknown_ids_render_as_removed_list() {
        let (_d, st) = state().await;
        let a = st
            .db
            .blocklists()
            .insert(NewBlocklist {
                url: "https://a.example/hosts".to_owned(),
                format: BlocklistFormat::Hosts,
                enabled: true,
            })
            .await
            .expect("insert a");

        // One block for the live list, one for a stale id, one unattributed.
        seed_block(&st, "x.test.", Some(a.id)).await;
        seed_block(&st, "ghost.test.", Some(99_999)).await; // no such source
        seed_block(&st, "null.test.", None).await;

        let html = st
            .render_blocklists(&test_user(), None, None)
            .await
            .expect("render")
            .render()
            .expect("template");

        assert!(
            html.contains("removed list"),
            "blocks for stale/None ids must surface as a removed-list row"
        );
    }

    #[tokio::test]
    async fn effectiveness_empty_log_renders_zeros_without_panic() {
        let (_d, st) = state().await;
        st.db
            .blocklists()
            .insert(NewBlocklist {
                url: "https://a.example/hosts".to_owned(),
                format: BlocklistFormat::Hosts,
                enabled: true,
            })
            .await
            .expect("insert");

        let html = st
            .render_blocklists(&test_user(), None, None)
            .await
            .expect("render")
            .render()
            .expect("template");

        // Zero blocks → "0" count and an em-dash share, no panic.
        assert!(html.contains("https://a.example/hosts"));
        assert!(html.contains("—"), "zero-total share renders as em-dash");
        assert!(!html.contains("removed list"));
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
