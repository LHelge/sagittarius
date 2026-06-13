//! Global settings management (SPEC §9, §7, §4).
//!
//! Edits the typed `settings` row (cache bounds, blocking mode + custom sinkhole
//! IPs, blocklist refresh interval, UI theme), writes through to E3.4, and then
//! updates the live [`RuntimeSettings`] snapshot so changes apply where the
//! subsystem supports it:
//!
//! - **min/max TTL, negative-TTL cap, blocking mode/custom IP** apply
//!   immediately (read from the snapshot at synthesis / cache-store time).
//! - **blocklist refresh interval** is re-read by the scheduler at the next
//!   cycle boundary (E7.4).
//! - **cache capacity** is fixed when the moka cache is built, so a change is
//!   persisted but only takes effect after a restart — surfaced in the UI.
//!
//! The session-cookie `Secure` policy is intentionally **not** here: it is an
//! operational CLI/env setting (E1.2) because it depends on deployment topology.

use std::net::{Ipv4Addr, Ipv6Addr};

use askama::Template;
use askama_web::WebTemplate;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode, Uri, header},
    response::{IntoResponse, Redirect, Response},
};
use serde::Deserialize;

use crate::{
    resolver::state::RuntimeSettings,
    storage::{
        query_log::QueryLogRepository,
        settings::{BlockingMode, SelectionStrategy, Settings, SettingsRepository},
    },
    web::{
        AppState, Chrome,
        auth::CurrentUser,
        render::{WebError, WebResult},
    },
};

impl AppState {
    async fn render_settings(
        &self,
        user: &CurrentUser,
        error: Option<String>,
        notice: Option<String>,
    ) -> WebResult<SettingsPageTemplate> {
        let s = self.db.settings().get().await?;
        Ok(SettingsPageTemplate {
            chrome: self.chrome("settings", user).await,
            cache_min_ttl: s.cache_min_ttl,
            cache_max_ttl: s.cache_max_ttl,
            cache_negative_ttl_cap: s.cache_negative_ttl_cap,
            cache_capacity: s.cache_capacity,
            blocking_mode: s.blocking_mode.as_str(),
            custom_block_ipv4: s
                .custom_block_ipv4
                .map(|i| i.to_string())
                .unwrap_or_default(),
            custom_block_ipv6: s
                .custom_block_ipv6
                .map(|i| i.to_string())
                .unwrap_or_default(),
            blocklist_refresh_interval: s.blocklist_refresh_interval,
            query_log_enabled: s.query_log_enabled,
            query_log_retention_days: s.query_log_retention_days,
            upstream_selection_strategy: s.upstream_selection_strategy.as_str(),
            upstream_parallel_fanout: s.upstream_parallel_fanout,
            error,
            notice,
        })
    }

    /// `GET /settings`.
    pub async fn settings_page(
        user: CurrentUser,
        State(state): State<AppState>,
    ) -> WebResult<Response> {
        Ok(state
            .render_settings(&user, None, None)
            .await?
            .into_response())
    }

    /// `POST /settings`.
    pub async fn settings_save(
        user: CurrentUser,
        State(state): State<AppState>,
        axum::Form(form): axum::Form<SettingsForm>,
    ) -> WebResult<Response> {
        match state.apply_settings(form).await {
            Ok(()) => Ok(state
                .render_settings(&user, None, Some("Settings saved.".to_owned()))
                .await?
                .into_response()),
            // A validation error re-renders the form with the message and a 400.
            Err(WebError::BadRequest(msg)) => {
                let page = state.render_settings(&user, Some(msg), None).await?;
                Ok((StatusCode::BAD_REQUEST, page).into_response())
            }
            Err(e) => Err(e),
        }
    }

    /// `POST /theme/toggle` — flip the UI theme from the topbar sun/moon button.
    ///
    /// Theme is a persisted UI-only setting (read fresh into the page chrome on
    /// every render). This flips it — anything not already `dark` becomes
    /// `dark`, so the initial `auto` resolves to an explicit choice on first
    /// click — and redirects (PRG) back to the page the toggle was clicked on.
    pub async fn theme_toggle(
        _user: CurrentUser,
        State(state): State<AppState>,
        headers: HeaderMap,
    ) -> WebResult<Response> {
        let mut settings = state.db.settings().get().await?;
        settings.ui_theme = if settings.ui_theme == "dark" {
            "light".to_owned()
        } else {
            "dark".to_owned()
        };
        state.db.settings().update(&settings).await?;

        // Return to the originating page; take only the same-origin path from
        // the Referer (never the full URL) so this can't become an open redirect.
        let back = headers
            .get(header::REFERER)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<Uri>().ok())
            .and_then(|u| u.path_and_query().map(|pq| pq.as_str().to_owned()))
            .unwrap_or_else(|| "/".to_owned());
        Ok(Redirect::to(&back).into_response())
    }

    /// `POST /settings/clear-log` — delete all persisted query-log history.
    pub async fn settings_clear_log(
        user: CurrentUser,
        State(state): State<AppState>,
    ) -> WebResult<Response> {
        state.db.query_log().clear_all().await?;
        Ok(state
            .render_settings(&user, None, Some("Query log cleared.".to_owned()))
            .await?
            .into_response())
    }

    /// Validate and persist a settings form, then refresh the live snapshot.
    async fn apply_settings(&self, form: SettingsForm) -> WebResult<()> {
        // The theme is owned by the topbar toggle, not this form; preserve the
        // stored value across an otherwise-unrelated settings save.
        let ui_theme = self.db.settings().get().await?.ui_theme;
        let settings = form.into_settings(ui_theme)?;
        self.db.settings().update(&settings).await?;
        // Apply to the live snapshot (capacity needs a restart; see module doc).
        self.resolver
            .store_settings(RuntimeSettings::from(&settings));
        // The selection strategy / fan-out is read when (re)building the pool,
        // so rebuild it now to apply the change immediately (E15.5).
        self.rebuild_upstream_pool().await?;
        Ok(())
    }
}

/// Settings form payload.
#[derive(Debug, Deserialize)]
pub struct SettingsForm {
    cache_min_ttl: u32,
    cache_max_ttl: u32,
    cache_negative_ttl_cap: u32,
    cache_capacity: u64,
    blocking_mode: String,
    #[serde(default)]
    custom_block_ipv4: String,
    #[serde(default)]
    custom_block_ipv6: String,
    blocklist_refresh_interval: u32,
    /// HTML checkbox: present (any value) when ticked, absent when unticked.
    #[serde(default)]
    query_log_enabled: Option<String>,
    query_log_retention_days: u32,
    upstream_selection_strategy: String,
    upstream_parallel_fanout: u32,
}

impl SettingsForm {
    /// Validate the raw form into a typed [`Settings`].
    ///
    /// The UI theme is no longer part of this form — it is toggled from the
    /// topbar (see [`AppState::theme_toggle`]) — so the caller passes the
    /// currently-stored `ui_theme` through to preserve it across a save.
    fn into_settings(self, ui_theme: String) -> WebResult<Settings> {
        if self.cache_min_ttl > self.cache_max_ttl {
            return Err(WebError::bad_request(
                "Minimum cache TTL must not exceed the maximum.",
            ));
        }
        if self.cache_capacity == 0 {
            return Err(WebError::bad_request("Cache capacity must be at least 1."));
        }
        let blocking_mode: BlockingMode = self
            .blocking_mode
            .parse()
            .map_err(|_| WebError::bad_request("Invalid blocking mode."))?;

        // Custom IPs only matter in Custom mode, where the inputs are visible
        // and validated strictly. In other modes the inputs are hidden, so we
        // keep whatever still parses (preserving previously-saved IPs) and
        // silently drop anything else — a stale value can never block saving.
        let (custom_block_ipv4, custom_block_ipv6) = if blocking_mode == BlockingMode::Custom {
            (
                parse_opt_ip::<Ipv4Addr>(&self.custom_block_ipv4, "IPv4")?,
                parse_opt_ip::<Ipv6Addr>(&self.custom_block_ipv6, "IPv6")?,
            )
        } else {
            (
                self.custom_block_ipv4.trim().parse::<Ipv4Addr>().ok(),
                self.custom_block_ipv6.trim().parse::<Ipv6Addr>().ok(),
            )
        };

        if self.query_log_retention_days == 0 {
            return Err(WebError::bad_request(
                "Query-log retention must be at least 1 day.",
            ));
        }

        let upstream_selection_strategy: SelectionStrategy = self
            .upstream_selection_strategy
            .parse()
            .map_err(|_| WebError::bad_request("Invalid upstream selection strategy."))?;
        if self.upstream_parallel_fanout < 1 {
            return Err(WebError::bad_request(
                "Parallel fan-out must be at least 1.",
            ));
        }

        Ok(Settings {
            cache_min_ttl: self.cache_min_ttl,
            cache_max_ttl: self.cache_max_ttl,
            cache_negative_ttl_cap: self.cache_negative_ttl_cap,
            cache_capacity: self.cache_capacity,
            blocking_mode,
            custom_block_ipv4,
            custom_block_ipv6,
            blocklist_refresh_interval: self.blocklist_refresh_interval,
            ui_theme,
            query_log_enabled: self.query_log_enabled.is_some(),
            query_log_retention_days: self.query_log_retention_days,
            upstream_selection_strategy,
            upstream_parallel_fanout: self.upstream_parallel_fanout,
        })
    }
}

/// Parse an optional IP string (empty → `None`).
fn parse_opt_ip<T: std::str::FromStr>(s: &str, label: &str) -> Result<Option<T>, WebError> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(None);
    }
    s.parse::<T>()
        .map(Some)
        .map_err(|_| WebError::bad_request(format!("'{s}' is not a valid {label} address.")))
}

/// The settings page.
#[derive(Template, WebTemplate)]
#[template(path = "settings.html")]
struct SettingsPageTemplate {
    chrome: Chrome,
    cache_min_ttl: u32,
    cache_max_ttl: u32,
    cache_negative_ttl_cap: u32,
    cache_capacity: u64,
    blocking_mode: &'static str,
    custom_block_ipv4: String,
    custom_block_ipv6: String,
    blocklist_refresh_interval: u32,
    query_log_enabled: bool,
    query_log_retention_days: u32,
    upstream_selection_strategy: &'static str,
    upstream_parallel_fanout: u32,
    error: Option<String>,
    notice: Option<String>,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::synth::BlockMode;
    use tempfile::TempDir;

    async fn state() -> (TempDir, AppState) {
        let (dir, db) = crate::test_support::temp_db().await;
        (dir, AppState::for_test(db).await)
    }

    fn base_form() -> SettingsForm {
        SettingsForm {
            cache_min_ttl: 10,
            cache_max_ttl: 3600,
            cache_negative_ttl_cap: 300,
            cache_capacity: 50_000,
            blocking_mode: "nxdomain".to_owned(),
            custom_block_ipv4: String::new(),
            custom_block_ipv6: String::new(),
            blocklist_refresh_interval: 7200,
            query_log_enabled: Some("on".to_owned()),
            query_log_retention_days: 30,
            upstream_selection_strategy: "random".to_owned(),
            upstream_parallel_fanout: 2,
        }
    }

    #[tokio::test]
    async fn apply_settings_persists_and_updates_snapshot() {
        let (_d, st) = state().await;
        st.apply_settings(base_form()).await.expect("apply");

        // Persisted.
        let s = st.db.settings().get().await.unwrap();
        assert_eq!(s.cache_max_ttl, 3600);
        assert_eq!(s.blocking_mode, BlockingMode::NxDomain);
        // The theme is owned by the topbar toggle now, so a settings save
        // leaves the stored value (the fresh-install default) untouched.
        assert_eq!(s.ui_theme, "auto");

        // Live snapshot updated (blocking mode applies immediately).
        assert_eq!(st.resolver.settings().block_mode, BlockMode::NxDomain);
        assert_eq!(st.resolver.settings().cache_max_ttl, 3600);
    }

    #[tokio::test]
    async fn parallel_strategy_rebuilds_pool_in_parallel_mode() {
        let (_d, st) = state().await;

        // A fresh test pool is sequential.
        assert_eq!(st.upstream_pool.load().parallel_fanout(), None);

        let mut f = base_form();
        f.upstream_selection_strategy = "parallel".to_owned();
        f.upstream_parallel_fanout = 3;
        st.apply_settings(f).await.expect("apply");

        // Persisted + live snapshot reflect the strategy …
        let s = st.db.settings().get().await.unwrap();
        assert_eq!(s.upstream_selection_strategy, SelectionStrategy::Parallel);
        assert_eq!(
            st.resolver.settings().upstream_selection_strategy,
            SelectionStrategy::Parallel
        );
        // … and the pool was rebuilt in parallel mode with the configured fan-out.
        assert_eq!(st.upstream_pool.load().parallel_fanout(), Some(3));
    }

    #[tokio::test]
    async fn invalid_fanout_is_rejected() {
        let (_d, st) = state().await;
        let mut f = base_form();
        f.upstream_parallel_fanout = 0;
        assert!(matches!(
            st.apply_settings(f).await,
            Err(WebError::BadRequest(_))
        ));
    }

    #[tokio::test]
    async fn min_greater_than_max_is_rejected() {
        let (_d, st) = state().await;
        let mut f = base_form();
        f.cache_min_ttl = 5000;
        f.cache_max_ttl = 100;
        assert!(matches!(
            st.apply_settings(f).await,
            Err(WebError::BadRequest(_))
        ));
    }

    #[tokio::test]
    async fn custom_mode_with_ips_round_trips() {
        let (_d, st) = state().await;
        let mut f = base_form();
        f.blocking_mode = "custom".to_owned();
        f.custom_block_ipv4 = "203.0.113.1".to_owned();
        st.apply_settings(f).await.expect("apply custom");
        let s = st.db.settings().get().await.unwrap();
        assert_eq!(s.blocking_mode, BlockingMode::Custom);
        assert_eq!(s.custom_block_ipv4, Some("203.0.113.1".parse().unwrap()));
    }

    #[tokio::test]
    async fn invalid_custom_ip_in_custom_mode_is_rejected() {
        let (_d, st) = state().await;
        let mut f = base_form();
        f.blocking_mode = "custom".to_owned();
        f.custom_block_ipv4 = "not-an-ip".to_owned();
        assert!(matches!(
            st.apply_settings(f).await,
            Err(WebError::BadRequest(_))
        ));
    }

    #[tokio::test]
    async fn invalid_custom_ip_ignored_when_mode_not_custom() {
        let (_d, st) = state().await;
        let mut f = base_form(); // nxdomain
        // A stale/invalid value in the (hidden) custom field must not block the
        // save — it is simply dropped.
        f.custom_block_ipv4 = "not-an-ip".to_owned();
        st.apply_settings(f).await.expect("apply");
        let s = st.db.settings().get().await.unwrap();
        assert_eq!(s.custom_block_ipv4, None);
    }

    #[tokio::test]
    async fn valid_custom_ip_preserved_across_non_custom_save() {
        let (_d, st) = state().await;
        // A valid custom IP survives a save made while in a non-custom mode, so
        // switching modes back and forth does not lose it.
        let mut f = base_form(); // nxdomain
        f.custom_block_ipv4 = "203.0.113.9".to_owned();
        st.apply_settings(f).await.expect("apply");
        let s = st.db.settings().get().await.unwrap();
        assert_eq!(s.custom_block_ipv4, Some("203.0.113.9".parse().unwrap()));
    }

    #[tokio::test]
    async fn query_log_fields_round_trip() {
        let (_d, st) = state().await;
        let mut f = base_form();
        // Unticked checkbox → None → disabled; custom retention window.
        f.query_log_enabled = None;
        f.query_log_retention_days = 7;
        st.apply_settings(f).await.expect("apply");

        let s = st.db.settings().get().await.unwrap();
        assert!(!s.query_log_enabled, "unticked checkbox disables logging");
        assert_eq!(s.query_log_retention_days, 7);

        // The live snapshot is updated too, so the writer gate sees it at once.
        assert!(!st.resolver.settings().query_log_enabled);
        assert_eq!(st.resolver.settings().query_log_retention_days, 7);
    }

    #[tokio::test]
    async fn zero_retention_is_rejected() {
        let (_d, st) = state().await;
        let mut f = base_form();
        f.query_log_retention_days = 0;
        assert!(matches!(
            st.apply_settings(f).await,
            Err(WebError::BadRequest(_))
        ));
    }

    #[tokio::test]
    async fn clear_log_empties_the_table() {
        use crate::{
            resolver::pipeline::Outcome,
            storage::query_log::{QueryLogRecord, QueryLogRepository},
        };

        let (_d, st) = state().await;
        let repo = st.db.query_log();
        repo.insert_batch(&[QueryLogRecord {
            id: 0,
            ts: 1,
            client: "10.0.0.1".to_owned(),
            qname: "x.test.".to_owned(),
            qtype: "A".to_owned(),
            outcome: Outcome::Forwarded,
            rcode: Some(0),
            upstream: None,
            latency_ms: 1,
            blocklist_id: None,
        }])
        .await
        .expect("seed a row");

        repo.clear_all().await.expect("clear");
        assert!(repo.page(None, 10).await.expect("page").is_empty());
    }
}
