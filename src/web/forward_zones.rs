//! Conditional-forward zone management (SPEC §9).
//!
//! List the private reverse zones (and any custom zones), set each zone's
//! router/DHCP `target` resolver, and toggle whether it participates in routing.
//! A convenience "forward all to" action points every seeded reverse zone at one
//! target in a single click — the common LAN setup.
//!
//! This module only persists configuration; the resolver hot path that actually
//! routes queries under an enabled zone to its target is wired up in E13.4, which
//! will rebuild its live forwarder snapshot from these rows on every change.

use std::net::{IpAddr, SocketAddr};

use askama::Template;
use askama_web::WebTemplate;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use serde::Deserialize;

use crate::{
    storage::forward_zones::ForwardZoneRepository,
    web::{
        AppState, Chrome,
        auth::CurrentUser,
        render::{WebError, WebResult},
    },
};

impl AppState {
    async fn render_forwarding(
        &self,
        user: &CurrentUser,
        error: Option<String>,
    ) -> WebResult<ForwardingPageTemplate> {
        let zones = self
            .db
            .forward_zones()
            .list()
            .await?
            .into_iter()
            .map(|z| ForwardZoneView {
                id: z.id,
                zone_suffix: z.zone_suffix,
                target: z.target.unwrap_or_default(),
                enabled: z.enabled,
            })
            .collect();
        Ok(ForwardingPageTemplate {
            chrome: self.chrome("forwarding", user).await,
            zones,
            error,
        })
    }

    /// `GET /forwarding`.
    pub async fn forwarding_page(
        user: CurrentUser,
        State(state): State<AppState>,
    ) -> WebResult<Response> {
        Ok(state.render_forwarding(&user, None).await?.into_response())
    }

    /// `POST /forwarding/target` — set or clear one zone's target.
    pub async fn forward_zone_set_target(
        user: CurrentUser,
        State(state): State<AppState>,
        axum::Form(form): axum::Form<SetTargetForm>,
    ) -> WebResult<Response> {
        match state.set_zone_target(form).await {
            Ok(()) => Ok(Redirect::to("/forwarding").into_response()),
            Err(WebError::BadRequest(msg)) => {
                let page = state.render_forwarding(&user, Some(msg)).await?;
                Ok((StatusCode::BAD_REQUEST, page).into_response())
            }
            Err(e) => Err(e),
        }
    }

    async fn set_zone_target(&self, form: SetTargetForm) -> WebResult<()> {
        let target = normalize_target(&form.target)?;
        self.db
            .forward_zones()
            .set_target(form.id, target.as_deref())
            .await?;
        Ok(())
    }

    /// `POST /forwarding/toggle` — enable/disable one zone.
    pub async fn forward_zone_toggle(
        _user: CurrentUser,
        State(state): State<AppState>,
        axum::Form(form): axum::Form<ToggleZoneForm>,
    ) -> WebResult<Response> {
        state
            .db
            .forward_zones()
            .set_enabled(form.id, form.enabled)
            .await?;
        Ok(Redirect::to("/forwarding").into_response())
    }

    /// `POST /forwarding/apply-all` — point every zone at one target and enable
    /// them all.  The one-click LAN reverse-DNS setup.
    pub async fn forward_zone_apply_all(
        user: CurrentUser,
        State(state): State<AppState>,
        axum::Form(form): axum::Form<ApplyAllForm>,
    ) -> WebResult<Response> {
        match state.apply_target_to_all(form).await {
            Ok(()) => Ok(Redirect::to("/forwarding").into_response()),
            Err(WebError::BadRequest(msg)) => {
                let page = state.render_forwarding(&user, Some(msg)).await?;
                Ok((StatusCode::BAD_REQUEST, page).into_response())
            }
            Err(e) => Err(e),
        }
    }

    async fn apply_target_to_all(&self, form: ApplyAllForm) -> WebResult<()> {
        let Some(target) = normalize_target(&form.target)? else {
            return Err(WebError::bad_request(
                "Enter the router/DHCP resolver address to forward all reverse zones to.",
            ));
        };
        let repo = self.db.forward_zones();
        for zone in repo.list().await? {
            repo.set_target(zone.id, Some(&target)).await?;
            repo.set_enabled(zone.id, true).await?;
        }
        Ok(())
    }
}

/// Validate and normalize a target resolver string.
///
/// Accepts a bare IP (`10.0.0.1`) or an `IP:port` socket address
/// (`10.0.0.1:5353`).  An empty/blank string normalizes to `None` (clears the
/// target).  Anything else is a [`WebError::BadRequest`] so a zone never stores
/// an address the resolver could not parse.
fn normalize_target(raw: &str) -> WebResult<Option<String>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.parse::<IpAddr>().is_ok() || trimmed.parse::<SocketAddr>().is_ok() {
        Ok(Some(trimmed.to_owned()))
    } else {
        Err(WebError::bad_request(
            "Target must be an IP address (optionally with :port), e.g. 192.168.1.1 or 192.168.1.1:5353.",
        ))
    }
}

/// Set-target form payload.
#[derive(Debug, Deserialize)]
pub struct SetTargetForm {
    id: i64,
    #[serde(default)]
    target: String,
}

/// Enable/disable form payload.
#[derive(Debug, Deserialize)]
pub struct ToggleZoneForm {
    id: i64,
    enabled: bool,
}

/// Apply-to-all form payload.
#[derive(Debug, Deserialize)]
pub struct ApplyAllForm {
    #[serde(default)]
    target: String,
}

/// One forward-zone row for display.
struct ForwardZoneView {
    id: i64,
    zone_suffix: String,
    target: String,
    enabled: bool,
}

/// The forwarding management page.
#[derive(Template, WebTemplate)]
#[template(path = "forwarding.html")]
struct ForwardingPageTemplate {
    chrome: Chrome,
    zones: Vec<ForwardZoneView>,
    error: Option<String>,
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

    // ── normalize_target ──────────────────────────────────────────────────────

    #[test]
    fn normalize_target_accepts_ip_and_socket() {
        assert_eq!(
            normalize_target("192.168.1.1").unwrap().as_deref(),
            Some("192.168.1.1")
        );
        assert_eq!(
            normalize_target(" 10.0.0.1:5353 ").unwrap().as_deref(),
            Some("10.0.0.1:5353")
        );
        assert_eq!(
            normalize_target("fd00::1").unwrap().as_deref(),
            Some("fd00::1")
        );
    }

    #[test]
    fn normalize_target_blank_is_none() {
        assert!(normalize_target("   ").unwrap().is_none());
    }

    #[test]
    fn normalize_target_rejects_garbage() {
        assert!(matches!(
            normalize_target("router.local"),
            Err(WebError::BadRequest(_))
        ));
    }

    // ── handlers (via the inner helpers) ──────────────────────────────────────

    #[tokio::test]
    async fn set_target_then_toggle_persists() {
        let (_d, st) = state().await;
        let zones = st.db.forward_zones().list().await.unwrap();
        let id = zones
            .iter()
            .find(|z| z.zone_suffix == "168.192.in-addr.arpa")
            .unwrap()
            .id;

        st.set_zone_target(SetTargetForm {
            id,
            target: "192.168.1.1".to_owned(),
        })
        .await
        .expect("set target");
        st.db
            .forward_zones()
            .set_enabled(id, true)
            .await
            .expect("enable");

        let enabled = st.db.forward_zones().list_enabled().await.unwrap();
        assert_eq!(enabled.len(), 1);
        assert_eq!(enabled[0].target.as_deref(), Some("192.168.1.1"));
    }

    #[tokio::test]
    async fn set_target_rejects_bad_address() {
        let (_d, st) = state().await;
        let id = st.db.forward_zones().list().await.unwrap()[0].id;
        let err = st
            .set_zone_target(SetTargetForm {
                id,
                target: "not-an-ip".to_owned(),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, WebError::BadRequest(_)));
    }

    #[tokio::test]
    async fn apply_all_targets_and_enables_every_zone() {
        let (_d, st) = state().await;
        st.apply_target_to_all(ApplyAllForm {
            target: "192.168.1.1".to_owned(),
        })
        .await
        .expect("apply all");

        let all = st.db.forward_zones().list().await.unwrap();
        let enabled = st.db.forward_zones().list_enabled().await.unwrap();
        assert_eq!(
            enabled.len(),
            all.len(),
            "every zone must be enabled and targeted"
        );
        for z in &enabled {
            assert_eq!(z.target.as_deref(), Some("192.168.1.1"));
        }
    }

    #[tokio::test]
    async fn apply_all_requires_a_target() {
        let (_d, st) = state().await;
        let err = st
            .apply_target_to_all(ApplyAllForm {
                target: "  ".to_owned(),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, WebError::BadRequest(_)));
    }

    #[tokio::test]
    async fn render_lists_seeded_zones() {
        let (_d, st) = state().await;
        let user = CurrentUser {
            user_id: 1,
            session_id: "sess".to_owned(),
        };
        let page = st.render_forwarding(&user, None).await.expect("render");
        assert_eq!(page.zones.len(), 20, "all seeded zones must render");
        assert!(page.zones.iter().all(|z| !z.enabled));
    }
}
