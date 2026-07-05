//! Primary-side config-sync API (SPEC §13, E18.4).
//!
//! Exposes the read-only `GET /api/v1/config` endpoint that a **secondary**
//! instance polls to mirror this **primary**'s configuration.  The endpoint is
//! authenticated by an [`ApiKeyAuth`] bearer key and lives on a sub-router that
//! bypasses the cookie CSRF / wizard guards (a machine caller has no browser
//! session).  See [`AppState::router`](crate::web::AppState).
//!
//! # Conditional requests
//!
//! The response carries an `ETag` equal to the snapshot's content
//! [`version`](crate::sync::dto::ConfigSnapshot::version).  A secondary echoes
//! it as `If-None-Match`; when it still matches, the endpoint returns **304 Not
//! Modified** with no body so an unchanged config is not re-transferred or
//! re-applied — the same conditional-GET shape used for blocklist fetches
//! ([`crate::blocklist::fetch`]).

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};

use crate::{
    storage::{
        admin_users::AdminUserRepository,
        blocklists::BlocklistRepository,
        forward_zones::ForwardZoneRepository,
        lists::{AllowlistRepository, BlacklistRepository},
        local_records::LocalRecordRepository,
        settings::SettingsRepository,
        upstreams::UpstreamRepository,
    },
    sync::dto::{
        AdminUserDto, BlocklistSourceDto, ConfigSnapshot, ForwardZoneDto, LocalRecordDto,
        SettingsDto, UpstreamDto,
    },
    web::{AppState, auth::ApiKeyAuth, render::WebResult},
};

impl AppState {
    /// Build the mirror-worthy [`ConfigSnapshot`] from the database.
    ///
    /// Every `Vec` is sorted by a stable key so the snapshot's content
    /// [`version`](ConfigSnapshot::version) depends only on configuration
    /// content, not on the order SQLite happened to return rows in.
    pub(crate) async fn build_config_snapshot(&self) -> WebResult<ConfigSnapshot> {
        let settings = SettingsDto::from(&self.db.settings().get().await?);

        let mut upstreams: Vec<UpstreamDto> = self
            .db
            .upstreams()
            .list()
            .await?
            .iter()
            .map(UpstreamDto::from)
            .collect();
        upstreams.sort_by(|a, b| {
            a.sort_order
                .cmp(&b.sort_order)
                .then_with(|| a.address.cmp(&b.address))
        });

        let mut blacklist: Vec<String> = self
            .db
            .blacklist()
            .list()
            .await?
            .into_iter()
            .map(|e| e.domain)
            .collect();
        blacklist.sort();

        let mut allowlist: Vec<String> = self
            .db
            .allowlist()
            .list()
            .await?
            .into_iter()
            .map(|e| e.domain)
            .collect();
        allowlist.sort();

        let mut local_records: Vec<LocalRecordDto> = self
            .db
            .local_records()
            .list()
            .await?
            .iter()
            .map(LocalRecordDto::from)
            .collect();
        local_records.sort_by(|a, b| {
            a.name
                .cmp(&b.name)
                .then_with(|| a.record_type.cmp(&b.record_type))
        });

        let mut forward_zones: Vec<ForwardZoneDto> = self
            .db
            .forward_zones()
            .list()
            .await?
            .iter()
            .map(ForwardZoneDto::from)
            .collect();
        forward_zones.sort_by(|a, b| {
            a.sort_order
                .cmp(&b.sort_order)
                .then_with(|| a.zone_suffix.cmp(&b.zone_suffix))
        });

        let mut blocklists: Vec<BlocklistSourceDto> = self
            .db
            .blocklists()
            .list()
            .await?
            .iter()
            .map(BlocklistSourceDto::from)
            .collect();
        blocklists.sort_by(|a, b| a.url.cmp(&b.url));

        // admin_users().list_all() already orders by username.
        let admin_users: Vec<AdminUserDto> = self
            .db
            .admin_users()
            .list_all()
            .await?
            .iter()
            .map(AdminUserDto::from)
            .collect();

        Ok(ConfigSnapshot {
            settings,
            upstreams,
            blacklist,
            allowlist,
            local_records,
            forward_zones,
            blocklists,
            admin_users,
        })
    }

    /// `GET /api/v1/config` — the read-only config snapshot for a secondary.
    ///
    /// Authenticated by [`ApiKeyAuth`].  Honours `If-None-Match` against the
    /// snapshot version (→ 304) and otherwise returns the JSON snapshot with an
    /// `ETag`.
    pub async fn sync_config(
        _auth: ApiKeyAuth,
        State(state): State<AppState>,
        headers: HeaderMap,
    ) -> Response {
        let snapshot = match state.build_config_snapshot().await {
            Ok(s) => s,
            Err(e) => return e.into_response(),
        };
        let version = snapshot.version();
        let etag = format!("\"{version}\"");

        let if_none_match = headers
            .get(header::IF_NONE_MATCH)
            .and_then(|v| v.to_str().ok());
        if etag_matches(if_none_match, &version) {
            return (StatusCode::NOT_MODIFIED, [(header::ETAG, etag)]).into_response();
        }

        let body = serde_json::to_vec(&snapshot).expect("ConfigSnapshot serializes to JSON");
        (
            [
                (header::ETAG, etag),
                (header::CONTENT_TYPE, "application/json".to_owned()),
            ],
            body,
        )
            .into_response()
    }
}

/// Whether an `If-None-Match` header value matches `version`.
///
/// Tolerates the optional weak-validator prefix (`W/`) and the surrounding
/// double quotes an ETag is normally sent with.
fn etag_matches(if_none_match: Option<&str>, version: &str) -> bool {
    if_none_match.is_some_and(|v| {
        v.trim()
            .trim_start_matches("W/")
            .trim_matches('"')
            .eq(version)
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn etag_matches_quoted_weak_and_bare() {
        assert!(etag_matches(Some("\"abc\""), "abc"));
        assert!(etag_matches(Some("W/\"abc\""), "abc"));
        assert!(etag_matches(Some("abc"), "abc"));
        assert!(!etag_matches(Some("\"other\""), "abc"));
        assert!(!etag_matches(None, "abc"));
    }

    #[tokio::test]
    async fn build_config_snapshot_reflects_db_state() {
        use crate::storage::lists::BlacklistRepository;

        let (_dir, db) = crate::test_support::temp_db().await;
        db.blacklist().add("ads.example.com").await.unwrap();
        let state = AppState::for_test(db).await;

        let snap = state.build_config_snapshot().await.expect("snapshot");
        // Seed defaults: two Cloudflare upstreams, the reverse forward zones.
        assert_eq!(snap.upstreams.len(), 2);
        assert!(snap.blacklist.contains(&"ads.example.com.".to_owned()));
        assert_eq!(snap.settings.blocking_mode, "null-ip");
        // A rebuild over unchanged state yields the identical version.
        let again = state.build_config_snapshot().await.expect("snapshot");
        assert_eq!(snap.version(), again.version());
    }
}
