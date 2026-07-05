//! API-key management for the config-sync surface (SPEC §13, E18.5).
//!
//! A **secondary/fallback** instance authenticates to this (the **primary**)
//! instance's read-only config-sync API with a bearer key minted here.  This
//! page lets the operator **create** a key (its plaintext is shown exactly once
//! and never again), **list** existing keys (active and revoked), and
//! **revoke** one.
//!
//! Only the SHA-256 hash of a key's token is stored (see
//! [`crate::storage::api_keys`]); the plaintext returned by
//! [`MintedApiKey::mint`](crate::web::auth::MintedApiKey) is displayed in the
//! create response and then dropped.

use askama::Template;
use askama_web::WebTemplate;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use serde::Deserialize;

use crate::{
    storage::api_keys::ApiKeyRepository,
    time::Clock,
    web::{
        AppState, Chrome,
        auth::{CurrentUser, MintedApiKey},
        render::WebResult,
    },
};

impl AppState {
    async fn render_apikeys(
        &self,
        user: &CurrentUser,
        error: Option<String>,
        notice: Option<String>,
        new_key: Option<String>,
    ) -> WebResult<ApiKeysPageTemplate> {
        let now = Clock::now_secs();
        let keys = self
            .db
            .api_keys()
            .list()
            .await?
            .into_iter()
            .map(|k| ApiKeyView {
                id: k.id,
                label: k.label,
                created: ago(now, k.created_at),
                last_used: k
                    .last_used_at
                    .map_or_else(|| "never".to_owned(), |t| ago(now, t)),
                revoked: k.revoked_at.is_some(),
            })
            .collect();

        Ok(ApiKeysPageTemplate {
            chrome: self.chrome("apikeys", user).await,
            keys,
            new_key,
            error,
            notice,
        })
    }

    /// `GET /apikeys` — list existing keys.
    pub async fn apikeys_page(
        user: CurrentUser,
        State(state): State<AppState>,
    ) -> WebResult<Response> {
        Ok(state
            .render_apikeys(&user, None, None, None)
            .await?
            .into_response())
    }

    /// `POST /apikeys/create` — mint a new key and show its plaintext once.
    pub async fn apikey_create(
        user: CurrentUser,
        State(state): State<AppState>,
        axum::Form(form): axum::Form<CreateApiKeyForm>,
    ) -> WebResult<Response> {
        let label = form.label.trim();
        if label.is_empty() {
            let page = state
                .render_apikeys(&user, Some("Give the key a label.".to_owned()), None, None)
                .await?;
            return Ok((StatusCode::BAD_REQUEST, page).into_response());
        }

        let minted = MintedApiKey::mint(label);
        let plaintext = minted.plaintext.clone();
        state.db.api_keys().insert(&minted.row).await?;

        Ok(state
            .render_apikeys(
                &user,
                None,
                Some("API key created. Copy it now — it is not shown again.".to_owned()),
                Some(plaintext),
            )
            .await?
            .into_response())
    }

    /// `POST /apikeys/revoke` — revoke a key by id.
    pub async fn apikey_revoke(
        _user: CurrentUser,
        State(state): State<AppState>,
        axum::Form(form): axum::Form<ApiKeyIdForm>,
    ) -> WebResult<Response> {
        state
            .db
            .api_keys()
            .revoke(&form.id, Clock::now_secs())
            .await?;
        Ok(Redirect::to("/apikeys").into_response())
    }
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

/// Create-key form payload.
#[derive(Debug, Deserialize)]
pub struct CreateApiKeyForm {
    label: String,
}

/// Form payload carrying just a key id.
#[derive(Debug, Deserialize)]
pub struct ApiKeyIdForm {
    id: String,
}

/// One API-key row for display (never carries the token hash).
struct ApiKeyView {
    id: String,
    label: String,
    created: String,
    last_used: String,
    revoked: bool,
}

/// The API-key management page.
#[derive(Template, WebTemplate)]
#[template(path = "apikeys.html")]
struct ApiKeysPageTemplate {
    chrome: Chrome,
    keys: Vec<ApiKeyView>,
    /// The one-time plaintext of a just-created key, shown once then forgotten.
    new_key: Option<String>,
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
        assert_eq!(ago(100, 200), "0s ago");
    }

    #[tokio::test]
    async fn create_shows_plaintext_once_then_lists_without_it() {
        let (_d, st) = state().await;

        // Create renders the plaintext exactly once …
        let resp = AppState::apikey_create(
            test_user(),
            State(st.clone()),
            axum::Form(CreateApiKeyForm {
                label: "fallback-nas".to_owned(),
            }),
        )
        .await
        .expect("create");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("fallback-nas"));
        assert!(html.contains("not shown again"));

        // The stored row exists …
        let keys = st.db.api_keys().list().await.unwrap();
        assert_eq!(keys.len(), 1);
        let id = keys[0].id.clone();

        // … and a fresh page render never re-shows the token, only the id.
        let page = st
            .render_apikeys(&test_user(), None, None, None)
            .await
            .expect("render")
            .render()
            .expect("template");
        assert!(page.contains(&id), "key id must be listed");
        assert!(
            !page.contains(&format!("{id}.")),
            "the secret token must never re-render"
        );
    }

    #[tokio::test]
    async fn empty_label_is_rejected() {
        let (_d, st) = state().await;
        let resp = AppState::apikey_create(
            test_user(),
            State(st.clone()),
            axum::Form(CreateApiKeyForm {
                label: "   ".to_owned(),
            }),
        )
        .await
        .expect("create");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(st.db.api_keys().list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn revoke_marks_key_revoked() {
        let (_d, st) = state().await;
        let minted = MintedApiKey::mint("k");
        let id = minted.row.id.clone();
        st.db.api_keys().insert(&minted.row).await.unwrap();

        let resp = AppState::apikey_revoke(
            test_user(),
            State(st.clone()),
            axum::Form(ApiKeyIdForm { id: id.clone() }),
        )
        .await
        .expect("revoke");
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);

        assert!(
            st.db.api_keys().find_active(&id).await.unwrap().is_none(),
            "revoked key must no longer authenticate"
        );
    }
}
