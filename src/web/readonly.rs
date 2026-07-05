//! Read-only enforcement for a secondary/fallback instance (SPEC §13, E18.9).
//!
//! A secondary mirrors the primary's configuration and must not accept local
//! edits.  [`guard`] rejects every state-changing request with **403** while in
//! secondary mode, except the authentication endpoints (`/login`, `/logout`) so
//! the operator can still sign in and out with the mirrored credentials.
//!
//! It is applied **outside** the CSRF layer so it short-circuits first: a
//! mutation on a secondary is refused before any token handling.  In primary
//! mode the guard is a pure pass-through and adds a single branch per request.

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::web::{AppState, csrf};

/// Message returned when a mutation is refused on a read-only secondary.
const READ_ONLY_MESSAGE: &str =
    "This is a read-only fallback instance; configuration is managed on the primary.";

/// Middleware that blocks mutations on a read-only secondary instance.
pub async fn guard(State(state): State<AppState>, req: Request, next: Next) -> Response {
    // Primary instances are unaffected.
    if !state.instance_mode.is_secondary() {
        return next.run(req).await;
    }

    // Safe (non-mutating) methods always pass — the whole UI stays viewable.
    if csrf::is_safe(req.method()) {
        return next.run(req).await;
    }

    // Authentication must still work locally with the mirrored credentials.
    let path = req.uri().path();
    if path == "/login" || path == "/logout" {
        return next.run(req).await;
    }

    (StatusCode::FORBIDDEN, READ_ONLY_MESSAGE).into_response()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::InstanceMode;
    use axum::{
        Router,
        body::Body,
        http::{Method, Request as HttpRequest},
        middleware,
        routing::{get, post},
    };
    use tower::ServiceExt; // for `oneshot`

    async fn ok() -> &'static str {
        "ok"
    }

    async fn app(mode: InstanceMode) -> Router {
        let (_dir, db) = crate::test_support::temp_db().await;
        let mut state = AppState::for_test(db).await;
        state.instance_mode = mode;
        // Leak the TempDir so the pool stays valid for the test's lifetime.
        std::mem::forget(_dir);
        Router::new()
            .route("/x", get(ok).post(ok))
            .route("/login", post(ok))
            .route("/logout", post(ok))
            .layer(middleware::from_fn_with_state(state.clone(), guard))
            .with_state(state)
    }

    async fn status(router: Router, method: Method, path: &str) -> StatusCode {
        let req = HttpRequest::builder()
            .method(method)
            .uri(path)
            .body(Body::empty())
            .unwrap();
        router.oneshot(req).await.unwrap().status()
    }

    #[tokio::test]
    async fn primary_allows_all_methods() {
        let r = app(InstanceMode::Primary).await;
        assert_eq!(status(r.clone(), Method::GET, "/x").await, StatusCode::OK);
        assert_eq!(status(r, Method::POST, "/x").await, StatusCode::OK);
    }

    #[tokio::test]
    async fn secondary_blocks_mutations_but_allows_reads_and_auth() {
        let mode = InstanceMode::Secondary {
            primary_url: "https://p.lan".to_owned(),
        };
        let r = app(mode).await;
        // GET is fine (viewable), POST /x is refused.
        assert_eq!(status(r.clone(), Method::GET, "/x").await, StatusCode::OK);
        assert_eq!(
            status(r.clone(), Method::POST, "/x").await,
            StatusCode::FORBIDDEN
        );
        // Login / logout still work.
        assert_eq!(
            status(r.clone(), Method::POST, "/login").await,
            StatusCode::OK
        );
        assert_eq!(status(r, Method::POST, "/logout").await, StatusCode::OK);
    }
}
