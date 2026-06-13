//! Temporarily pause / resume DNS blocking (E12, SPEC §9).
//!
//! Pi-hole's "disable blocking", time-boxed. The admin picks a duration (5 m /
//! 30 m / 1 h / custom) and every blocking stage stands down until the deadline;
//! local records keep answering. The deadline lives on the shared
//! [`ResolverState`](crate::resolver::state::ResolverState) (E12.1) and
//! auto-resumes by comparison, so these handlers only flip the flag — there is
//! no timer to cancel and nothing to persist (a restart resumes blocking).
//!
//! Both routes are state-changing POSTs and so are CSRF-protected by the
//! middleware in [`crate::web::csrf`]; the navbar/banner forms carry the
//! session-bound token as a `csrf_token` field.

use axum::{
    extract::State,
    response::{IntoResponse, Redirect, Response},
};
use serde::Deserialize;
use tracing::info;

use crate::web::{AppState, auth::CurrentUser};

/// Upper bound on a single pause, in minutes (24 h).
///
/// A guard against a fat-fingered custom value silently disabling blocking for
/// days. The in-memory deadline also resets on restart, so this is a soft cap.
const MAX_PAUSE_MINUTES: i64 = 24 * 60;

/// The pause duration, in whole minutes, from a preset button or the custom
/// input. (`csrf_token` travels alongside but is consumed by the CSRF layer.)
#[derive(Debug, Deserialize)]
pub struct PauseForm {
    pub minutes: i64,
}

impl AppState {
    /// `POST /blocking/pause` — pause all blocking for the requested minutes.
    ///
    /// Clamps the request to `1..=MAX_PAUSE_MINUTES` so a zero/negative or
    /// absurd value can neither no-op confusingly nor pause indefinitely, then
    /// redirects (PRG) to the dashboard where the countdown banner renders.
    pub async fn blocking_pause(
        _user: CurrentUser,
        State(state): State<AppState>,
        axum::Form(form): axum::Form<PauseForm>,
    ) -> Response {
        let minutes = form.minutes.clamp(1, MAX_PAUSE_MINUTES);
        state.resolver.pause_for_secs(minutes * 60);
        info!(minutes, "blocking paused");
        Redirect::to("/").into_response()
    }

    /// `POST /blocking/resume` — resume blocking immediately.
    pub async fn blocking_resume(_user: CurrentUser, State(state): State<AppState>) -> Response {
        state.resolver.resume();
        info!("blocking resumed");
        Redirect::to("/").into_response()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn state() -> (TempDir, AppState) {
        let (dir, db) = crate::test_support::temp_db().await;
        let st = AppState::for_test(db).await;
        (dir, st)
    }

    #[tokio::test]
    async fn pause_clamps_and_sets_deadline() {
        let (_d, st) = state().await;
        assert!(!st.resolver.blocking_paused());

        st.resolver.pause_for_secs(5 * 60);
        assert!(st.resolver.blocking_paused());

        // The chrome derives a positive remaining-seconds value for the banner.
        let remaining = st.pause_remaining().expect("paused");
        assert!(remaining > 0 && remaining <= 5 * 60);
    }

    #[tokio::test]
    async fn resume_clears_the_deadline() {
        let (_d, st) = state().await;
        st.resolver.pause_for_secs(30 * 60);
        assert!(st.resolver.blocking_paused());

        st.resolver.resume();
        assert!(!st.resolver.blocking_paused());
        assert_eq!(st.pause_remaining(), None);
    }
}
