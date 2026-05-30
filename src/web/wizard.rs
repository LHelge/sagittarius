//! First-run wizard (SPEC §9, §10).
//!
//! When the `admin_users` table is empty, the **web UI** is locked behind a
//! one-step wizard that creates the initial admin account.  The DNS resolver is
//! unaffected — it serves from boot using the seeded defaults regardless of
//! whether an admin account exists; only the admin UI is gated.
//!
//! Gating is implemented by [`guard`], a middleware applied ahead of the auth
//! and CSRF layers:
//!
//! - While no admin exists, every admin route (including `/login`) redirects to
//!   `/setup`, except the embedded assets and `/setup` itself.
//! - Once an admin exists, `/setup` is closed and redirects to `/login`; normal
//!   authentication applies everywhere else.
//!
//! A fast-path [`AppState::setup_done`] flag avoids a database count on every
//! request: it flips to `true` the first time an admin is observed and never
//! flips back during a process's lifetime.

use std::sync::atomic::Ordering;

use askama::Template;
use askama_web::WebTemplate;
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
};

use crate::{
    storage::admin_users::{AdminUserRepository, SqliteAdminUserRepo},
    web::{AppState, Chrome, auth::Password, render::WebError},
};

/// Minimum acceptable length for the initial admin password.
const MIN_PASSWORD_LEN: usize = 8;

impl AppState {
    /// Whether the first-run wizard must run (i.e. no admin user exists yet).
    ///
    /// Cached via [`AppState::setup_done`] so a database count happens at most
    /// once per process once an admin exists.  On a database error we report
    /// `false` so a transient failure does not trap the operator in the wizard;
    /// the normal auth flow then applies.
    async fn needs_setup(&self) -> bool {
        if self.setup_done.load(Ordering::Relaxed) {
            return false;
        }
        match SqliteAdminUserRepo::new(self.db.pool().clone())
            .count()
            .await
        {
            Ok(0) => true,
            Ok(_) => {
                self.setup_done.store(true, Ordering::Relaxed);
                false
            }
            Err(e) => {
                tracing::warn!(error = %e, "admin_users count failed; assuming setup complete");
                false
            }
        }
    }
}

/// Middleware that routes all admin traffic through the wizard until the first
/// admin account exists, then closes the wizard.
pub async fn guard(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let path = req.uri().path();

    // Assets must always load so the wizard/login pages render correctly.
    if path.starts_with("/assets/") || path == "/favicon.ico" {
        return next.run(req).await;
    }

    if state.needs_setup().await {
        // No admin yet: force the wizard for everything except the wizard itself.
        if path == "/setup" {
            return next.run(req).await;
        }
        return Redirect::to("/setup").into_response();
    }

    // Admin exists: the wizard is closed.
    if path == "/setup" {
        return Redirect::to("/login").into_response();
    }
    next.run(req).await
}

/// First-run wizard form payload.
#[derive(Debug, serde::Deserialize)]
pub struct SetupForm {
    username: String,
    password: String,
    confirm: String,
}

impl SetupForm {
    /// The submitted username, trimmed of surrounding whitespace.
    fn username(&self) -> &str {
        self.username.trim()
    }

    /// Validate the inputs, returning a user-facing message on failure.
    fn validate(&self) -> Result<(), String> {
        if self.username().is_empty() {
            return Err("Username is required.".to_owned());
        }
        if self.password.len() < MIN_PASSWORD_LEN {
            return Err(format!(
                "Password must be at least {MIN_PASSWORD_LEN} characters."
            ));
        }
        if self.password != self.confirm {
            return Err("Passwords do not match.".to_owned());
        }
        Ok(())
    }
}

impl AppState {
    /// `GET /setup` — render the first-run wizard form.
    pub async fn setup_form(State(state): State<AppState>) -> Response {
        WizardTemplate {
            chrome: state.bare_chrome().await,
            error: None,
        }
        .into_response()
    }

    /// `POST /setup` — create the initial admin account.
    pub async fn setup_submit(
        State(state): State<AppState>,
        axum::Form(form): axum::Form<SetupForm>,
    ) -> Response {
        let repo = SqliteAdminUserRepo::new(state.db.pool().clone());

        if let Err(msg) = form.validate() {
            return WizardTemplate {
                chrome: state.bare_chrome().await,
                error: Some(msg),
            }
            .into_response();
        }

        let password = match Password::hash(&form.password) {
            Ok(p) => p,
            Err(e) => return e.into_response(),
        };
        match repo
            .create_initial(form.username(), password.as_str())
            .await
        {
            Ok(Some(_)) => {}
            Ok(None) => return Redirect::to("/login").into_response(),
            Err(e) => return WebError::from(e).into_response(),
        }

        // Unlock the UI; the operator now logs in normally.
        state.setup_done.store(true, Ordering::Relaxed);
        Redirect::to("/login").into_response()
    }
}

/// The first-run wizard page (bare layout).
#[derive(Template, WebTemplate)]
#[template(path = "setup.html")]
struct WizardTemplate {
    chrome: Chrome,
    error: Option<String>,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn form(username: &str, password: &str, confirm: &str) -> SetupForm {
        SetupForm {
            username: username.to_owned(),
            password: password.to_owned(),
            confirm: confirm.to_owned(),
        }
    }

    #[test]
    fn validate_accepts_good_input() {
        assert!(form("admin", "longenough", "longenough").validate().is_ok());
    }

    #[test]
    fn validate_rejects_empty_username() {
        assert!(form("", "longenough", "longenough").validate().is_err());
        // Whitespace-only usernames are rejected too (trimmed).
        assert!(form("   ", "longenough", "longenough").validate().is_err());
    }

    #[test]
    fn validate_rejects_short_password() {
        let err = form("admin", "short", "short").validate().unwrap_err();
        assert!(err.contains("at least"));
    }

    #[test]
    fn validate_rejects_mismatch() {
        let err = form("admin", "longenough", "different")
            .validate()
            .unwrap_err();
        assert!(err.contains("do not match"));
    }
}
