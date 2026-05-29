//! Shared request-handling helpers: the [`WebError`] type that every admin
//! handler can return.
//!
//! Handlers map domain failures (storage errors, validation problems) into a
//! [`WebError`], which renders a small self-contained HTML error page styled
//! by the embedded assets.  Internal errors are logged and shown generically
//! so implementation detail never leaks to the browser; client errors show a
//! short, HTML-escaped message.

use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
use tracing::error;

// ── WebError ──────────────────────────────────────────────────────────────────

/// An error raised while handling an admin request.
#[derive(Debug)]
pub enum WebError {
    /// Something went wrong server-side (500).  The detail is logged, not shown.
    Internal(String),
    /// The request was malformed or failed validation (400).
    BadRequest(String),
    /// The requested resource does not exist (404).
    NotFound(String),
}

impl WebError {
    /// Construct an [`WebError::Internal`].
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }

    /// Construct a [`WebError::BadRequest`].
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::BadRequest(msg.into())
    }

    /// Construct a [`WebError::NotFound`].
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::NotFound(msg.into())
    }
}

impl std::fmt::Display for WebError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Internal(m) => write!(f, "internal error: {m}"),
            Self::BadRequest(m) => write!(f, "bad request: {m}"),
            Self::NotFound(m) => write!(f, "not found: {m}"),
        }
    }
}

impl std::error::Error for WebError {}

impl From<crate::storage::Error> for WebError {
    fn from(e: crate::storage::Error) -> Self {
        // Storage errors are server-side; surface generically and log detail.
        Self::Internal(format!("storage: {e}"))
    }
}

impl IntoResponse for WebError {
    fn into_response(self) -> Response {
        let (status, heading, detail) = match self {
            Self::Internal(detail) => {
                error!(detail, "admin request failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Something went wrong",
                    "An internal error occurred. Check the server logs for details.".to_owned(),
                )
            }
            Self::BadRequest(msg) => (StatusCode::BAD_REQUEST, "Invalid request", msg),
            Self::NotFound(msg) => (StatusCode::NOT_FOUND, "Not found", msg),
        };
        (status, Html(error_page(status, heading, &detail))).into_response()
    }
}

/// Render a minimal, self-contained error page.
///
/// Deliberately built without Askama or a database read so it cannot fail
/// recursively while reporting a failure.
fn error_page(status: StatusCode, heading: &str, detail: &str) -> String {
    let code = status.as_u16();
    let detail = html_escape(detail);
    format!(
        "<!doctype html><html lang=\"en\" data-theme=\"auto\"><head>\
         <meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <meta name=\"color-scheme\" content=\"light dark\">\
         <link rel=\"icon\" type=\"image/png\" href=\"/assets/icon.png\">\
         <link rel=\"stylesheet\" href=\"/assets/pico.pumpkin.min.css\">\
         <link rel=\"stylesheet\" href=\"/assets/app.css\">\
         <title>{code} · sagittarius</title></head><body><main class=\"container\">\
         <article class=\"sgt-centered\"><hgroup><h1>{heading}</h1><p>{detail}</p></hgroup>\
         <a href=\"/\" role=\"button\" class=\"secondary\">Return to dashboard</a>\
         </article></main></body></html>"
    )
}

/// Minimal HTML-escaping for the few interpolated strings on the error page.
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_escape_escapes_metacharacters() {
        assert_eq!(
            html_escape("<a href=\"x\">&'"),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#x27;"
        );
    }

    #[tokio::test]
    async fn internal_error_is_500_and_generic() {
        let resp = WebError::internal("secret detail").into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&body);
        assert!(!body.contains("secret detail"), "detail must not leak");
        assert!(body.contains("Something went wrong"));
    }

    #[tokio::test]
    async fn bad_request_shows_escaped_message() {
        let resp = WebError::bad_request("bad <domain>").into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&body);
        assert!(body.contains("bad &lt;domain&gt;"));
    }
}
