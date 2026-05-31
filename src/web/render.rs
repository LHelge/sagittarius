//! Shared request-handling helpers: the [`WebError`] type that every admin
//! handler can return.
//!
//! Handlers map domain failures (storage errors, validation problems) into a
//! [`WebError`], which renders a small self-contained HTML error page styled
//! by the embedded assets.  Internal errors are logged and shown generically
//! so implementation detail never leaks to the browser; client errors show a
//! short, HTML-escaped message.

use std::convert::Infallible;

use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response, Sse, sse::Event},
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

/// Result alias for admin request handlers and their helpers.
///
/// Handlers return `WebResult<Response>` and use `?`; `WebError` implements
/// [`IntoResponse`] and `From<storage::Error>`, so axum renders the error and
/// storage failures convert automatically.
pub type WebResult<T> = std::result::Result<T, WebError>;

impl From<crate::storage::Error> for WebError {
    fn from(e: crate::storage::Error) -> Self {
        match e {
            // A rejected domain is a client input problem, not a server fault.
            crate::storage::Error::InvalidDomain(_) => Self::BadRequest(e.to_string()),
            other => Self::Internal(format!("storage: {other}")),
        }
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

/// Presentation helper for domain names shown in the admin UI.
///
/// Internally domains are kept in their canonical, fully-qualified form with a
/// trailing dot (the [`Name`](crate::codec::name::Name) normalization).  That
/// form is unconventional to show to a human, so the web layer strips the
/// trailing dot at the display boundary while leaving the stored value intact.
pub(crate) trait DomainDisplay {
    /// The domain without its canonical trailing dot, for human-facing display.
    ///
    /// The root zone (`"."`) is returned unchanged so it never renders blank.
    fn display_domain(&self) -> &str;
}

impl DomainDisplay for str {
    fn display_domain(&self) -> &str {
        match self.strip_suffix('.') {
            Some(stripped) if !stripped.is_empty() => stripped,
            _ => self,
        }
    }
}

/// Wrap one or more Datastar patch events into a one-shot SSE [`Response`].
///
/// Datastar's `@get`/`@post` actions expect a `text/event-stream` reply that
/// carries the patch events and then closes. This centralizes that wrapping for
/// the short, fire-once responses (toasts, scroll-back appends); the long-lived
/// streams (e.g. `/events`) build their own [`Sse`] directly.
pub(crate) fn datastar_response(events: Vec<Event>) -> Response {
    Sse::new(async_stream::stream! {
        for event in events {
            yield Ok::<Event, Infallible>(event);
        }
    })
    .into_response()
}

/// Minimal HTML-escaping for the few interpolated strings on the error page
/// and in dynamically-built fragments (e.g. the toast).
pub(crate) fn html_escape(s: &str) -> String {
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
    fn display_domain_strips_trailing_dot() {
        assert_eq!("ads.example.com.".display_domain(), "ads.example.com");
        // Already bare (or never normalized) names are untouched.
        assert_eq!("router.home.lan".display_domain(), "router.home.lan");
        // The root zone stays visible rather than rendering blank.
        assert_eq!(".".display_domain(), ".");
    }

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
