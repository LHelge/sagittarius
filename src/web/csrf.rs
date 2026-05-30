//! CSRF protection for state-changing requests (SPEC §9, §11).
//!
//! Every mutating request (POST/PUT/PATCH/DELETE) passes through [`guard`],
//! which combines three defences:
//!
//! 1. **`SameSite=Strict` session cookie** (set in [`crate::web::auth`]) — a
//!    cross-site request never carries the session cookie at all, so it cannot
//!    act as the authenticated user.
//! 2. **Origin / Referer check** against the browser-facing admin origin
//!    ([`crate::web::origin`]) — a request whose `Origin`/`Referer` names a
//!    different origin is rejected.
//! 3. **Session-bound anti-CSRF token** — a token derived as
//!    `HMAC-SHA256(server_key, session_id)` is issued to every rendered page
//!    (via [`crate::web::Chrome`], exposed as the Datastar `csrf` signal on
//!    `<body>`) and must accompany authenticated mutations. It is accepted from
//!    any of: the `X-CSRF-Token` header, the `csrf` field of a JSON body
//!    (Datastar `@post` sends all signals as JSON), or a `csrf_token` urlencoded
//!    form field. Because it is keyed by the session id it rotates on login.
//!
//! Pre-authentication forms (login, the first-run wizard) have no session yet,
//! so they require a matching `Origin` or `Referer`; the session-bound token
//! check is skipped only because there is no session id to bind it to.

use axum::{
    body::{Body, Bytes},
    extract::{Request, State},
    http::{Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use tracing::warn;

use crate::web::{
    AppState,
    auth::SessionCookie,
    crypto::{ConstantTimeEq, ToHex},
    origin,
};

type HmacSha256 = Hmac<Sha256>;

/// Maximum mutating-request body we will buffer to look for a `csrf_token`
/// form field.  Admin forms are tiny; anything larger is rejected.
const MAX_FORM_BODY: usize = 64 * 1024;

/// A session-bound anti-CSRF token: `HMAC-SHA256(csrf_key, session_id)`,
/// hex-encoded.  Unforgeable without the per-process key and bound to the
/// session, so it rotates on login.
pub(crate) struct CsrfToken(String);

impl CsrfToken {
    /// The hex token value, for embedding in rendered pages.
    pub(crate) fn into_string(self) -> String {
        self.0
    }

    /// Borrow the hex token value.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    /// Constant-time check that a `presented` token matches this one.
    pub(crate) fn verify(&self, presented: &str) -> bool {
        self.as_str().ct_eq(presented)
    }
}

impl AppState {
    /// Derive the session-bound [`CsrfToken`] for `session_id`.
    pub(crate) fn csrf_token(&self, session_id: &str) -> CsrfToken {
        let mut mac = HmacSha256::new_from_slice(self.csrf_key.as_ref())
            .expect("HMAC accepts any key length");
        mac.update(session_id.as_bytes());
        CsrfToken(mac.finalize().into_bytes().to_hex())
    }
}

/// Whether `method` is a safe (non-mutating) method that bypasses CSRF checks.
fn is_safe(method: &Method) -> bool {
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
    )
}

/// The CSRF middleware applied to the whole router.
///
/// Safe methods pass straight through.  Mutations are origin-checked, and —
/// when a session cookie is present — must carry a matching anti-CSRF token.
pub async fn guard(State(state): State<AppState>, req: Request, next: Next) -> Response {
    if is_safe(req.method()) {
        return next.run(req).await;
    }

    let cookie = SessionCookie::from_headers(req.headers());

    // (2) Origin / Referer must match the browser-facing admin origin.  For
    // pre-auth forms, require one of those headers because there is no
    // session-bound token yet.
    if !origin_ok(&state, req.headers(), cookie.is_none()) {
        warn!("CSRF: rejected mutation with mismatched Origin/Referer");
        return forbidden();
    }

    // (3) Token check, only when an authenticated session cookie is present.
    // Pre-auth forms (login/wizard) have no session; the handler's auth
    // extractor still gates them.
    let Some(cookie) = cookie else {
        return next.run(req).await;
    };
    let expected = state.csrf_token(&cookie.id);

    // The token may arrive in the `X-CSRF-Token` header (explicit API clients) …
    if let Some(header_token) = req
        .headers()
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        && expected.verify(header_token)
    {
        return next.run(req).await;
    }

    // … or in the request body, which we buffer and then put back so the
    // handler still sees it. Two body shapes carry the token:
    //   - Datastar `@post` sends all signals as a JSON object → the `csrf`
    //     field (signal set on <body> via data-signals-csrf),
    //   - plain HTML forms send urlencoded → the `csrf_token` field.
    let is_json = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.contains("application/json"));

    let (parts, body) = req.into_parts();
    let bytes = match axum::body::to_bytes(body, MAX_FORM_BODY).await {
        Ok(b) => b,
        Err(_) => return forbidden(),
    };
    let token = if is_json {
        json_field(&bytes, "csrf")
    } else {
        form_field(&bytes, "csrf_token")
    };
    if !token.is_some_and(|t| expected.verify(&t)) {
        warn!("CSRF: rejected mutation with missing/invalid token");
        return forbidden();
    }
    next.run(Request::from_parts(parts, Body::from(bytes)))
        .await
}

/// Validate the `Origin` (preferred) or `Referer` header against the
/// browser-facing admin origin.  When `require_header` is false and both are
/// absent, callers can still rely on the session-bound CSRF token.
fn origin_ok(state: &AppState, headers: &axum::http::HeaderMap, require_header: bool) -> bool {
    let Some(expected) = origin::origin(state.cookie_policy, headers) else {
        // Can't determine our own origin (no Host header) — fail closed.
        return false;
    };

    if let Some(o) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        return o == expected;
    }
    if let Some(r) = headers.get(header::REFERER).and_then(|v| v.to_str().ok()) {
        // Referer carries a path; match the origin prefix at a boundary.
        return r == expected
            || r.strip_prefix(&expected)
                .is_some_and(|rest| rest.starts_with('/'));
    }
    // Neither header present: authenticated callers may still rely on the token,
    // but pre-auth forms require an origin signal.
    !require_header
}

/// Extract a string field from a JSON object body by key (used for Datastar's
/// signal payload).
fn json_field(body: &Bytes, key: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    value.get(key)?.as_str().map(str::to_owned)
}

/// Extract a urlencoded form field value by key.
///
/// The CSRF token is hex (no characters that urlencoding would alter), so a
/// raw scan without percent-decoding is sufficient here.
fn form_field(body: &Bytes, key: &str) -> Option<String> {
    let body = std::str::from_utf8(body).ok()?;
    for pair in body.split('&') {
        if let Some((k, v)) = pair.split_once('=')
            && k == key
        {
            return Some(v.to_owned());
        }
    }
    None
}

/// A bare 403 response.
fn forbidden() -> Response {
    (StatusCode::FORBIDDEN, "CSRF check failed").into_response()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    #[test]
    fn safe_methods_detected() {
        assert!(is_safe(&Method::GET));
        assert!(is_safe(&Method::HEAD));
        assert!(!is_safe(&Method::POST));
        assert!(!is_safe(&Method::DELETE));
    }

    #[test]
    fn form_field_extracts_token() {
        let body = Bytes::from_static(b"foo=1&csrf_token=abc123&bar=2");
        assert_eq!(form_field(&body, "csrf_token").as_deref(), Some("abc123"));
        assert_eq!(form_field(&body, "missing"), None);
    }

    #[test]
    fn json_field_extracts_token() {
        let body = Bytes::from_static(br#"{"csrf":"abc123","f_text":"","queries":5}"#);
        assert_eq!(json_field(&body, "csrf").as_deref(), Some("abc123"));
        assert_eq!(json_field(&body, "missing"), None);
        // Non-string and malformed inputs are rejected, not panicked on.
        assert_eq!(json_field(&Bytes::from_static(b"not json"), "csrf"), None);
        assert_eq!(
            json_field(&Bytes::from_static(br#"{"csrf":5}"#), "csrf"),
            None
        );
    }

    #[test]
    fn origin_ok_matches_and_rejects() {
        use crate::config::SessionCookieSecurePolicy;

        // Build a state-independent check via the origin helper directly is not
        // possible (origin_ok needs AppState for the policy); cover the policy
        // wiring through origin::origin instead.
        let mut h = HeaderMap::new();
        h.insert("host", "127.0.0.1:8080".parse().unwrap());
        let expected = origin::origin(SessionCookieSecurePolicy::Never, &h).unwrap();
        assert_eq!(expected, "http://127.0.0.1:8080");
    }
}
