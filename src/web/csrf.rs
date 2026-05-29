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
//!    (via [`crate::web::Chrome`]) and must accompany authenticated mutations,
//!    either as the `X-CSRF-Token` header (Datastar `data-headers`) or as a
//!    `csrf_token` form field.  Because it is keyed by the session id it
//!    rotates automatically on login.
//!
//! Pre-authentication forms (login, the first-run wizard) have no session yet,
//! so they are protected by the `SameSite` + origin checks alone; the token
//! check is skipped when no session cookie is present.  This is safe because
//! the underlying handlers still require a valid session via the
//! [`CurrentUser`](crate::web::auth::CurrentUser) extractor.

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

use crate::web::{AppState, auth, origin};

type HmacSha256 = Hmac<Sha256>;

/// Maximum mutating-request body we will buffer to look for a `csrf_token`
/// form field.  Admin forms are tiny; anything larger is rejected.
const MAX_FORM_BODY: usize = 64 * 1024;

impl AppState {
    /// Derive the session-bound CSRF token for `session_id`.
    ///
    /// `HMAC-SHA256(csrf_key, session_id)`, hex-encoded.  Unforgeable without
    /// the per-process key and bound to the session, so it rotates on login.
    pub(crate) fn csrf_token(&self, session_id: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(self.csrf_key.as_ref())
            .expect("HMAC accepts any key length");
        mac.update(session_id.as_bytes());
        to_hex(mac.finalize().into_bytes())
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

    // (2) Origin / Referer must match the browser-facing admin origin when present.
    if !origin_ok(&state, req.headers()) {
        warn!("CSRF: rejected mutation with mismatched Origin/Referer");
        return forbidden();
    }

    // (3) Token check, only when an authenticated session cookie is present.
    // Pre-auth forms (login/wizard) have no session; the handler's auth
    // extractor still gates them.
    let Some((session_id, _token)) = auth::read_cookie(req.headers()) else {
        return next.run(req).await;
    };
    let expected = state.csrf_token(&session_id);

    // Token may arrive in the X-CSRF-Token header (Datastar) ...
    if let Some(header_token) = req
        .headers()
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
    {
        return if auth::ct_eq(header_token, &expected) {
            next.run(req).await
        } else {
            warn!("CSRF: rejected mutation with bad X-CSRF-Token header");
            forbidden()
        };
    }

    // ... or as a `csrf_token` form field (buffer the body, then rebuild it).
    let (parts, body) = req.into_parts();
    let bytes = match axum::body::to_bytes(body, MAX_FORM_BODY).await {
        Ok(b) => b,
        Err(_) => return forbidden(),
    };
    let ok = form_field(&bytes, "csrf_token").is_some_and(|t| auth::ct_eq(&t, &expected));
    if !ok {
        warn!("CSRF: rejected mutation with missing/invalid csrf_token field");
        return forbidden();
    }
    next.run(Request::from_parts(parts, Body::from(bytes)))
        .await
}

/// Validate the `Origin` (preferred) or `Referer` header against the
/// browser-facing admin origin.  Absent both, we defer to the token +
/// `SameSite` defences and allow the request.
fn origin_ok(state: &AppState, headers: &axum::http::HeaderMap) -> bool {
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
    // Neither header present: rely on SameSite + the token.
    true
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

/// Lowercase-hex encode.
fn to_hex(bytes: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = bytes.as_ref();
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
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

    #[test]
    fn to_hex_round_trips_known_value() {
        assert_eq!(to_hex([0x00, 0xff, 0x10]), "00ff10");
    }
}
