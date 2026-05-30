//! Authenticated admin access — Argon2id passwords, home-grown sessions, and
//! the cookie-security policy (SPEC §9, §11).
//!
//! # Passwords
//!
//! Passwords are hashed with **Argon2id** using the `argon2` crate's default
//! cost (the OWASP-recommended m = 19 MiB, t = 2, p = 1) and stored as PHC
//! strings.  Verification is constant-time via
//! [`argon2::password_hash::PasswordVerifier`] and reads the cost from each
//! stored PHC string.
//!
//! # Sessions
//!
//! A session is an opaque random id plus a separate 256-bit bearer token.  The
//! cookie carries `{id}.{token}`; the database stores only the SHA-256 hash of
//! the token, so a database read alone cannot mint a session.  Lookups locate
//! the row by id (the primary key) and then verify the token hash in constant
//! time.  Lifetimes are **idle 7 days** (rolling) and **absolute 30 days**.
//!
//! # Cookie security
//!
//! The `Secure` attribute and cookie name follow the operational
//! [`SessionCookieSecurePolicy`] (SPEC §9/§10):
//!
//! - `auto` — `Secure` + `__Host-sgt_session` when the browser-facing request
//!   is HTTPS (a trusted `X-Forwarded-Proto: https` from a reverse proxy);
//!   otherwise the unprefixed insecure cookie for direct plain-HTTP loopback use.
//! - `always` — always `Secure` + `__Host-sgt_session`.
//! - `never` — never `Secure`; unprefixed cookie.
//!
//! `X-Forwarded-Proto` is only meaningful behind a **trusted** reverse proxy;
//! direct public plain-HTTP exposure is not a safe deployment (SPEC §11).
//! `HttpOnly`, `SameSite=Strict`, and `Path=/` are always set, and the
//! `__Host-` prefix is only ever used together with `Secure` + `Path=/` + no
//! `Domain`, satisfying the browser prefix rules.

use std::time::{SystemTime, UNIX_EPOCH};

use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use axum::{
    extract::{FromRequestParts, State},
    http::{HeaderMap, header, request::Parts},
    response::{IntoResponse, Redirect, Response},
};
use rand::Rng;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tracing::warn;

use crate::{
    config::SessionCookieSecurePolicy,
    storage::{
        admin_users::{AdminUserRepository, SqliteAdminUserRepo},
        sessions::{NewSession, SessionRepository, SqliteSessionRepo},
    },
    web::{AppState, Chrome, origin, render::WebError},
};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Rolling idle lifetime: a session goes stale this long after its last use.
const IDLE_SECS: i64 = 7 * 24 * 3600;
/// Absolute lifetime: a session cannot live longer than this since creation.
const ABSOLUTE_SECS: i64 = 30 * 24 * 3600;
/// Only slide the idle-expiry forward (a DB write) when it would extend the
/// window by more than this, to avoid a write on every single request.
const RENEW_THRESHOLD_SECS: i64 = 3600;

/// Cookie name when `Secure` is set (browser `__Host-` prefix rules apply).
const COOKIE_SECURE: &str = "__Host-sgt_session";
/// Cookie name for direct plain-HTTP / loopback use (no prefix).
const COOKIE_INSECURE: &str = "sgt_session";

// ── Password hashing ────────────────────────────────────────────────────────

/// Build the Argon2id hasher.
///
/// Uses the crate default, which is Argon2id (v0x13) with the OWASP-recommended
/// cost (m = 19 MiB, t = 2, p = 1).  Verification reads the cost from each
/// stored PHC string, so existing hashes stay verifiable even if the default
/// changes in a future crate upgrade.
fn hasher() -> Argon2<'static> {
    Argon2::default()
}

/// Hash a plaintext password into an Argon2id PHC string.
pub fn hash_password(plain: &str) -> Result<String, WebError> {
    let mut salt_bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut salt_bytes);
    let salt = SaltString::encode_b64(&salt_bytes)
        .map_err(|e| WebError::internal(format!("salt encode: {e}")))?;
    let phc = hasher()
        .hash_password(plain.as_bytes(), &salt)
        .map_err(|e| WebError::internal(format!("password hash: {e}")))?;
    Ok(phc.to_string())
}

/// Verify a plaintext password against a stored PHC string (constant-time).
pub fn verify_password(plain: &str, phc: &str) -> bool {
    match PasswordHash::new(phc) {
        Ok(parsed) => hasher().verify_password(plain.as_bytes(), &parsed).is_ok(),
        Err(_) => false,
    }
}

/// A throwaway hash used to keep failed-login timing close to successful-login
/// timing when the username does not exist (avoids a user-enumeration oracle).
fn dummy_hash() -> &'static str {
    use std::sync::OnceLock;
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| {
        hash_password("timing-equalisation-placeholder").expect("hash dummy password")
    })
}

// ── Token / hashing helpers ───────────────────────────────────────────────────

/// Lowercase-hex encode a byte slice.
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

/// Generate `n` cryptographically random bytes as a hex string.
fn random_hex(n: usize) -> String {
    let mut buf = vec![0u8; n];
    rand::rng().fill_bytes(&mut buf);
    to_hex(&buf)
}

/// Hex SHA-256 of a string (used to hash the bearer token at rest).
fn sha256_hex(input: &str) -> String {
    to_hex(Sha256::digest(input.as_bytes()))
}

/// Constant-time string equality (length-independent only in the equal-length
/// case; differing lengths short-circuit, which is acceptable for fixed-width
/// hashes).
pub(crate) fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Current unix epoch in seconds.
fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

// ── Cookie policy ─────────────────────────────────────────────────────────────

/// Decide whether the session cookie should carry `Secure` for this request.
///
/// Shares the browser-facing scheme decision with the CSRF origin check via
/// [`origin::is_https`] so the two always agree behind a reverse proxy.
fn cookie_secure(policy: SessionCookieSecurePolicy, headers: &HeaderMap) -> bool {
    origin::is_https(policy, headers)
}

/// The cookie name to use for a given `Secure` decision.
fn cookie_name(secure: bool) -> &'static str {
    if secure {
        COOKIE_SECURE
    } else {
        COOKIE_INSECURE
    }
}

/// Build a `Set-Cookie` value installing the session for `max_age` seconds.
fn set_cookie(name: &str, value: &str, secure: bool, max_age: i64) -> String {
    let mut c = format!("{name}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}");
    if secure {
        c.push_str("; Secure");
    }
    c
}

/// Build a `Set-Cookie` value that clears the session cookie.
fn clear_cookie(name: &str, secure: bool) -> String {
    set_cookie(name, "", secure, 0)
}

/// Extract the `(id, token)` pair from the session cookie, if present.
pub(crate) fn read_cookie(headers: &HeaderMap) -> Option<(String, String)> {
    for raw in headers.get_all(header::COOKIE) {
        let Ok(s) = raw.to_str() else { continue };
        for pair in s.split(';') {
            let pair = pair.trim();
            let Some((name, value)) = pair.split_once('=') else {
                continue;
            };
            if name == COOKIE_SECURE || name == COOKIE_INSECURE {
                let (id, token) = value.split_once('.')?;
                return Some((id.to_owned(), token.to_owned()));
            }
        }
    }
    None
}

// ── Session lifecycle ─────────────────────────────────────────────────────────

/// The authenticated admin extracted from a valid session.
///
/// Used as an axum extractor to gate protected routes: when no valid session
/// is present the request is redirected to `/login`.
#[derive(Debug, Clone)]
pub struct CurrentUser {
    /// The owning admin user id.
    pub user_id: i64,
    /// The opaque session id (used to derive the session-bound CSRF token).
    pub session_id: String,
}

/// Resolve the current user from the request cookies, applying idle/absolute
/// expiry and sliding the idle window forward where warranted.  Returns `None`
/// for any missing, malformed, expired, or mismatched session.
pub(crate) async fn current_user(state: &AppState, headers: &HeaderMap) -> Option<CurrentUser> {
    let (id, token) = read_cookie(headers)?;
    let repo = SqliteSessionRepo::new(state.db.pool().clone());
    let session = repo.find(&id).await.ok()??;

    let now = now_epoch();
    // Idle and absolute expiry.
    if now >= session.expires_at || now >= session.created_at + ABSOLUTE_SECS {
        return None;
    }
    // Constant-time token check.
    if !ct_eq(&sha256_hex(&token), &session.token_hash) {
        return None;
    }

    // Slide the idle window forward (DB-only; the cookie Max-Age already spans
    // the absolute window). Throttled to avoid a write on every request.
    let new_expires = (now + IDLE_SECS).min(session.created_at + ABSOLUTE_SECS);
    if new_expires - session.expires_at > RENEW_THRESHOLD_SECS {
        let _ = repo.touch(&id, new_expires).await;
    }

    Some(CurrentUser {
        user_id: session.user_id,
        session_id: id,
    })
}

/// Create a session for `user_id` and return the `Set-Cookie` header value.
async fn begin_session(
    state: &AppState,
    headers: &HeaderMap,
    user_id: i64,
) -> Result<String, WebError> {
    let id = random_hex(16);
    let token = random_hex(32);
    let token_hash = sha256_hex(&token);
    let expires_at = now_epoch() + IDLE_SECS;

    SqliteSessionRepo::new(state.db.pool().clone())
        .insert(&NewSession {
            id: id.clone(),
            token_hash,
            user_id,
            expires_at,
        })
        .await
        .map_err(WebError::from)?;

    let secure = cookie_secure(state.cookie_policy, headers);
    let value = format!("{id}.{token}");
    Ok(set_cookie(
        cookie_name(secure),
        &value,
        secure,
        ABSOLUTE_SECS,
    ))
}

// ── CurrentUser extractor ─────────────────────────────────────────────────────

impl FromRequestParts<AppState> for CurrentUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        match current_user(state, &parts.headers).await {
            Some(user) => Ok(user),
            None => Err(Redirect::to("/login").into_response()),
        }
    }
}

// ── Login / logout handlers ─────────────────────────────────────────────────

/// Login form payload.
#[derive(Debug, Deserialize)]
pub struct LoginForm {
    username: String,
    password: String,
}

/// `GET /login` — render the login form, or bounce to `/` if already signed in.
pub async fn login_form(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if current_user(&state, &headers).await.is_some() {
        return Redirect::to("/").into_response();
    }
    LoginTemplate {
        chrome: state.bare_chrome().await,
        error: None,
    }
    .into_response()
}

/// `POST /login` — verify credentials and start a session on success.
pub async fn login_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Form(form): axum::Form<LoginForm>,
) -> Response {
    let repo = SqliteAdminUserRepo::new(state.db.pool().clone());
    let user = match repo.find_by_username(&form.username).await {
        Ok(u) => u,
        Err(e) => return WebError::from(e).into_response(),
    };

    // Verify against the real hash, or a dummy hash if the user is unknown, so
    // the two paths take comparable time (no user-enumeration timing oracle).
    let authenticated = match &user {
        Some(u) => verify_password(&form.password, &u.password_hash),
        None => {
            let _ = verify_password(&form.password, dummy_hash());
            false
        }
    };

    if !authenticated {
        return LoginTemplate {
            chrome: state.bare_chrome().await,
            error: Some("Invalid username or password.".to_owned()),
        }
        .into_response();
    }

    let user_id = user.expect("authenticated implies a user").id;
    match begin_session(&state, &headers, user_id).await {
        Ok(cookie) => ([(header::SET_COOKIE, cookie)], Redirect::to("/")).into_response(),
        Err(e) => e.into_response(),
    }
}

/// `POST /logout` — invalidate the current session and clear the cookie.
pub async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some((id, _token)) = read_cookie(&headers) {
        let _ = SqliteSessionRepo::new(state.db.pool().clone())
            .delete(&id)
            .await;
    }
    let secure = cookie_secure(state.cookie_policy, &headers);
    let cookie = clear_cookie(cookie_name(secure), secure);
    ([(header::SET_COOKIE, cookie)], Redirect::to("/login")).into_response()
}

// ── Templates ───────────────────────────────────────────────────────────────

use askama::Template;
use askama_web::WebTemplate;

/// The login page (bare layout, no navigation).
#[derive(Template, WebTemplate)]
#[template(path = "login.html")]
struct LoginTemplate {
    chrome: Chrome,
    error: Option<String>,
}

// ── Startup warning ───────────────────────────────────────────────────────────

/// Log a warning if the cookie policy is `never` while the admin interface is
/// bound to a non-loopback address (SPEC §9/§10: `never` is loopback-only).
pub fn warn_if_insecure(policy: SessionCookieSecurePolicy, admin_addr: std::net::SocketAddr) {
    if policy == SessionCookieSecurePolicy::Never && !admin_addr.ip().is_loopback() {
        warn!(
            %admin_addr,
            "session-cookie-secure=never on a non-loopback admin bind: session \
             cookies will be sent without Secure — use 'always' behind a TLS \
             reverse proxy, or bind loopback"
        );
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_then_verify_round_trips() {
        let phc = hash_password("correct horse battery staple").expect("hash");
        assert!(phc.starts_with("$argon2id$"), "PHC must be argon2id: {phc}");
        assert!(verify_password("correct horse battery staple", &phc));
        assert!(!verify_password("wrong password", &phc));
    }

    #[test]
    fn verify_rejects_garbage_hash() {
        assert!(!verify_password("anything", "not-a-phc-string"));
    }

    #[test]
    fn hashes_are_salted_and_distinct() {
        let a = hash_password("same").unwrap();
        let b = hash_password("same").unwrap();
        assert_ne!(a, b, "random salt must make hashes differ");
        assert!(verify_password("same", &a));
        assert!(verify_password("same", &b));
    }

    #[test]
    fn ct_eq_matches_str_eq() {
        assert!(ct_eq("abcdef", "abcdef"));
        assert!(!ct_eq("abcdef", "abcdeg"));
        assert!(!ct_eq("abc", "abcd"));
    }

    #[test]
    fn sha256_hex_is_stable_and_64_chars() {
        let h = sha256_hex("token");
        assert_eq!(h.len(), 64);
        assert_eq!(h, sha256_hex("token"));
        assert_ne!(h, sha256_hex("token2"));
    }

    #[test]
    fn random_hex_is_unique_and_right_length() {
        let a = random_hex(32);
        let b = random_hex(32);
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
    }

    #[test]
    fn cookie_secure_follows_policy() {
        let mut https = HeaderMap::new();
        https.insert("x-forwarded-proto", "https".parse().unwrap());
        let plain = HeaderMap::new();

        assert!(cookie_secure(SessionCookieSecurePolicy::Always, &plain));
        assert!(!cookie_secure(SessionCookieSecurePolicy::Never, &https));
        assert!(cookie_secure(SessionCookieSecurePolicy::Auto, &https));
        assert!(!cookie_secure(SessionCookieSecurePolicy::Auto, &plain));
    }

    #[test]
    fn cookie_name_matches_secure() {
        assert_eq!(cookie_name(true), "__Host-sgt_session");
        assert_eq!(cookie_name(false), "sgt_session");
    }

    #[test]
    fn set_cookie_includes_required_attributes() {
        let secure = set_cookie("__Host-sgt_session", "id.tok", true, 100);
        assert!(secure.contains("Path=/"));
        assert!(secure.contains("HttpOnly"));
        assert!(secure.contains("SameSite=Strict"));
        assert!(secure.contains("Max-Age=100"));
        assert!(secure.contains("; Secure"));

        let insecure = set_cookie("sgt_session", "id.tok", false, 100);
        assert!(!insecure.contains("Secure"));
    }

    #[test]
    fn read_cookie_parses_id_and_token() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "foo=bar; sgt_session=abc.def".parse().unwrap(),
        );
        let (id, token) = read_cookie(&headers).expect("cookie present");
        assert_eq!(id, "abc");
        assert_eq!(token, "def");
    }

    #[test]
    fn read_cookie_absent_is_none() {
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, "other=1".parse().unwrap());
        assert!(read_cookie(&headers).is_none());
    }
}
