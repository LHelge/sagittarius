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

use std::sync::OnceLock;

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
        admin_users::AdminUserRepository,
        sessions::{NewSession, SessionRepository},
    },
    time::Clock,
    web::{
        AppState, Chrome,
        crypto::{ConstantTimeEq, ToHex},
        origin,
        render::{WebError, WebResult},
    },
};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Rolling idle lifetime: a session goes stale this long after its last use.
const IDLE_SECS: i64 = crate::time::days(7).as_secs() as i64;
/// Absolute lifetime: a session cannot live longer than this since creation.
const ABSOLUTE_SECS: i64 = crate::time::days(30).as_secs() as i64;
/// Only slide the idle-expiry forward (a DB write) when it would extend the
/// window by more than this, to avoid a write on every single request.
const RENEW_THRESHOLD_SECS: i64 = 3600;

/// Cookie name when `Secure` is set (browser `__Host-` prefix rules apply).
const COOKIE_SECURE: &str = "__Host-sgt_session";
/// Cookie name for direct plain-HTTP / loopback use (no prefix).
const COOKIE_INSECURE: &str = "sgt_session";

// ── Password ──────────────────────────────────────────────────────────────────

/// An Argon2id-hashed password, stored and compared as a PHC string.
///
/// Hashing uses the `argon2` crate default (Argon2id v0x13, OWASP cost
/// m = 19 MiB / t = 2 / p = 1); verification reads the cost from the parsed PHC
/// string, so stored hashes stay verifiable across crate-default changes.
pub struct Password(String);

impl Password {
    /// Hash a plaintext password into a new [`Password`] (random per-hash salt).
    pub fn hash(plain: &str) -> WebResult<Self> {
        let mut salt_bytes = [0u8; 16];
        rand::rng().fill_bytes(&mut salt_bytes);
        let salt = SaltString::encode_b64(&salt_bytes)
            .map_err(|e| WebError::internal(format!("salt encode: {e}")))?;
        let phc = Self::hasher()
            .hash_password(plain.as_bytes(), &salt)
            .map_err(|e| WebError::internal(format!("password hash: {e}")))?;
        Ok(Self(phc.to_string()))
    }

    /// Wrap a PHC string already loaded from storage.
    pub fn from_phc(phc: String) -> Self {
        Self(phc)
    }

    /// Verify a plaintext candidate against this hash (constant-time).
    pub fn verify(&self, plain: &str) -> bool {
        match PasswordHash::new(&self.0) {
            Ok(parsed) => Self::hasher()
                .verify_password(plain.as_bytes(), &parsed)
                .is_ok(),
            Err(_) => false,
        }
    }

    /// The PHC string, for persisting to storage.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Build the Argon2id hasher (crate default cost).
    fn hasher() -> Argon2<'static> {
        Argon2::default()
    }

    /// A process-wide throwaway hash used to keep failed-login timing close to
    /// successful-login timing when the username does not exist (avoids a
    /// user-enumeration oracle).
    fn dummy() -> &'static Password {
        static DUMMY: OnceLock<Password> = OnceLock::new();
        DUMMY.get_or_init(|| {
            Password::hash("timing-equalisation-placeholder").expect("hash dummy password")
        })
    }
}

// ── SessionToken ────────────────────────────────────────────────────────────────

/// The opaque bearer token carried in the session cookie.
///
/// Only its [hash](SessionToken::hash) is stored server-side, so a database
/// read alone cannot mint a session.
pub(crate) struct SessionToken(String);

impl SessionToken {
    /// Number of random bytes behind a token (256-bit).
    const BYTES: usize = 32;

    /// Generate a fresh cryptographically random token.
    fn generate() -> Self {
        let mut buf = [0u8; Self::BYTES];
        rand::rng().fill_bytes(&mut buf);
        Self(buf.to_hex())
    }

    /// The hex SHA-256 of the token, as stored at rest.
    fn hash(&self) -> String {
        Sha256::digest(self.0.as_bytes()).to_hex()
    }

    /// Constant-time check that this token hashes to `stored_hash`.
    fn verify(&self, stored_hash: &str) -> bool {
        self.hash().as_str().ct_eq(stored_hash)
    }

    /// The raw token value, for embedding in the cookie.
    fn as_str(&self) -> &str {
        &self.0
    }
}

// ── SessionCookie ─────────────────────────────────────────────────────────────

/// The session cookie value: an opaque id plus the bearer token, wire-encoded
/// as `{id}.{token}`.  Owns parsing from request headers and rendering the
/// `Set-Cookie` header, including the `__Host-` prefix / `Secure` policy.
pub(crate) struct SessionCookie {
    /// Opaque random session id (the row primary key; safe to expose).
    pub(crate) id: String,
    /// The bearer token (secret).
    token: SessionToken,
}

impl SessionCookie {
    /// Number of random bytes behind the opaque session id.
    const ID_BYTES: usize = 16;

    /// Mint a brand-new session id + bearer token.
    fn issue() -> Self {
        let mut buf = [0u8; Self::ID_BYTES];
        rand::rng().fill_bytes(&mut buf);
        Self {
            id: buf.to_hex(),
            token: SessionToken::generate(),
        }
    }

    /// Parse the session cookie from request headers, if present and well-formed.
    pub(crate) fn from_headers(headers: &HeaderMap) -> Option<Self> {
        for raw in headers.get_all(header::COOKIE) {
            let Ok(s) = raw.to_str() else { continue };
            for pair in s.split(';') {
                let pair = pair.trim();
                let Some((name, value)) = pair.split_once('=') else {
                    continue;
                };
                if name == COOKIE_SECURE || name == COOKIE_INSECURE {
                    let (id, token) = value.split_once('.')?;
                    return Some(Self {
                        id: id.to_owned(),
                        token: SessionToken(token.to_owned()),
                    });
                }
            }
        }
        None
    }

    /// The cookie name to use for a given `Secure` decision.
    fn name(secure: bool) -> &'static str {
        if secure {
            COOKIE_SECURE
        } else {
            COOKIE_INSECURE
        }
    }

    /// Build a `Set-Cookie` value installing this session for `max_age` seconds.
    fn set_header(&self, secure: bool, max_age: i64) -> String {
        let value = format!("{}.{}", self.id, self.token.as_str());
        Self::attributes(Self::name(secure), &value, secure, max_age)
    }

    /// Build a `Set-Cookie` value that clears the session cookie.
    fn clear_header(secure: bool) -> String {
        Self::attributes(Self::name(secure), "", secure, 0)
    }

    /// Render the shared cookie attribute string.
    fn attributes(name: &str, value: &str, secure: bool, max_age: i64) -> String {
        let mut c = format!("{name}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}");
        if secure {
            c.push_str("; Secure");
        }
        c
    }

    /// Log a warning if the cookie policy is `never` while the admin interface
    /// is bound to a non-loopback address (SPEC §9/§10: `never` is loopback-only).
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
}

// ── CurrentUser ─────────────────────────────────────────────────────────────────

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

impl FromRequestParts<AppState> for CurrentUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        match state.current_user(&parts.headers).await {
            Some(user) => Ok(user),
            None => Err(Redirect::to("/login").into_response()),
        }
    }
}

// ── Session lifecycle + handlers (on AppState) ────────────────────────────────

impl AppState {
    /// Resolve the current user from the request cookies, applying idle/absolute
    /// expiry and sliding the idle window forward where warranted.  Returns
    /// `None` for any missing, malformed, expired, or mismatched session.
    pub(crate) async fn current_user(&self, headers: &HeaderMap) -> Option<CurrentUser> {
        let cookie = SessionCookie::from_headers(headers)?;
        let repo = self.db.sessions();
        let session = repo.find(&cookie.id).await.ok()??;

        let now = Clock::now_secs();
        // Idle and absolute expiry.
        if now >= session.expires_at || now >= session.created_at + ABSOLUTE_SECS {
            let _ = repo.delete(&cookie.id).await;
            let _ = repo.delete_expired(now).await;
            return None;
        }
        // Constant-time token check.
        if !cookie.token.verify(&session.token_hash) {
            return None;
        }

        // Slide the idle window forward (DB-only; the cookie Max-Age already
        // spans the absolute window). Throttled to avoid a write per request.
        let new_expires = (now + IDLE_SECS).min(session.created_at + ABSOLUTE_SECS);
        if new_expires - session.expires_at > RENEW_THRESHOLD_SECS {
            let _ = repo.touch(&cookie.id, new_expires).await;
        }

        Some(CurrentUser {
            user_id: session.user_id,
            session_id: cookie.id,
        })
    }

    /// Create a session for `user_id` and return the `Set-Cookie` header value.
    async fn begin_session(&self, headers: &HeaderMap, user_id: i64) -> WebResult<String> {
        let cookie = SessionCookie::issue();
        let expires_at = Clock::now_secs() + IDLE_SECS;

        self.db
            .sessions()
            .insert(&NewSession {
                id: cookie.id.clone(),
                token_hash: cookie.token.hash(),
                user_id,
                expires_at,
            })
            .await
            .map_err(WebError::from)?;

        let secure = origin::is_https(self.cookie_policy, headers);
        Ok(cookie.set_header(secure, ABSOLUTE_SECS))
    }

    /// `GET /login` — render the login form, or bounce to `/` if already signed in.
    pub async fn login_form(State(state): State<AppState>, headers: HeaderMap) -> Response {
        if state.current_user(&headers).await.is_some() {
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
    ) -> WebResult<Response> {
        let user = state
            .db
            .admin_users()
            .find_by_username(&form.username)
            .await?;

        // Verify against the real hash, or a dummy hash if the user is unknown,
        // so the two paths take comparable time (no user-enumeration oracle).
        let authenticated = match &user {
            Some(u) => Password::from_phc(u.password_hash.clone()).verify(&form.password),
            None => {
                let _ = Password::dummy().verify(&form.password);
                false
            }
        };

        if !authenticated {
            return Ok(LoginTemplate {
                chrome: state.bare_chrome().await,
                error: Some("Invalid username or password.".to_owned()),
            }
            .into_response());
        }

        let user_id = user.expect("authenticated implies a user").id;
        let cookie = state.begin_session(&headers, user_id).await?;
        Ok(([(header::SET_COOKIE, cookie)], Redirect::to("/")).into_response())
    }

    /// `POST /logout` — invalidate the current session and clear the cookie.
    pub async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
        if let Some(cookie) = SessionCookie::from_headers(&headers) {
            let _ = state.db.sessions().delete(&cookie.id).await;
        }
        let secure = origin::is_https(state.cookie_policy, &headers);
        let cookie = SessionCookie::clear_header(secure);
        ([(header::SET_COOKIE, cookie)], Redirect::to("/login")).into_response()
    }
}

// ── Login form + template ─────────────────────────────────────────────────────

/// Login form payload.
#[derive(Debug, Deserialize)]
pub struct LoginForm {
    username: String,
    password: String,
}

use askama::Template;
use askama_web::WebTemplate;

/// The login page (bare layout, no navigation).
#[derive(Template, WebTemplate)]
#[template(path = "login.html")]
struct LoginTemplate {
    chrome: Chrome,
    error: Option<String>,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_then_verify_round_trips() {
        let pw = Password::hash("correct horse battery staple").expect("hash");
        assert!(
            pw.as_str().starts_with("$argon2id$"),
            "PHC must be argon2id: {}",
            pw.as_str()
        );
        assert!(pw.verify("correct horse battery staple"));
        assert!(!pw.verify("wrong password"));
    }

    #[test]
    fn verify_rejects_garbage_hash() {
        assert!(!Password::from_phc("not-a-phc-string".to_owned()).verify("anything"));
    }

    #[test]
    fn hashes_are_salted_and_distinct() {
        let a = Password::hash("same").unwrap();
        let b = Password::hash("same").unwrap();
        assert_ne!(
            a.as_str(),
            b.as_str(),
            "random salt must make hashes differ"
        );
        assert!(a.verify("same"));
        assert!(b.verify("same"));
    }

    #[test]
    fn session_token_hash_is_stable_and_verifies() {
        let token = SessionToken::generate();
        let hash = token.hash();
        assert_eq!(hash.len(), 64, "hex SHA-256 is 64 chars");
        assert!(token.verify(&hash));
        assert!(!token.verify(&"0".repeat(64)));
        assert_ne!(
            token.as_str(),
            SessionToken::generate().as_str(),
            "tokens must be unique"
        );
    }

    #[test]
    fn cookie_name_matches_secure() {
        assert_eq!(SessionCookie::name(true), "__Host-sgt_session");
        assert_eq!(SessionCookie::name(false), "sgt_session");
    }

    #[test]
    fn set_header_includes_required_attributes() {
        let cookie = SessionCookie {
            id: "id".to_owned(),
            token: SessionToken("tok".to_owned()),
        };
        let secure = cookie.set_header(true, 100);
        assert!(secure.starts_with("__Host-sgt_session=id.tok"));
        assert!(secure.contains("Path=/"));
        assert!(secure.contains("HttpOnly"));
        assert!(secure.contains("SameSite=Strict"));
        assert!(secure.contains("Max-Age=100"));
        assert!(secure.contains("; Secure"));

        let insecure = cookie.set_header(false, 100);
        assert!(insecure.starts_with("sgt_session=id.tok"));
        assert!(!insecure.contains("Secure"));

        assert!(SessionCookie::clear_header(false).contains("Max-Age=0"));
    }

    #[test]
    fn from_headers_parses_id_and_token() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "foo=bar; sgt_session=abc.def".parse().unwrap(),
        );
        let cookie = SessionCookie::from_headers(&headers).expect("cookie present");
        assert_eq!(cookie.id, "abc");
        assert_eq!(cookie.token.as_str(), "def");
    }

    #[test]
    fn from_headers_absent_is_none() {
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, "other=1".parse().unwrap());
        assert!(SessionCookie::from_headers(&headers).is_none());
    }
}
