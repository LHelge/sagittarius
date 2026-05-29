//! Browser-facing scheme/host derivation, shared by the cookie-`Secure`
//! decision ([`crate::web::auth`]) and the CSRF origin check
//! ([`crate::web::csrf`]).
//!
//! Keeping both consumers on the same helper guarantees they agree on what the
//! browser-facing origin is — important behind a TLS-terminating reverse proxy
//! where the wire connection is plain HTTP but the user-facing scheme is HTTPS.
//!
//! # Trust model
//!
//! `X-Forwarded-Proto` / `X-Forwarded-Host` are only meaningful behind a
//! **trusted** reverse proxy (SPEC §9/§11).  Sagittarius binds loopback by
//! default and is documented to run behind such a proxy for any remote access;
//! direct public plain-HTTP exposure is explicitly not a safe deployment, so
//! honouring these headers here matches the documented topology.

use axum::http::HeaderMap;

use crate::config::SessionCookieSecurePolicy;

/// Whether the browser-facing request is HTTPS, per the cookie policy.
///
/// - `Always` → always `true`
/// - `Never` → always `false`
/// - `Auto` → `true` only when a trusted `X-Forwarded-Proto: https` is present
///   (there is no built-in TLS in v0.1, so a direct connection is plain HTTP).
pub fn is_https(policy: SessionCookieSecurePolicy, headers: &HeaderMap) -> bool {
    match policy {
        SessionCookieSecurePolicy::Always => true,
        SessionCookieSecurePolicy::Never => false,
        SessionCookieSecurePolicy::Auto => headers
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .map(first_csv)
            .is_some_and(|s| s.eq_ignore_ascii_case("https")),
    }
}

/// The browser-facing host (`host[:port]`), preferring a trusted
/// `X-Forwarded-Host` over the request `Host` header.
pub fn host(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-forwarded-host")
        .or_else(|| headers.get(axum::http::header::HOST))
        .and_then(|v| v.to_str().ok())
        .map(|s| first_csv(s).to_owned())
}

/// The browser-facing origin (`scheme://host[:port]`), or `None` if the host
/// cannot be determined.
pub fn origin(policy: SessionCookieSecurePolicy, headers: &HeaderMap) -> Option<String> {
    let scheme = if is_https(policy, headers) {
        "https"
    } else {
        "http"
    };
    host(headers).map(|h| format!("{scheme}://{h}"))
}

/// Take the first entry of a possibly comma-separated proxy header value and
/// trim surrounding whitespace (proxies may append multiple hops).
fn first_csv(s: &str) -> &str {
    s.split(',').next().unwrap_or(s).trim()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(*k, v.parse().unwrap());
        }
        h
    }

    #[test]
    fn is_https_follows_policy() {
        let xfp = headers(&[("x-forwarded-proto", "https")]);
        let plain = HeaderMap::new();
        assert!(is_https(SessionCookieSecurePolicy::Always, &plain));
        assert!(!is_https(SessionCookieSecurePolicy::Never, &xfp));
        assert!(is_https(SessionCookieSecurePolicy::Auto, &xfp));
        assert!(!is_https(SessionCookieSecurePolicy::Auto, &plain));
    }

    #[test]
    fn host_prefers_forwarded() {
        let h = headers(&[
            ("host", "internal:8080"),
            ("x-forwarded-host", "dns.example.com"),
        ]);
        assert_eq!(host(&h).as_deref(), Some("dns.example.com"));

        let h = headers(&[("host", "localhost:8080")]);
        assert_eq!(host(&h).as_deref(), Some("localhost:8080"));
    }

    #[test]
    fn origin_combines_scheme_and_host() {
        let h = headers(&[
            ("host", "internal"),
            ("x-forwarded-host", "dns.example.com"),
            ("x-forwarded-proto", "https"),
        ]);
        assert_eq!(
            origin(SessionCookieSecurePolicy::Auto, &h).as_deref(),
            Some("https://dns.example.com")
        );

        let h = headers(&[("host", "127.0.0.1:8080")]);
        assert_eq!(
            origin(SessionCookieSecurePolicy::Never, &h).as_deref(),
            Some("http://127.0.0.1:8080")
        );
    }

    #[test]
    fn first_csv_takes_first_hop() {
        assert_eq!(first_csv("https, http"), "https");
        assert_eq!(first_csv("a.example , b"), "a.example");
        assert_eq!(first_csv("solo"), "solo");
    }
}
