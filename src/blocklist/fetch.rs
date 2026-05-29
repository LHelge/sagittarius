//! HTTP fetcher with conditional-request support (SPEC §6, E7.1).
//!
//! [`Fetcher`] issues HTTP GET requests against blocklist source URLs and
//! applies RFC 7232 conditional-request headers (`If-None-Match`,
//! `If-Modified-Since`) to avoid redundant transfers when the remote content
//! has not changed.
//!
//! # Usage
//!
//! ```no_run
//! # use sagittarius::blocklist::fetch::{Fetcher, Validators, FetchOutcome};
//! # async fn example() -> Result<(), sagittarius::blocklist::fetch::FetchError> {
//! let fetcher = Fetcher::new();
//!
//! // First fetch — no validators yet.
//! let validators = Validators::default();
//! let outcome = fetcher.fetch("https://example.com/hosts.txt", &validators).await?;
//!
//! if let FetchOutcome::Modified { body, validators: new_validators } = outcome {
//!     // Persist body and new_validators for the next conditional request.
//!     println!("Fetched {} bytes", body.len());
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # TLS / crypto provider
//!
//! `reqwest` is compiled with the `rustls-no-provider` feature so that it
//! shares the same `ring`-backed `rustls::crypto::CryptoProvider` that hickory
//! installs for DoT/DoH transport.  [`Fetcher::new`] installs `ring` as the
//! process-wide default provider if no provider has been installed yet; this is
//! a no-op when hickory already did so.

use std::time::Duration;

use bytes::Bytes;
use reqwest::{
    StatusCode,
    header::{ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED},
};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Default per-request timeout.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Default maximum decompressed body size (64 MiB).
const DEFAULT_MAX_SIZE: usize = 64 * 1024 * 1024;

// ── Validators ────────────────────────────────────────────────────────────────

/// HTTP conditional-request validators stored from a previous successful fetch.
///
/// Passed to [`Fetcher::fetch`] to generate `If-None-Match` and
/// `If-Modified-Since` headers.  Both fields are `None` until the first
/// successful 200 response populates them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Validators {
    /// The `ETag` value returned by the previous 200 response.
    pub etag: Option<String>,
    /// The `Last-Modified` value returned by the previous 200 response.
    pub last_modified: Option<String>,
}

// ── FetchOutcome ──────────────────────────────────────────────────────────────

/// The outcome of a single [`Fetcher::fetch`] call.
#[derive(Debug)]
pub enum FetchOutcome {
    /// The server returned HTTP 200; the body and updated validators are
    /// included.
    Modified {
        /// Decompressed response body.
        body: Bytes,
        /// New validators parsed from the response headers; store these for
        /// the next conditional request.
        validators: Validators,
    },
    /// The server returned HTTP 304 — the previously cached content is still
    /// current.
    NotModified,
}

// ── FetchError ────────────────────────────────────────────────────────────────

/// Errors that can arise during a [`Fetcher::fetch`] call.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    /// The request could not be sent or the response could not be read.
    ///
    /// This variant wraps transient network errors and build-time
    /// misconfiguration (e.g. invalid URL).
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),

    /// The server returned an HTTP status code other than 200 or 304.
    #[error("unexpected HTTP status {0}")]
    UnexpectedStatus(StatusCode),

    /// The decompressed response body exceeded the configured size cap.
    ///
    /// The carried value is the configured limit in bytes.
    #[error("response body exceeds the {0}-byte size limit")]
    BodyTooLarge(usize),

    /// The per-request timeout elapsed before a complete response was received.
    #[error("request timed out")]
    Timeout,
}

// ── Fetcher ───────────────────────────────────────────────────────────────────

/// HTTP blocklist fetcher.
///
/// Holds one reused [`reqwest::Client`] and applies consistent timeout and
/// size-cap policies across all requests.  Cheap to clone (the inner
/// `reqwest::Client` is `Arc`-wrapped).
///
/// Build with [`Fetcher::new`] for production defaults or chain
/// [`Fetcher::with_timeout`] / [`Fetcher::with_max_size`] to override for
/// tests.
#[derive(Clone, Debug)]
pub struct Fetcher {
    client: reqwest::Client,
    max_size: usize,
}

impl Default for Fetcher {
    fn default() -> Self {
        Self::new()
    }
}

impl Fetcher {
    /// Construct a fetcher with the production defaults:
    /// - timeout: 30 s
    /// - max decompressed body size: 64 MiB
    ///
    /// Installs `ring` as the process-wide default rustls crypto provider if
    /// one has not already been installed (a no-op when hickory has already
    /// done so).
    pub fn new() -> Self {
        Self::build(DEFAULT_TIMEOUT, DEFAULT_MAX_SIZE)
    }

    /// Override the per-request timeout, consuming and returning `self`.
    ///
    /// Rebuilds the inner `reqwest::Client` so that the new timeout is applied
    /// to all subsequent requests.
    pub fn with_timeout(self, timeout: Duration) -> Self {
        Self::build(timeout, self.max_size)
    }

    /// Override the maximum decompressed body size cap (in bytes), consuming
    /// and returning `self`.
    ///
    /// The new limit is applied on the **next** call to [`Self::fetch`];
    /// no client rebuild is required.
    pub fn with_max_size(mut self, max_size: usize) -> Self {
        self.max_size = max_size;
        self
    }

    // ── private builder ───────────────────────────────────────────────────────

    /// Build the inner `reqwest::Client` with the given timeout.
    ///
    /// Uses `rustls-no-provider` — `ring` must have been installed as the
    /// default crypto provider before this is called.  We call
    /// `install_default()` here and silently ignore the error that occurs when
    /// a provider is already installed (e.g. by hickory).
    fn build(timeout: Duration, max_size: usize) -> Self {
        // Install ring as the default rustls crypto provider.  This is a
        // no-op when hickory (or any other crate) already called
        // `install_default()`; the `Err` is intentionally swallowed.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let client = reqwest::Client::builder()
            .timeout(timeout)
            // Gzip auto-decompression is enabled by the `gzip` feature flag on
            // the reqwest crate; the `ClientBuilder::gzip` call is still
            // required to activate it at the client level.
            .gzip(true)
            .build()
            .expect("reqwest::Client build should never fail with ring installed");

        Self { client, max_size }
    }

    // ── fetch ─────────────────────────────────────────────────────────────────

    /// Fetch `url` using a conditional GET when `validators` are present.
    ///
    /// - Sets `If-None-Match` from `validators.etag` when `Some`.
    /// - Sets `If-Modified-Since` from `validators.last_modified` when `Some`.
    /// - Returns [`FetchOutcome::NotModified`] on HTTP 304.
    /// - Returns [`FetchOutcome::Modified`] on HTTP 200 with the decompressed
    ///   body and the new validators parsed from the response headers.
    /// - Returns [`FetchError::BodyTooLarge`] if the decompressed body exceeds
    ///   [`Self::with_max_size`].
    /// - Returns [`FetchError::UnexpectedStatus`] for any other status code.
    ///
    /// # Errors
    ///
    /// Returns [`FetchError::Request`] on transport / build failures,
    /// [`FetchError::Timeout`] when the request exceeds the configured
    /// deadline, [`FetchError::UnexpectedStatus`] for unexpected HTTP status
    /// codes, and [`FetchError::BodyTooLarge`] when the decompressed body
    /// exceeds `max_size`.
    pub async fn fetch(
        &self,
        url: &str,
        validators: &Validators,
    ) -> Result<FetchOutcome, FetchError> {
        let mut builder = self.client.get(url);

        if let Some(etag) = &validators.etag {
            builder = builder.header(IF_NONE_MATCH, etag);
        }
        if let Some(last_modified) = &validators.last_modified {
            builder = builder.header(IF_MODIFIED_SINCE, last_modified);
        }

        let response = builder.send().await.map_err(|e| {
            if e.is_timeout() {
                FetchError::Timeout
            } else {
                FetchError::Request(e)
            }
        })?;

        match response.status() {
            StatusCode::NOT_MODIFIED => Ok(FetchOutcome::NotModified),

            StatusCode::OK => {
                // Parse validators from the response headers before consuming
                // the response body.
                let new_validators = Validators {
                    etag: response
                        .headers()
                        .get(ETAG)
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_owned),
                    last_modified: response
                        .headers()
                        .get(LAST_MODIFIED)
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_owned),
                };

                // Stream the body and enforce the decompressed size cap.
                // We do NOT trust Content-Length because it reflects the
                // *compressed* size; we must measure after gzip decompression.
                let mut accumulated = Vec::new();
                let mut response = response;
                while let Some(chunk) = response.chunk().await.map_err(FetchError::Request)? {
                    accumulated.extend_from_slice(&chunk);
                    if accumulated.len() > self.max_size {
                        return Err(FetchError::BodyTooLarge(self.max_size));
                    }
                }

                Ok(FetchOutcome::Modified {
                    body: Bytes::from(accumulated),
                    validators: new_validators,
                })
            }

            other => Err(FetchError::UnexpectedStatus(other)),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bytes::Bytes;
    use wiremock::matchers::{header, header_exists, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::{FetchError, FetchOutcome, Fetcher, Validators};

    // ── helpers ───────────────────────────────────────────────────────────────

    /// A fetcher with a short timeout (5 s) and default max-size for tests.
    fn test_fetcher() -> Fetcher {
        Fetcher::new().with_timeout(Duration::from_secs(5))
    }

    // ── 200 OK ────────────────────────────────────────────────────────────────

    /// A 200 response returns `Modified` with the body bytes and the ETag /
    /// Last-Modified values parsed from the response headers.
    #[tokio::test]
    async fn ok_200_returns_modified_with_body_and_validators() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/hosts.txt"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(b"0.0.0.0 ads.example.com\n".to_vec())
                    .insert_header("etag", r#""abc123""#)
                    .insert_header("last-modified", "Thu, 01 Jan 2026 00:00:00 GMT"),
            )
            .mount(&server)
            .await;

        let url = format!("{}/hosts.txt", server.uri());
        let outcome = test_fetcher()
            .fetch(&url, &Validators::default())
            .await
            .expect("fetch must succeed on 200");

        let FetchOutcome::Modified { body, validators } = outcome else {
            panic!("expected Modified, got NotModified");
        };

        assert_eq!(body, Bytes::from("0.0.0.0 ads.example.com\n"));
        assert_eq!(validators.etag.as_deref(), Some(r#""abc123""#));
        assert_eq!(
            validators.last_modified.as_deref(),
            Some("Thu, 01 Jan 2026 00:00:00 GMT")
        );
    }

    // ── 304 Not Modified ──────────────────────────────────────────────────────

    /// When the request carries a matching `If-None-Match`, the server returns
    /// 304 and the fetcher returns `NotModified`.  Also asserts that the
    /// `If-None-Match` header was actually sent.
    #[tokio::test]
    async fn conditional_get_304_returns_not_modified() {
        let server = MockServer::start().await;

        // Respond 304 only when the request carries the matching ETag.
        Mock::given(method("GET"))
            .and(path("/hosts.txt"))
            .and(header(
                reqwest::header::IF_NONE_MATCH.as_str(),
                r#""abc123""#,
            ))
            .respond_with(ResponseTemplate::new(304))
            .mount(&server)
            .await;

        let url = format!("{}/hosts.txt", server.uri());
        let validators = Validators {
            etag: Some(r#""abc123""#.to_owned()),
            last_modified: None,
        };
        let outcome = test_fetcher()
            .fetch(&url, &validators)
            .await
            .expect("fetch must succeed on 304");

        assert!(
            matches!(outcome, FetchOutcome::NotModified),
            "expected NotModified"
        );
    }

    /// Verify the `If-None-Match` header is actually sent by the fetcher when
    /// validators carry an ETag.
    #[tokio::test]
    async fn if_none_match_header_is_sent_when_etag_is_set() {
        let server = MockServer::start().await;

        // Only match when the If-None-Match header is present.
        Mock::given(method("GET"))
            .and(path("/hosts.txt"))
            .and(header_exists(reqwest::header::IF_NONE_MATCH.as_str()))
            .respond_with(ResponseTemplate::new(304))
            .mount(&server)
            .await;

        let url = format!("{}/hosts.txt", server.uri());
        let validators = Validators {
            etag: Some(r#""some-etag""#.to_owned()),
            last_modified: None,
        };

        // If the If-None-Match header is NOT sent, wiremock won't match the
        // mock and will return 404 instead, causing the fetch to error.
        test_fetcher()
            .fetch(&url, &validators)
            .await
            .expect("fetch should match the 304 mock, proving If-None-Match was sent");
    }

    // ── gzip decompression ────────────────────────────────────────────────────

    /// A gzip-compressed response body is transparently decompressed and the
    /// returned bytes equal the original plaintext content.
    #[tokio::test]
    async fn gzip_body_is_decompressed() {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write as _;

        let plaintext = b"0.0.0.0 tracker.example.org\n";

        // Gzip-compress the payload.
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(plaintext).unwrap();
        let compressed = encoder.finish().unwrap();

        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/hosts.txt"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(compressed)
                    .insert_header("content-encoding", "gzip"),
            )
            .mount(&server)
            .await;

        let url = format!("{}/hosts.txt", server.uri());
        let outcome = test_fetcher()
            .fetch(&url, &Validators::default())
            .await
            .expect("fetch must succeed");

        let FetchOutcome::Modified { body, .. } = outcome else {
            panic!("expected Modified");
        };

        assert_eq!(
            body.as_ref(),
            plaintext,
            "decompressed body must equal the original plaintext"
        );
    }

    // ── oversize body ─────────────────────────────────────────────────────────

    /// When the decompressed body exceeds the configured `max_size`, the
    /// fetcher returns `FetchError::BodyTooLarge` with the configured limit.
    #[tokio::test]
    async fn oversize_body_returns_body_too_large_error() {
        let server = MockServer::start().await;

        // 32 bytes of body content — larger than our 16-byte cap.
        let large_body = b"0.0.0.0 ads.example.com\n0.0.0.0 x\n";
        assert!(
            large_body.len() > 16,
            "test body must exceed the 16-byte cap"
        );

        Mock::given(method("GET"))
            .and(path("/hosts.txt"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(large_body.to_vec()))
            .mount(&server)
            .await;

        let url = format!("{}/hosts.txt", server.uri());
        let fetcher = Fetcher::new()
            .with_timeout(Duration::from_secs(5))
            .with_max_size(16);

        let result = fetcher.fetch(&url, &Validators::default()).await;

        assert!(
            matches!(result, Err(FetchError::BodyTooLarge(16))),
            "expected BodyTooLarge(16), got: {result:?}"
        );
    }

    // ── unexpected status ─────────────────────────────────────────────────────

    /// An HTTP 500 response surfaces as `FetchError::UnexpectedStatus`.
    #[tokio::test]
    async fn unexpected_status_500_returns_error() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/hosts.txt"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let url = format!("{}/hosts.txt", server.uri());
        let result = test_fetcher().fetch(&url, &Validators::default()).await;

        assert!(
            matches!(result, Err(FetchError::UnexpectedStatus(s)) if s.as_u16() == 500),
            "expected UnexpectedStatus(500), got: {result:?}"
        );
    }

    // ── validators default ────────────────────────────────────────────────────

    /// The `Default` implementation of `Validators` has both fields `None`.
    #[test]
    fn validators_default_is_all_none() {
        let v = Validators::default();
        assert!(v.etag.is_none());
        assert!(v.last_modified.is_none());
    }

    // ── 200 without validators in response ────────────────────────────────────

    /// A 200 response that carries neither ETag nor Last-Modified results in
    /// `Modified` with all-`None` validators.
    #[tokio::test]
    async fn ok_200_without_response_validators_yields_none_validators() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/hosts.txt"))
            .respond_with(
                ResponseTemplate::new(200).set_body_bytes(b"0.0.0.0 example.com\n".to_vec()),
            )
            .mount(&server)
            .await;

        let url = format!("{}/hosts.txt", server.uri());
        let outcome = test_fetcher()
            .fetch(&url, &Validators::default())
            .await
            .expect("fetch must succeed");

        let FetchOutcome::Modified { validators, .. } = outcome else {
            panic!("expected Modified");
        };

        assert!(validators.etag.is_none(), "etag must be None");
        assert!(
            validators.last_modified.is_none(),
            "last_modified must be None"
        );
    }
}
