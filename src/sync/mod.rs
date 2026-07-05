//! Secondary/fallback config mirroring (SPEC §13).
//!
//! A **secondary** instance mirrors a **primary**'s configuration over the
//! primary's read-only, API-key-authenticated config-sync API, while keeping
//! all hot-path-local state (DNS cache, aggregated blocklist set, query log)
//! local.  See the plan for the full design.
//!
//! # Sub-modules
//!
//! - [`dto`] — the wire contract: a [`dto::ConfigSnapshot`] of the mirror-worthy
//!   configuration, plus its content-hash version.  Shared by the primary
//!   (serialize, in [`crate::web::sync`]) and the secondary (deserialize + apply,
//!   the syncer).
//! - [`apply`] — the applier: writes a snapshot through to the local SQLite and
//!   swaps the live in-memory state via the same seams the web handlers use.

pub mod apply;
pub mod dto;

// ── SyncError ─────────────────────────────────────────────────────────────────

/// Errors that can occur while fetching or applying a config snapshot.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    /// The HTTP request to the primary failed (network, TLS, connect, …).
    #[error("config-sync request failed: {0}")]
    Http(#[from] reqwest::Error),

    /// The primary returned a status other than 200 or 304.
    #[error("primary returned unexpected status {0}")]
    UnexpectedStatus(reqwest::StatusCode),

    /// The response body could not be decoded into a [`dto::ConfigSnapshot`], or
    /// a field within it could not be parsed.
    #[error("could not decode config snapshot: {0}")]
    Decode(String),

    /// A storage error occurred while applying the snapshot.
    #[error("storage error while applying config: {0}")]
    Storage(#[from] crate::storage::Error),

    /// A live-state swap (reload / rebuild) failed while applying the snapshot.
    #[error("failed to apply config: {0}")]
    Apply(String),
}

// ── ConfigSyncer ──────────────────────────────────────────────────────────────

use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::{sync::dto::ConfigSnapshot, web::AppState};

/// How often a secondary polls the primary for configuration changes.
const POLL_INTERVAL: Duration = Duration::from_secs(60);

/// Per-request timeout for the config-sync fetch.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The relative path of the primary's config-sync endpoint.
const CONFIG_PATH: &str = "/api/v1/config";

/// The outcome of a single [`ConfigSyncer::sync_once`] tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncOutcome {
    /// The primary returned a new snapshot which was applied; carries the new
    /// content version.
    Applied(String),
    /// The primary reported the config unchanged (HTTP 304).
    NotModified,
}

/// The secondary-side config-sync client (SPEC §13).
///
/// Polls the primary's `GET /api/v1/config`, and on a change applies the
/// snapshot to the local instance via [`AppState::apply_config_snapshot`].  When
/// the primary is unreachable it keeps the last-good configuration — the whole
/// point of a fallback — so only a valid `200` ever mutates local state.
pub struct ConfigSyncer {
    app: AppState,
    client: reqwest::Client,
    /// Full URL of the primary's config endpoint.
    config_url: String,
    /// Bearer key (`{id}.{token}`) for the primary's API.
    api_key: String,
    /// The content version last successfully applied; sent as `If-None-Match`.
    last_version: Option<String>,
}

impl ConfigSyncer {
    /// Construct a syncer targeting `primary_url` (no trailing slash) with
    /// `api_key`, applying changes into `app`.
    ///
    /// Builds a `reqwest` client mirroring [`crate::blocklist::fetch::Fetcher`]
    /// (installs `ring` as the default rustls provider if none is set; 30 s
    /// timeout).
    #[must_use]
    pub fn new(app: AppState, primary_url: &str, api_key: &str) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .gzip(true)
            .build()
            .expect("reqwest::Client build should never fail with ring installed");

        Self {
            app,
            client,
            config_url: format!("{primary_url}{CONFIG_PATH}"),
            api_key: api_key.to_owned(),
            last_version: None,
        }
    }

    /// Perform one poll → apply cycle.
    ///
    /// Returns [`SyncOutcome::NotModified`] on a 304, or
    /// [`SyncOutcome::Applied`] after a new snapshot has been persisted and
    /// swapped live.  `last_version` is advanced **only** after a successful
    /// apply, so a transient failure re-fetches and retries next tick.
    pub async fn sync_once(&mut self) -> Result<SyncOutcome, SyncError> {
        let mut req = self.client.get(&self.config_url).bearer_auth(&self.api_key);
        if let Some(version) = &self.last_version {
            req = req.header(reqwest::header::IF_NONE_MATCH, format!("\"{version}\""));
        }

        let resp = req.send().await?;
        match resp.status() {
            reqwest::StatusCode::OK => {
                let etag = resp
                    .headers()
                    .get(reqwest::header::ETAG)
                    .and_then(|v| v.to_str().ok())
                    .map(strip_etag_quotes);
                let body = resp.bytes().await?;
                let snapshot: ConfigSnapshot =
                    serde_json::from_slice(&body).map_err(|e| SyncError::Decode(e.to_string()))?;

                self.app.apply_config_snapshot(&snapshot).await?;

                // Advance the version only after a successful apply.
                let version = etag.unwrap_or_else(|| snapshot.version());
                self.last_version = Some(version.clone());
                Ok(SyncOutcome::Applied(version))
            }
            reqwest::StatusCode::NOT_MODIFIED => Ok(SyncOutcome::NotModified),
            other => Err(SyncError::UnexpectedStatus(other)),
        }
    }

    /// Run the syncer until `token` is cancelled.
    ///
    /// Syncs immediately on startup, then every [`POLL_INTERVAL`].  A failed
    /// tick is logged and the last-good configuration is retained; the loop
    /// keeps polling so the secondary recovers automatically once the primary
    /// returns.
    pub async fn run(mut self, token: CancellationToken) {
        info!(url = %self.config_url, "config-sync started");
        self.tick().await;

        loop {
            tokio::select! {
                () = tokio::time::sleep(POLL_INTERVAL) => self.tick().await,
                () = token.cancelled() => {
                    info!("config-sync shutting down");
                    break;
                }
            }
        }
    }

    /// One tick with logging of the outcome (never propagates errors — a
    /// secondary must keep serving from its last-good config).
    async fn tick(&mut self) {
        match self.sync_once().await {
            Ok(SyncOutcome::Applied(version)) => {
                info!(version = %version, "config-sync applied a new snapshot");
            }
            Ok(SyncOutcome::NotModified) => {
                tracing::debug!("config-sync: primary config unchanged");
            }
            Err(e) => {
                warn!(error = %e, "config-sync failed; keeping last-good configuration");
            }
        }
    }
}

/// Strip the optional weak prefix and surrounding quotes from an `ETag` value,
/// yielding the bare content version.
fn strip_etag_quotes(etag: &str) -> String {
    etag.trim()
        .trim_start_matches("W/")
        .trim_matches('"')
        .to_owned()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        codec::name::Name,
        storage::{api_keys::ApiKeyRepository, lists::BlacklistRepository},
        web::{AdminServer, auth::MintedApiKey},
    };

    #[test]
    fn strip_etag_quotes_handles_weak_and_bare() {
        assert_eq!(strip_etag_quotes("\"abc\""), "abc");
        assert_eq!(strip_etag_quotes("W/\"abc\""), "abc");
        assert_eq!(strip_etag_quotes("abc"), "abc");
    }

    /// End-to-end: a change on a live primary reaches the secondary's live
    /// state; a second poll is a no-op (304); a wrong key errors.
    #[tokio::test]
    async fn syncer_mirrors_primary_changes_and_conditional_polls() {
        // ── Primary: seed a blacklist entry + mint an API key, then serve. ──────
        let (_pdir, pdb) = crate::test_support::temp_db().await;
        pdb.blacklist().add("ads.example.com").await.unwrap();
        let primary = AppState::for_test(pdb).await;
        let primary_handle = primary.clone(); // to mutate config after binding
        let minted = MintedApiKey::mint("secondary");
        let key = minted.plaintext.clone();
        primary.db.api_keys().insert(&minted.row).await.unwrap();

        let server = AdminServer::bind("127.0.0.1:0".parse().unwrap(), primary)
            .await
            .unwrap();
        let base = format!("http://{}", server.local_addr().unwrap());
        let token = CancellationToken::new();
        let token2 = token.clone();
        let handle = tokio::spawn(async move { server.serve(token2).await });

        // ── Secondary: its own empty DB + a syncer pointed at the primary. ──────
        let (_sdir, sdb) = crate::test_support::temp_db().await;
        let secondary = AppState::for_test(sdb).await;
        let mut syncer = ConfigSyncer::new(secondary.clone(), &base, &key);

        // First sync applies the primary's config.
        let outcome = syncer.sync_once().await.expect("first sync");
        assert!(matches!(outcome, SyncOutcome::Applied(_)));
        let ads: Name = "ads.example.com".parse().unwrap();
        assert!(
            secondary.resolver.blacklist().contains(&ads),
            "the secondary's live blacklist must mirror the primary"
        );

        // Second sync with an unchanged primary is a no-op (304).
        assert_eq!(
            syncer.sync_once().await.expect("second sync"),
            SyncOutcome::NotModified
        );

        // A change on the primary propagates on the next sync.
        primary_handle
            .db
            .blacklist()
            .add("tracker.evil.net")
            .await
            .unwrap();
        assert!(matches!(
            syncer.sync_once().await.expect("third sync"),
            SyncOutcome::Applied(_)
        ));
        let tracker: Name = "tracker.evil.net".parse().unwrap();
        assert!(secondary.resolver.blacklist().contains(&tracker));

        // A wrong key is rejected (401 → UnexpectedStatus).
        let mut bad = ConfigSyncer::new(secondary.clone(), &base, "wrong.key");
        assert!(matches!(
            bad.sync_once().await,
            Err(SyncError::UnexpectedStatus(_))
        ));

        token.cancel();
        tokio::time::timeout(std::time::Duration::from_secs(5), handle)
            .await
            .expect("shutdown")
            .expect("task");
    }
}
