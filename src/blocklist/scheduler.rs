//! Blocklist refresh scheduler — periodic fetch → parse → aggregate cycle
//! (SPEC §6, E7.4).
//!
//! [`BlocklistScheduler`] orchestrates the full lifecycle of external blocklist
//! sources: it runs an **offline-cache warm-up** at startup (no network) and
//! then drives a **periodic refresh** loop that fetches, parses, and atomically
//! installs an updated [`MatchSet`] into the shared [`ResolverState`].
//!
//! # Pipeline
//!
//! ```text
//! ┌──────────────┐   load_cache   ┌──────────────┐   parse   ┌───────────┐   install
//! │   storage    │ ─────────────► │  aggregate   │ ────────► │ matchset  │ ──────────►
//! └──────────────┘                └──────────────┘           └───────────┘
//!
//! ┌──────────────┐   HTTP GET     ┌──────────────┐   parse   ┌───────────┐   install
//! │   fetcher    │ ─────────────► │  aggregate   │ ────────► │ matchset  │ ──────────►
//! └──────────────┘                └──────────────┘           └───────────┘
//! ```
//!
//! # Resilience
//!
//! A transient network failure for one source will **not** clear that source
//! from the live set.  The scheduler falls back to the previously cached body
//! so the active blocklist retains its last-good snapshot.  Only a source that
//! has never been successfully fetched *and* has no cached content contributes
//! nothing.
//!
//! # Interval live-updates
//!
//! The refresh interval is re-read from [`ResolverState::settings`] at the
//! start of every sleep, so a settings change made via E8 takes effect at the
//! next cycle boundary.  E8 may also fire the [`RefreshTrigger`] immediately
//! after changing the interval to apply the new value without waiting.

use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::{
    blocklist::{
        aggregate::Aggregator,
        fetch::{FetchOutcome, Fetcher, Validators},
        parse::{BlocklistParser as _, Parser},
    },
    resolver::state::ResolverState,
    storage::blocklists::{BlocklistRepository, RefreshMetadata, SqliteBlocklistRepo},
};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Minimum enforced refresh interval.
///
/// Even if `blocklist_refresh_interval` is set to 0 (or a very small value)
/// in the settings row, the scheduler clamps to this floor so a misconfigured
/// value cannot create a busy-loop.
const MIN_INTERVAL: Duration = Duration::from_secs(60);

// ── RefreshSummary ────────────────────────────────────────────────────────────

/// Summary of a single completed refresh cycle.
///
/// Returned by [`BlocklistScheduler::refresh_once`] for logging and test
/// assertions.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RefreshSummary {
    /// Number of sources that returned HTTP 200 with new content.
    pub fetched: usize,
    /// Number of sources that returned HTTP 304 (content unchanged).
    pub not_modified: usize,
    /// Number of sources that encountered a fetch or parse error.
    pub failed: usize,
    /// Total unique domains installed into the live set after aggregation.
    pub total_domains: usize,
}

// ── RefreshError ──────────────────────────────────────────────────────────────

/// Hard errors that abort an entire refresh cycle.
///
/// Per-source fetch / parse failures are handled internally (logged as
/// warnings; the source falls back to its cached body) and are **not** this
/// error.  Only a failure to enumerate the enabled sources is treated as a
/// cycle-level error.
#[derive(Debug, thiserror::Error)]
pub enum RefreshError {
    /// The storage layer failed to list enabled blocklist sources.
    ///
    /// This is the only hard error — all per-source failures are resilient.
    #[error("failed to list enabled blocklist sources: {0}")]
    Storage(#[from] crate::storage::Error),
}

// ── RefreshTrigger ────────────────────────────────────────────────────────────

/// An on-demand trigger that fires an immediate refresh of the blocklist set.
///
/// Obtained via [`BlocklistScheduler::trigger`].  Cheap to clone.
///
/// E8's "refresh now" button will hold one of these and call
/// [`RefreshTrigger::trigger`] when the user presses it.
#[derive(Debug, Clone)]
pub struct RefreshTrigger(Arc<Notify>);

impl RefreshTrigger {
    /// Request an immediate out-of-schedule refresh.
    ///
    /// If the scheduler is currently busy with a refresh the notification is
    /// stored and the next `notified()` call will see it without losing the
    /// trigger.
    pub fn trigger(&self) {
        self.0.notify_one();
    }
}

// ── BlocklistScheduler ────────────────────────────────────────────────────────

/// Background blocklist refresh scheduler.
///
/// Created once at startup, after [`ResolverState::hydrate`].  Call
/// [`load_from_cache`](Self::load_from_cache) *before* starting the DNS
/// listeners to ensure the blocklist is populated from the offline cache
/// without a network round-trip.  Then pass `run` to a
/// [`tokio_util::task::TaskTracker`] as the long-lived background task.
pub struct BlocklistScheduler {
    repo: SqliteBlocklistRepo,
    state: Arc<ResolverState>,
    fetcher: Fetcher,
    /// Shared `Notify` between the scheduler loop and any `RefreshTrigger`s.
    notify: Arc<Notify>,
}

impl BlocklistScheduler {
    /// Construct a new scheduler.
    ///
    /// No I/O is performed here — call [`load_from_cache`](Self::load_from_cache)
    /// and then [`run`](Self::run) to start work.
    pub fn new(repo: SqliteBlocklistRepo, state: Arc<ResolverState>, fetcher: Fetcher) -> Self {
        Self {
            repo,
            state,
            fetcher,
            notify: Arc::new(Notify::new()),
        }
    }

    /// Return a [`RefreshTrigger`] handle that can fire an on-demand refresh.
    ///
    /// Multiple handles may be obtained; each shares the same [`Notify`].
    pub fn trigger(&self) -> RefreshTrigger {
        RefreshTrigger(Arc::clone(&self.notify))
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Decode `content` bytes with `format` and add the resulting name set to
    /// `aggregator` under `source_id`.
    ///
    /// This DRYs the identical decode-parse-add step used by both
    /// [`load_from_cache`](Self::load_from_cache) and
    /// [`refresh_once`](Self::refresh_once).
    fn decode_and_add(
        aggregator: &mut Aggregator<i64>,
        source_id: i64,
        format: crate::storage::blocklists::BlocklistFormat,
        content: &[u8],
    ) {
        let text = String::from_utf8_lossy(content);
        let names = Parser::from(format).parse(&text);
        aggregator.add(source_id, names);
    }

    // ── Offline-start ─────────────────────────────────────────────────────────

    /// Build the live blocklist set purely from the SQLite offline cache.
    ///
    /// Does **not** touch the network.  Sources with no cached content
    /// contribute nothing but do not prevent others from loading.
    ///
    /// Call this once, before starting the DNS listeners, so that blocked
    /// domains are active immediately on restart even before the first
    /// network refresh completes.
    pub async fn load_from_cache(&self) {
        let sources = match self.repo.list_enabled().await {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "offline cache load: failed to list sources, skipping");
                return;
            }
        };

        let mut aggregator: Aggregator<i64> = Aggregator::new();
        let mut loaded = 0usize;

        for source in &sources {
            let cached = match self.repo.load_cache(source.id).await {
                Ok(Some(c)) => c,
                Ok(None) => continue,
                Err(e) => {
                    warn!(
                        id = source.id,
                        url = %source.url,
                        error = %e,
                        "offline cache load: failed to read cache, skipping source"
                    );
                    continue;
                }
            };

            Self::decode_and_add(&mut aggregator, source.id, source.format, &cached.content);
            loaded += 1;
        }

        let total = aggregator.len();
        let _ = aggregator.install(self.state.blocklist());

        info!(
            sources_loaded = loaded,
            total_domains = total,
            "offline cache load complete"
        );
    }

    // ── Network refresh ───────────────────────────────────────────────────────

    /// Run a single full network refresh cycle.
    ///
    /// Fetches all enabled sources, parses them, and atomically installs the
    /// merged domain set into the live [`MatchSet`].  Per-source errors are
    /// handled resiliently — a failing source falls back to its cached body so
    /// it is NOT dropped from the live set.
    ///
    /// # Errors
    ///
    /// Returns [`RefreshError::Storage`] only when the initial `list_enabled`
    /// call fails (i.e. the storage layer is completely unavailable).  All
    /// per-source failures are handled internally.
    pub async fn refresh_once(&self) -> Result<RefreshSummary, RefreshError> {
        let sources = self.repo.list_enabled().await?;

        let mut aggregator: Aggregator<i64> = Aggregator::new();
        let mut summary = RefreshSummary::default();

        for source in &sources {
            let validators = Validators {
                etag: source.etag.clone(),
                last_modified: source.last_modified.clone(),
            };

            match self.fetcher.fetch(&source.url, &validators).await {
                Ok(FetchOutcome::Modified {
                    body,
                    validators: new_validators,
                }) => {
                    // Parse fresh content.
                    let text = String::from_utf8_lossy(&body);
                    let names = Parser::from(source.format).parse(&text);
                    let count = names.len();
                    aggregator.add(source.id, names);

                    // Persist the cache and refresh metadata.
                    if let Err(e) = self.repo.save_cache(source.id, &body).await {
                        warn!(
                            id = source.id,
                            url = %source.url,
                            error = %e,
                            "refresh: failed to save cache (continuing)"
                        );
                    }
                    let meta = RefreshMetadata {
                        entry_count: count as u64,
                        last_updated: now_epoch(),
                        etag: new_validators.etag,
                        last_modified: new_validators.last_modified,
                    };
                    if let Err(e) = self.repo.update_refresh_metadata(source.id, &meta).await {
                        warn!(
                            id = source.id,
                            url = %source.url,
                            error = %e,
                            "refresh: failed to update metadata (continuing)"
                        );
                    }

                    summary.fetched += 1;
                    info!(
                        id = source.id,
                        url = %source.url,
                        domains = count,
                        "refresh: source updated (200)"
                    );
                }

                Ok(FetchOutcome::NotModified) => {
                    // Content unchanged — load from cache to keep it in the set.
                    match self.repo.load_cache(source.id).await {
                        Ok(Some(cached)) => {
                            Self::decode_and_add(
                                &mut aggregator,
                                source.id,
                                source.format,
                                &cached.content,
                            );
                        }
                        Ok(None) => {
                            warn!(
                                id = source.id,
                                url = %source.url,
                                "refresh: 304 but no cached content found — source skipped"
                            );
                        }
                        Err(e) => {
                            warn!(
                                id = source.id,
                                url = %source.url,
                                error = %e,
                                "refresh: 304 but cache read failed — source skipped"
                            );
                        }
                    }
                    summary.not_modified += 1;
                    info!(
                        id = source.id,
                        url = %source.url,
                        "refresh: source not modified (304)"
                    );
                }

                Err(e) => {
                    // Network or protocol error — fall back to cached body.
                    warn!(
                        id = source.id,
                        url = %source.url,
                        error = %e,
                        "refresh: fetch failed, falling back to cached content"
                    );
                    match self.repo.load_cache(source.id).await {
                        Ok(Some(cached)) => {
                            Self::decode_and_add(
                                &mut aggregator,
                                source.id,
                                source.format,
                                &cached.content,
                            );
                        }
                        Ok(None) => {
                            warn!(
                                id = source.id,
                                url = %source.url,
                                "refresh: fetch failed and no cached content — source dropped"
                            );
                        }
                        Err(ce) => {
                            warn!(
                                id = source.id,
                                url = %source.url,
                                cache_error = %ce,
                                "refresh: fetch failed and cache read also failed — source dropped"
                            );
                        }
                    }
                    summary.failed += 1;
                }
            }
        }

        // Atomic swap: install the merged set.
        let contributions = aggregator.install(self.state.blocklist());
        summary.total_domains = self.state.blocklist().len();

        info!(
            fetched = summary.fetched,
            not_modified = summary.not_modified,
            failed = summary.failed,
            total_domains = summary.total_domains,
            sources = contributions.len(),
            "refresh cycle complete"
        );

        Ok(summary)
    }

    // ── Long-lived run loop ───────────────────────────────────────────────────

    /// Run the scheduler until `token` is cancelled.
    ///
    /// 1. Performs an immediate [`refresh_once`](Self::refresh_once) on startup
    ///    so fresh data is pulled shortly after boot (the offline cache is
    ///    already live from a prior [`load_from_cache`](Self::load_from_cache)
    ///    call).
    /// 2. Loops with three concurrent arms:
    ///    - A periodic sleep whose duration is read fresh from
    ///      [`ResolverState::settings`]`.blocklist_refresh_interval` on every
    ///      iteration, clamped to [`MIN_INTERVAL`].  Interval changes (E8
    ///      settings edits) therefore take effect at the next cycle boundary; E8
    ///      can also fire the [`RefreshTrigger`] to apply them immediately.
    ///    - An on-demand [`RefreshTrigger`] notification.
    ///    - Cancellation via `token`.
    ///
    /// The task exits promptly on cancellation.
    pub async fn run(self, token: CancellationToken) {
        // Immediate refresh on startup.
        match self.refresh_once().await {
            Ok(summary) => {
                info!(
                    fetched = summary.fetched,
                    not_modified = summary.not_modified,
                    failed = summary.failed,
                    total_domains = summary.total_domains,
                    "startup refresh complete"
                );
            }
            Err(e) => {
                warn!(error = %e, "startup refresh failed — will retry at next interval");
            }
        }

        // Periodic loop.
        loop {
            // Read the interval fresh each iteration so E8 settings changes take
            // effect at the next cycle boundary without needing a watch channel.
            let interval_secs = self.state.settings().blocklist_refresh_interval;
            let interval = Duration::from_secs(u64::from(interval_secs)).max(MIN_INTERVAL);

            tokio::select! {
                // Periodic timer arm.
                () = tokio::time::sleep(interval) => {
                    match self.refresh_once().await {
                        Ok(summary) => {
                            info!(
                                fetched = summary.fetched,
                                not_modified = summary.not_modified,
                                failed = summary.failed,
                                total_domains = summary.total_domains,
                                "periodic refresh complete"
                            );
                        }
                        Err(e) => {
                            warn!(error = %e, "periodic refresh failed — will retry at next interval");
                        }
                    }
                }

                // On-demand trigger arm.
                () = self.notify.notified() => {
                    match self.refresh_once().await {
                        Ok(summary) => {
                            info!(
                                fetched = summary.fetched,
                                not_modified = summary.not_modified,
                                failed = summary.failed,
                                total_domains = summary.total_domains,
                                "on-demand refresh complete"
                            );
                        }
                        Err(e) => {
                            warn!(error = %e, "on-demand refresh failed");
                        }
                    }
                }

                // Cancellation arm — exit promptly.
                () = token.cancelled() => {
                    info!("blocklist scheduler shutting down");
                    break;
                }
            }
        }
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Return the current Unix epoch time in seconds.
fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tempfile::TempDir;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::{
        blocklist::fetch::Fetcher,
        storage::{
            Db,
            blocklists::{BlocklistFormat, BlocklistRepository, NewBlocklist, SqliteBlocklistRepo},
        },
    };

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Open a temp SQLite DB, return the `TempDir` guard and the open `Db`.
    async fn open_db() -> (TempDir, Db) {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("test.db");
        let db = Db::connect(&path).await.expect("connect");
        (dir, db)
    }

    /// Build a scheduler with a short timeout (5 s) for test fetches.
    fn make_scheduler(db: &Db, state: Arc<ResolverState>) -> BlocklistScheduler {
        BlocklistScheduler::new(
            SqliteBlocklistRepo::new(db.pool().clone()),
            state,
            Fetcher::new().with_timeout(Duration::from_secs(5)),
        )
    }

    fn hosts_source(url: &str) -> NewBlocklist {
        NewBlocklist {
            url: url.to_owned(),
            format: BlocklistFormat::Hosts,
            enabled: true,
        }
    }

    // ── Offline start builds set from cache (no network) ─────────────────────

    /// Seeding the offline cache then calling `load_from_cache` must populate
    /// the live blocklist set without any network access.
    #[tokio::test]
    async fn load_from_cache_builds_set_without_network() {
        let (_dir, db) = open_db().await;
        let state = ResolverState::hydrate(&db).await.expect("hydrate");
        let repo = SqliteBlocklistRepo::new(db.pool().clone());

        // Insert an enabled source and manually seed its cache.
        let src = repo
            .insert(hosts_source("https://offline.example.com/hosts"))
            .await
            .expect("insert");

        let body = b"0.0.0.0 ads.example.com\n0.0.0.0 tracker.example.org\n";
        repo.save_cache(src.id, body).await.expect("save_cache");

        // Blocklist must be empty before the load.
        assert!(state.blocklist().is_empty());

        let scheduler = make_scheduler(&db, Arc::clone(&state));
        scheduler.load_from_cache().await;

        // Both domains from the cached body must now be in the live set.
        let ads: crate::codec::name::Name = "ads.example.com".parse().unwrap();
        let tracker: crate::codec::name::Name = "tracker.example.org".parse().unwrap();
        assert!(
            state.blocklist().contains(&ads),
            "ads.example.com must be blocked after cache load"
        );
        assert!(
            state.blocklist().contains(&tracker),
            "tracker.example.org must be blocked after cache load"
        );
        assert_eq!(state.blocklist().len(), 2);
    }

    // ── Network refresh installs a new snapshot ───────────────────────────────

    /// A 200 response installs fresh domains, persists the cache, updates
    /// `entry_count`, `last_updated`, and `etag` on the source row.
    #[tokio::test]
    async fn refresh_once_200_installs_domains_and_persists_metadata() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/hosts.txt"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(
                        b"0.0.0.0 ads.example.com\n0.0.0.0 tracker.example.org\n".to_vec(),
                    )
                    .insert_header("etag", r#""v1""#),
            )
            .mount(&server)
            .await;

        let url = format!("{}/hosts.txt", server.uri());

        let (_dir, db) = open_db().await;
        let state = ResolverState::hydrate(&db).await.expect("hydrate");
        let repo = SqliteBlocklistRepo::new(db.pool().clone());

        let src = repo.insert(hosts_source(&url)).await.expect("insert");

        let scheduler = make_scheduler(&db, Arc::clone(&state));
        let summary = scheduler.refresh_once().await.expect("refresh_once");

        // Summary counts.
        assert_eq!(summary.fetched, 1);
        assert_eq!(summary.not_modified, 0);
        assert_eq!(summary.failed, 0);
        assert_eq!(summary.total_domains, 2);

        // Live set contains both domains.
        let ads: crate::codec::name::Name = "ads.example.com".parse().unwrap();
        let tracker: crate::codec::name::Name = "tracker.example.org".parse().unwrap();
        assert!(state.blocklist().contains(&ads));
        assert!(state.blocklist().contains(&tracker));

        // Cache was persisted.
        let cached = repo
            .load_cache(src.id)
            .await
            .expect("load_cache")
            .expect("cache must be Some after refresh");
        assert!(!cached.content.is_empty());

        // Metadata was updated.
        let rows = repo.list().await.expect("list");
        let row = rows.iter().find(|r| r.id == src.id).expect("row");
        assert_eq!(row.entry_count, 2);
        assert!(row.last_updated.is_some(), "last_updated must be set");
        assert_eq!(row.etag.as_deref(), Some(r#""v1""#));
    }

    // ── 304 keeps the source in the set from cached body ─────────────────────

    /// When the server returns 304 the scheduler must fall back to the cached
    /// body so the source's domains remain in the live set.
    #[tokio::test]
    async fn refresh_once_304_retains_cached_domains() {
        let server = MockServer::start().await;

        // Only match when the If-None-Match header carries the stored ETag.
        Mock::given(method("GET"))
            .and(path("/hosts.txt"))
            .and(header(
                reqwest::header::IF_NONE_MATCH.as_str(),
                r#""etag-v1""#,
            ))
            .respond_with(ResponseTemplate::new(304))
            .mount(&server)
            .await;

        let url = format!("{}/hosts.txt", server.uri());

        let (_dir, db) = open_db().await;
        let state = ResolverState::hydrate(&db).await.expect("hydrate");
        let repo = SqliteBlocklistRepo::new(db.pool().clone());

        // Insert source with matching ETag already stored.
        let src = repo
            .insert(NewBlocklist {
                url,
                format: BlocklistFormat::Hosts,
                enabled: true,
            })
            .await
            .expect("insert");

        // Pre-seed the row's ETag.
        repo.update_refresh_metadata(
            src.id,
            &RefreshMetadata {
                entry_count: 2,
                last_updated: 1_700_000_000,
                etag: Some(r#""etag-v1""#.to_owned()),
                last_modified: None,
            },
        )
        .await
        .expect("update meta");

        // Pre-seed the cache with the domain list.
        let body = b"0.0.0.0 ads.example.com\n0.0.0.0 tracker.example.org\n";
        repo.save_cache(src.id, body).await.expect("save_cache");

        let scheduler = make_scheduler(&db, Arc::clone(&state));
        let summary = scheduler.refresh_once().await.expect("refresh_once");

        assert_eq!(summary.not_modified, 1);
        assert_eq!(summary.fetched, 0);
        assert_eq!(summary.failed, 0);

        // Cached domains must still be in the live set.
        let ads: crate::codec::name::Name = "ads.example.com".parse().unwrap();
        let tracker: crate::codec::name::Name = "tracker.example.org".parse().unwrap();
        assert!(
            state.blocklist().contains(&ads),
            "ads must be present after 304"
        );
        assert!(
            state.blocklist().contains(&tracker),
            "tracker must be present after 304"
        );
    }

    // ── Failing fetch retains the previous set; one bad source doesn't sink others

    /// Two sources: one good (200), one bad (500 + pre-seeded cache).
    ///
    /// After `refresh_once` both sources' domains must be in the live set.
    #[tokio::test]
    async fn refresh_once_bad_source_retains_cached_domains_and_does_not_sink_good_source() {
        let server = MockServer::start().await;

        // Good source — 200.
        Mock::given(method("GET"))
            .and(path("/good.txt"))
            .respond_with(
                ResponseTemplate::new(200).set_body_bytes(b"0.0.0.0 good.example.com\n".to_vec()),
            )
            .mount(&server)
            .await;

        // Bad source — 500.
        Mock::given(method("GET"))
            .and(path("/bad.txt"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let (_dir, db) = open_db().await;
        let state = ResolverState::hydrate(&db).await.expect("hydrate");
        let repo = SqliteBlocklistRepo::new(db.pool().clone());

        // Good source.
        repo.insert(NewBlocklist {
            url: format!("{}/good.txt", server.uri()),
            format: BlocklistFormat::Hosts,
            enabled: true,
        })
        .await
        .expect("insert good");

        // Bad source with a pre-seeded cache so its domains survive the failure.
        let bad = repo
            .insert(NewBlocklist {
                url: format!("{}/bad.txt", server.uri()),
                format: BlocklistFormat::DomainList,
                enabled: true,
            })
            .await
            .expect("insert bad");
        repo.save_cache(bad.id, b"bad-but-cached.example.com\n")
            .await
            .expect("seed bad cache");

        let scheduler = make_scheduler(&db, Arc::clone(&state));
        let summary = scheduler.refresh_once().await.expect("refresh_once");

        assert_eq!(summary.fetched, 1, "good source must count as fetched");
        assert_eq!(summary.failed, 1, "bad source must count as failed");

        let good: crate::codec::name::Name = "good.example.com".parse().unwrap();
        let cached: crate::codec::name::Name = "bad-but-cached.example.com".parse().unwrap();

        assert!(
            state.blocklist().contains(&good),
            "good domain must be present"
        );
        assert!(
            state.blocklist().contains(&cached),
            "bad source's cached domain must be retained"
        );
        assert_eq!(state.blocklist().len(), 2, "exactly 2 domains in live set");
    }

    // ── On-demand trigger forces a refresh ───────────────────────────────────

    /// Spawn `run`, wait for the startup refresh (v1), override the mock to v2
    /// with higher wiremock priority, fire the trigger, and poll until the live
    /// set reflects v2.
    ///
    /// Wiremock matches mocks in *ascending priority order* (1 = highest) with
    /// insertion order as a tiebreaker.  We mount v1 at the default priority
    /// (5) and v2 at priority 1 so that the v2 response wins once mounted.
    #[tokio::test]
    async fn run_on_demand_trigger_forces_refresh() {
        let server = MockServer::start().await;

        // v1 — served at the default priority (5) for the startup refresh.
        Mock::given(method("GET"))
            .and(path("/hosts.txt"))
            .respond_with(
                ResponseTemplate::new(200).set_body_bytes(b"0.0.0.0 v1.example.com\n".to_vec()),
            )
            .mount(&server)
            .await;

        let url = format!("{}/hosts.txt", server.uri());

        let (_dir, db) = open_db().await;
        let state = ResolverState::hydrate(&db).await.expect("hydrate");
        let repo = SqliteBlocklistRepo::new(db.pool().clone());

        repo.insert(hosts_source(&url)).await.expect("insert");

        let scheduler = BlocklistScheduler::new(
            SqliteBlocklistRepo::new(db.pool().clone()),
            Arc::clone(&state),
            Fetcher::new().with_timeout(Duration::from_secs(5)),
        );
        let trigger = scheduler.trigger();
        let token = CancellationToken::new();
        let token_clone = token.clone();

        // Spawn the scheduler.
        let task = tokio::spawn(async move {
            scheduler.run(token_clone).await;
        });

        // Wait until the startup refresh installs v1.
        let v1: crate::codec::name::Name = "v1.example.com".parse().unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            if state.blocklist().contains(&v1) {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for v1 to appear in blocklist"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Mount v2 with priority 1 (highest) so it beats the default-priority
        // v1 mock on all subsequent requests to the same path.
        Mock::given(method("GET"))
            .and(path("/hosts.txt"))
            .respond_with(
                ResponseTemplate::new(200).set_body_bytes(b"0.0.0.0 v2.example.com\n".to_vec()),
            )
            .with_priority(1)
            .mount(&server)
            .await;

        // Fire the on-demand trigger.  The default interval is 24h, so only
        // the trigger can wake the scheduler.
        trigger.trigger();

        // Poll until v2 appears in the live set.
        let v2: crate::codec::name::Name = "v2.example.com".parse().unwrap();
        let deadline2 = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            if state.blocklist().contains(&v2) {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline2,
                "timed out waiting for v2 to appear in blocklist after trigger"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Cancel the scheduler and confirm it exits cleanly.
        token.cancel();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("scheduler task timed out on shutdown")
            .expect("scheduler task panicked");
    }

    // ── Zero sources — no panic, empty set ───────────────────────────────────

    /// With no enabled blocklist sources `load_from_cache` and `refresh_once`
    /// must complete without error and install an empty set.
    #[tokio::test]
    async fn zero_sources_load_and_refresh_no_panic() {
        let (_dir, db) = open_db().await;
        let state = ResolverState::hydrate(&db).await.expect("hydrate");

        let scheduler = make_scheduler(&db, Arc::clone(&state));

        // Offline load with no sources must be a no-op.
        scheduler.load_from_cache().await;
        assert!(state.blocklist().is_empty());

        // Network refresh with no sources must also succeed.
        let summary = scheduler.refresh_once().await.expect("refresh_once");
        assert_eq!(summary.fetched, 0);
        assert_eq!(summary.not_modified, 0);
        assert_eq!(summary.failed, 0);
        assert_eq!(summary.total_domains, 0);
        assert!(state.blocklist().is_empty());
    }
}
