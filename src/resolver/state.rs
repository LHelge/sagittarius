//! Cohesive resolver state bundle: match sets, local-record matcher, cache,
//! and hot-swappable runtime settings.
//!
//! [`ResolverState`] is the single shared object that the DNS engine (E6) and
//! the web admin (E8) both hold via [`Arc`].  It owns:
//!
//! - Three [`MatchSet`] instances — admin blacklist, allowlist, and aggregated
//!   blocklist — each independently hot-swappable (SPEC §3.1, §3.2).
//! - A [`LocalMatcher`] for authoritative local records.
//! - A [`DnsCache`] for upstream response caching.
//! - An [`ArcSwap`]-protected [`RuntimeSettings`] snapshot for operational
//!   settings that can be swapped atomically without touching the cache.
//!
//! # Startup hydration
//!
//! Call [`ResolverState::hydrate`] once at startup.  It reads all tables from
//! SQLite and builds the in-memory state synchronously (from the caller's async
//! context).  The returned [`Arc<ResolverState>`] is then shared across tasks.
//!
//! # Live updates
//!
//! - E7 (blocklist refresh) calls `state.blocklist().store(new_set)`.
//! - E8 (admin blacklist/allowlist edits) calls `state.blacklist().store(…)` /
//!   `state.allowlist().store(…)`.
//! - E8 (settings change) calls `state.store_settings(new_settings)`.
//! - E8 (local-record edit) calls `state.local().store(new_records)`.
//!
//! **Precedence/ordering is NOT defined here.** That is the E6 pipeline layer's
//! concern.  This module just bundles the pieces and exposes lookups + swaps.

use std::{
    net::Ipv4Addr,
    net::Ipv6Addr,
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
};

use arc_swap::ArcSwap;

use crate::{
    codec::synth::BlockMode,
    resolver::{
        self,
        cache::DnsCache,
        local::{LocalMatcher, LocalRecords, RecordData},
        matchset::{AttributedSet, MatchSet},
    },
    storage::{
        Db,
        lists::{AllowlistRepository, BlacklistRepository},
        local_records::{LocalRecordRepository, RecordType},
        settings::{BlockingMode, Settings, SettingsRepository},
    },
    time::Clock,
};

// ── RuntimeSettings ───────────────────────────────────────────────────────────

/// A snapshot of operational runtime settings derived from [`Settings`].
///
/// Held inside an [`ArcSwap`] so that settings changes take effect atomically
/// on the hot path without restarting the server.
///
/// # Cache bounds vs. immediate-effect settings
///
/// The cache bounds (`cache_min_ttl`, `cache_max_ttl`, `cache_capacity`) are
/// stored here for reference, but **changing them requires rebuilding the
/// [`DnsCache`]** — `moka`'s capacity is fixed at build time (SPEC §3.2).
/// That rebuild is E8's concern and is out of scope here.
///
/// In contrast, `negative_ttl_cap`, `block_mode`, and
/// `blocklist_refresh_interval` take effect immediately on the next settings
/// swap without rebuilding anything.
#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeSettings {
    /// Minimum TTL to serve from the cache, in seconds.
    pub cache_min_ttl: u32,
    /// Maximum TTL to serve from the cache, in seconds.
    pub cache_max_ttl: u32,
    /// Maximum number of cache entries (fixed at cache build time; see note).
    pub cache_capacity: u64,
    /// Cap applied to negative (NXDOMAIN/NODATA) cache entries, in seconds.
    ///
    /// Used by E6.3 at cache-store time. Takes effect immediately on a swap.
    pub negative_ttl_cap: u32,
    /// How blocked domains are answered.
    ///
    /// Derived from [`BlockingMode`] and the custom IP fields. Takes effect
    /// immediately on a swap.
    pub block_mode: BlockMode,
    /// How often blocklists are refreshed, in seconds. Used by E7.
    ///
    /// Takes effect immediately on a swap.
    pub blocklist_refresh_interval: u32,
    /// Whether per-query events are persisted to the query log (E10).
    ///
    /// Read on the hot path by the telemetry sink so the writer can be gated
    /// cheaply without a DB round-trip. Takes effect immediately on a swap.
    pub query_log_enabled: bool,
    /// Query-log retention window in days (E10).
    ///
    /// Read by the hourly purge task from the live snapshot.
    pub query_log_retention_days: u32,
}

impl From<&Settings> for RuntimeSettings {
    /// Derive a [`RuntimeSettings`] snapshot from a [`Settings`] row.
    ///
    /// `block_mode` derivation:
    /// - [`BlockingMode::NxDomain`] → [`BlockMode::NxDomain`]
    /// - [`BlockingMode::NullIp`] → [`BlockMode::null_ip()`] (`0.0.0.0` / `::`)
    /// - [`BlockingMode::Custom`] → [`BlockMode::Address`] with the configured
    ///   custom IPs, falling back to [`Ipv4Addr::UNSPECIFIED`] /
    ///   [`Ipv6Addr::UNSPECIFIED`] if either custom IP is `None`.
    fn from(s: &Settings) -> Self {
        let block_mode = match s.blocking_mode {
            BlockingMode::NxDomain => BlockMode::NxDomain,
            BlockingMode::NullIp => BlockMode::null_ip(),
            BlockingMode::Custom => BlockMode::Address {
                v4: s.custom_block_ipv4.unwrap_or(Ipv4Addr::UNSPECIFIED),
                v6: s.custom_block_ipv6.unwrap_or(Ipv6Addr::UNSPECIFIED),
            },
        };

        Self {
            cache_min_ttl: s.cache_min_ttl,
            cache_max_ttl: s.cache_max_ttl,
            cache_capacity: s.cache_capacity,
            negative_ttl_cap: s.cache_negative_ttl_cap,
            block_mode,
            blocklist_refresh_interval: s.blocklist_refresh_interval,
            query_log_enabled: s.query_log_enabled,
            query_log_retention_days: s.query_log_retention_days,
        }
    }
}

// ── ResolverState ─────────────────────────────────────────────────────────────

/// Shared, hot-path resolver state owned by both the DNS engine (E6) and the
/// web admin (E8).
///
/// All components are independently hot-swappable via their respective
/// `store` methods; readers never block.  See the module-level documentation
/// for the update protocol.
pub struct ResolverState {
    /// Admin-managed blacklist (exact domain names).
    blacklist: MatchSet,
    /// Admin-managed allowlist (exact domain names that bypass blocking).
    allowlist: MatchSet,
    /// Aggregated blocklist from external sources (filled by E7 on refresh).
    ///
    /// A `Name → primary blocklist_id` map ([`AttributedSet`]) so blocks can be
    /// attributed to a source (E11); the decision layer still treats it as a
    /// presence check.  Starts empty at hydration; E7 installs the first set
    /// asynchronously.
    blocklist: AttributedSet,
    /// Authoritative local-record matcher.
    local: LocalMatcher,
    /// Raw-bytes DNS response cache.
    cache: DnsCache,
    /// Hot-swappable operational settings snapshot.
    settings: ArcSwap<RuntimeSettings>,
    /// Unix-second deadline until which all blocking is paused (E12).
    ///
    /// `0` means active (not paused). When `Clock::now_secs()` is below a
    /// non-zero deadline, the decision stack skips the blacklist/allowlist/
    /// blocklist stages. Auto-resumes by comparison — no timer is needed for
    /// correctness, and the value is in-memory only, so a restart resumes
    /// blocking (fail-safe). See SPEC §5 and §3.1.
    paused_until: AtomicI64,
}

impl ResolverState {
    // ── Component accessors ───────────────────────────────────────────────────

    /// The admin blacklist [`MatchSet`].
    ///
    /// E6 reads `blacklist().contains(name)`.
    /// E8 installs updated sets via `blacklist().store(new_set)`.
    #[must_use]
    pub fn blacklist(&self) -> &MatchSet {
        &self.blacklist
    }

    /// The admin allowlist [`MatchSet`].
    ///
    /// E6 reads `allowlist().contains(name)`.
    /// E8 installs updated sets via `allowlist().store(new_set)`.
    #[must_use]
    pub fn allowlist(&self) -> &MatchSet {
        &self.allowlist
    }

    /// The aggregated blocklist [`AttributedSet`].
    ///
    /// Starts empty at hydration.
    /// E6 reads `blocklist().contains(name)` (presence only).
    /// E7 installs refreshed maps via the aggregator's `install`.
    /// E11.3 reads `blocklist().primary_source(name)` to attribute a block.
    #[must_use]
    pub fn blocklist(&self) -> &AttributedSet {
        &self.blocklist
    }

    /// The local-record matcher.
    ///
    /// E6 reads `local().lookup(name, qtype)`.
    /// E8 installs updated snapshots via `local().store(new_records)`.
    #[must_use]
    pub fn local(&self) -> &LocalMatcher {
        &self.local
    }

    /// The DNS response cache.
    ///
    /// E6 reads `cache().get(…)` and writes `cache().insert(…)`.
    #[must_use]
    pub fn cache(&self) -> &DnsCache {
        &self.cache
    }

    // ── Settings accessors ────────────────────────────────────────────────────

    /// Load the current [`RuntimeSettings`] snapshot.
    ///
    /// Returns an [`arc_swap::Guard`] that holds a reference to the current
    /// [`Arc<RuntimeSettings>`] without incrementing the reference count.
    /// Prefer this for short-lived reads (single call); use
    /// [`ResolverState::settings_full`] when the snapshot must outlive an await
    /// point.
    #[must_use]
    pub fn settings(&self) -> arc_swap::Guard<Arc<RuntimeSettings>> {
        self.settings.load()
    }

    /// Load the current [`RuntimeSettings`] as a full, owned [`Arc`].
    ///
    /// Increments the reference count.  Use this when the snapshot must be
    /// kept alive across an await point or stored in another struct.
    #[must_use]
    pub fn settings_full(&self) -> Arc<RuntimeSettings> {
        self.settings.load_full()
    }

    /// Atomically replace the current [`RuntimeSettings`] with `new_settings`.
    ///
    /// E8 calls this after persisting a settings change to SQLite.
    /// The new settings take effect for all subsequent hot-path reads
    /// immediately (SPEC §3.2).
    pub fn store_settings(&self, new_settings: RuntimeSettings) {
        self.settings.store(Arc::new(new_settings));
    }

    // ── Pause control (E12) ───────────────────────────────────────────────────

    /// Pause all blocking for the next `secs` seconds.
    ///
    /// Stores `Clock::now_secs() + secs` as the deadline. While paused, the
    /// decision stack skips the blacklist/allowlist/blocklist stages; local
    /// records still answer authoritatively. A non-positive `secs` is treated
    /// as an immediate [`resume`](Self::resume).
    ///
    /// E8 calls this from the admin UI. Relaxed ordering — only eventual
    /// visibility on the hot path is required (consistent with `Stats`).
    pub fn pause_for_secs(&self, secs: i64) {
        let deadline = if secs > 0 {
            Clock::now_secs() + secs
        } else {
            0
        };
        self.paused_until.store(deadline, Ordering::Relaxed);
    }

    /// Resume blocking immediately, clearing any pause deadline.
    pub fn resume(&self) {
        self.paused_until.store(0, Ordering::Relaxed);
    }

    /// Whether blocking is currently paused.
    ///
    /// True when a deadline is set and still in the future. Read once per query
    /// on the hot path.
    #[must_use]
    pub fn blocking_paused(&self) -> bool {
        self.paused_until().is_some()
    }

    /// The active pause deadline as a Unix second, or `None` when blocking is
    /// active (no deadline, or the deadline has passed).
    ///
    /// Used by the admin UI to render the countdown banner (E12.2).
    #[must_use]
    pub fn paused_until(&self) -> Option<i64> {
        let deadline = self.paused_until.load(Ordering::Relaxed);
        (deadline != 0 && Clock::now_secs() < deadline).then_some(deadline)
    }

    // ── Startup hydration ─────────────────────────────────────────────────────

    /// Hydrate a [`ResolverState`] from the database and return it wrapped in
    /// an [`Arc`] ready for sharing across tasks.
    ///
    /// Reads:
    /// - [`Settings`] → builds the [`DnsCache`] and [`RuntimeSettings`].
    /// - Blacklist / allowlist rows → populates two [`MatchSet`]s.
    /// - The blocklist [`MatchSet`] is **intentionally left empty**; E7 fills
    ///   it on first refresh.
    /// - Local-record rows → builds a [`LocalRecords`] snapshot via the
    ///   [`LocalRecordsBuilder`](crate::resolver::local::LocalRecordsBuilder).
    ///
    /// # Errors
    ///
    /// Returns [`resolver::Error`] wrapping:
    /// - Storage errors from any repo call ([`resolver::Error::Storage`]).
    /// - A parse failure on a stored IP value or builder rejection
    ///   ([`resolver::Error::InvalidLocalRecord`]).
    pub async fn hydrate(db: &Db) -> resolver::Result<Arc<Self>> {
        // ── Settings ──────────────────────────────────────────────────────────
        let settings = db.settings().get().await?;

        let cache = DnsCache::new(
            settings.cache_capacity,
            settings.cache_min_ttl,
            settings.cache_max_ttl,
        );

        let runtime_settings = RuntimeSettings::from(&settings);

        // ── Blacklist & allowlist ─────────────────────────────────────────────
        let blacklist = db.blacklist().load_all().await?.into_iter().collect();
        let allowlist = db.allowlist().load_all().await?.into_iter().collect();

        // Blocklist starts empty; E7 fills it on first refresh.
        let blocklist = AttributedSet::empty();

        // ── Local records ─────────────────────────────────────────────────────
        let local_rows = db.local_records().load_all().await?;

        let local = LocalMatcher::new(build_local_records(local_rows)?);

        Ok(Arc::new(Self {
            blacklist,
            allowlist,
            blocklist,
            local,
            cache,
            settings: ArcSwap::from_pointee(runtime_settings),
            paused_until: AtomicI64::new(0),
        }))
    }
}

/// Build an immutable [`LocalRecords`] snapshot from persisted rows.
///
/// Shared by [`ResolverState::hydrate`] and the web admin's local-record edits
/// (E8.8), which rebuilds the snapshot after a change and swaps it via
/// [`LocalMatcher::store`](crate::resolver::local::LocalMatcher::store).
///
/// # Errors
///
/// Returns [`resolver::Error::InvalidLocalRecord`] if a stored value is not a
/// valid IP for its record type or the builder rejects the name.
pub fn build_local_records(
    rows: Vec<crate::storage::local_records::LocalRecord>,
) -> resolver::Result<LocalRecords> {
    let mut builder = LocalRecords::builder();
    for row in rows {
        let data = match row.record_type {
            RecordType::A => {
                let addr: Ipv4Addr = row.value.parse().map_err(|e| {
                    resolver::Error::InvalidLocalRecord(format!(
                        "record {:?} has invalid A value {:?}: {e}",
                        row.name, row.value
                    ))
                })?;
                RecordData::A(addr)
            }
            RecordType::Aaaa => {
                let addr: Ipv6Addr = row.value.parse().map_err(|e| {
                    resolver::Error::InvalidLocalRecord(format!(
                        "record {:?} has invalid AAAA value {:?}: {e}",
                        row.name, row.value
                    ))
                })?;
                RecordData::Aaaa(addr)
            }
        };

        // Strip trailing dot for the builder (which normalizes internally).
        let name = row.name.trim_end_matches('.');
        builder.add(name, data, row.ttl).map_err(|e| {
            resolver::Error::InvalidLocalRecord(format!(
                "could not add local record {:?}: {e}",
                row.name
            ))
        })?;
    }
    Ok(builder.build())
}

impl std::fmt::Debug for ResolverState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolverState")
            .field("blacklist", &self.blacklist)
            .field("allowlist", &self.allowlist)
            .field("blocklist", &self.blocklist)
            .field("local", &self.local)
            .finish_non_exhaustive()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::{
        codec::{message::Qtype, name::Name},
        resolver::local::LocalMatch,
        storage::{
            lists::{AllowlistRepository, BlacklistRepository},
            local_records::{LocalRecordRepository, NewLocalRecord, RecordType},
            settings::{BlockingMode, Settings},
        },
    };

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn name(s: &str) -> Name {
        s.parse().expect("valid domain name")
    }

    // ── RuntimeSettings::from(&Settings) ─────────────────────────────────────

    fn base_settings() -> Settings {
        Settings {
            cache_min_ttl: 1,
            cache_max_ttl: 86400,
            cache_negative_ttl_cap: 3600,
            cache_capacity: 100_000,
            blocking_mode: BlockingMode::NullIp,
            custom_block_ipv4: None,
            custom_block_ipv6: None,
            blocklist_refresh_interval: 86400,
            ui_theme: "auto".to_owned(),
            query_log_enabled: true,
            query_log_retention_days: 30,
        }
    }

    #[test]
    fn runtime_settings_from_nxdomain() {
        let mut s = base_settings();
        s.blocking_mode = BlockingMode::NxDomain;
        let rs = RuntimeSettings::from(&s);
        assert_eq!(rs.block_mode, BlockMode::NxDomain);
        assert_eq!(rs.negative_ttl_cap, 3600);
        assert_eq!(rs.cache_max_ttl, 86400);
        assert_eq!(rs.blocklist_refresh_interval, 86400);
    }

    #[test]
    fn runtime_settings_from_null_ip() {
        let s = base_settings();
        let rs = RuntimeSettings::from(&s);
        assert_eq!(rs.block_mode, BlockMode::null_ip());
    }

    #[test]
    fn runtime_settings_carries_query_log_fields() {
        let mut s = base_settings();
        s.query_log_enabled = false;
        s.query_log_retention_days = 7;
        let rs = RuntimeSettings::from(&s);
        assert!(!rs.query_log_enabled);
        assert_eq!(rs.query_log_retention_days, 7);
    }

    #[test]
    fn runtime_settings_from_custom_with_ips() {
        let mut s = base_settings();
        s.blocking_mode = BlockingMode::Custom;
        s.custom_block_ipv4 = Some("203.0.113.1".parse().unwrap());
        s.custom_block_ipv6 = Some("2001:db8::1".parse().unwrap());

        let rs = RuntimeSettings::from(&s);
        assert_eq!(
            rs.block_mode,
            BlockMode::Address {
                v4: "203.0.113.1".parse().unwrap(),
                v6: "2001:db8::1".parse().unwrap(),
            }
        );
    }

    #[test]
    fn runtime_settings_from_custom_none_ips_falls_back_to_unspecified() {
        let mut s = base_settings();
        s.blocking_mode = BlockingMode::Custom;
        s.custom_block_ipv4 = None;
        s.custom_block_ipv6 = None;

        let rs = RuntimeSettings::from(&s);
        assert_eq!(
            rs.block_mode,
            BlockMode::Address {
                v4: Ipv4Addr::UNSPECIFIED,
                v6: Ipv6Addr::UNSPECIFIED,
            }
        );
    }

    #[test]
    fn runtime_settings_from_custom_partial_ips() {
        let mut s = base_settings();
        s.blocking_mode = BlockingMode::Custom;
        s.custom_block_ipv4 = Some("10.0.0.1".parse().unwrap());
        s.custom_block_ipv6 = None;

        let rs = RuntimeSettings::from(&s);
        assert_eq!(
            rs.block_mode,
            BlockMode::Address {
                v4: "10.0.0.1".parse().unwrap(),
                v6: Ipv6Addr::UNSPECIFIED,
            }
        );
    }

    // ── Hydration: reflects rows ───────────────────────────────────────────────

    #[tokio::test]
    async fn hydration_reflects_blacklist_and_allowlist() {
        let (_dir, db) = crate::test_support::temp_db().await;

        let bl = db.blacklist();
        bl.add("ads.example.com").await.expect("add to blacklist");
        bl.add("tracker.evil.net").await.expect("add to blacklist");

        let al = db.allowlist();
        al.add("safe.example.com").await.expect("add to allowlist");

        let state = ResolverState::hydrate(&db).await.expect("hydrate");

        assert!(state.blacklist().contains(&name("ads.example.com")));
        assert!(state.blacklist().contains(&name("tracker.evil.net")));
        assert!(!state.blacklist().contains(&name("safe.example.com")));

        assert!(state.allowlist().contains(&name("safe.example.com")));
        assert!(!state.allowlist().contains(&name("ads.example.com")));
    }

    #[tokio::test]
    async fn hydration_blocklist_is_empty() {
        let (_dir, db) = crate::test_support::temp_db().await;
        let state = ResolverState::hydrate(&db).await.expect("hydrate");
        assert!(
            state.blocklist().is_empty(),
            "blocklist must be empty right after hydration"
        );
    }

    #[tokio::test]
    async fn hydration_reflects_local_records() {
        let (_dir, db) = crate::test_support::temp_db().await;

        let repo = db.local_records();
        repo.add(NewLocalRecord {
            name: "router.home.lan".to_owned(),
            record_type: RecordType::A,
            value: "192.168.1.1".to_owned(),
            ttl: 300,
        })
        .await
        .expect("add A record");

        repo.add(NewLocalRecord {
            name: "router.home.lan".to_owned(),
            record_type: RecordType::Aaaa,
            value: "fd00::1".to_owned(),
            ttl: 600,
        })
        .await
        .expect("add AAAA record");

        let state = ResolverState::hydrate(&db).await.expect("hydrate");

        // A lookup
        let a_match = state.local().lookup(&name("router.home.lan"), Qtype::A);
        assert!(
            matches!(a_match, LocalMatch::Answer { data: crate::resolver::local::RecordData::A(addr), ttl: 300 } if addr == "192.168.1.1".parse::<Ipv4Addr>().unwrap()),
            "expected A answer, got: {a_match:?}"
        );

        // AAAA lookup
        let aaaa_match = state.local().lookup(&name("router.home.lan"), Qtype::Aaaa);
        assert!(
            matches!(aaaa_match, LocalMatch::Answer { data: crate::resolver::local::RecordData::Aaaa(addr), ttl: 600 } if addr == "fd00::1".parse::<Ipv6Addr>().unwrap()),
            "expected AAAA answer, got: {aaaa_match:?}"
        );
    }

    // ── Hydration: settings reflect seed ──────────────────────────────────────

    #[tokio::test]
    async fn hydration_settings_reflect_seed() {
        let (_dir, db) = crate::test_support::temp_db().await;
        let state = ResolverState::hydrate(&db).await.expect("hydrate");

        let s = state.settings();
        assert_eq!(s.block_mode, BlockMode::null_ip(), "seed uses null-ip mode");
        assert_eq!(s.negative_ttl_cap, 3600);
        assert_eq!(s.cache_max_ttl, 86400);
        assert_eq!(s.blocklist_refresh_interval, 86400);
        assert_eq!(s.cache_min_ttl, 1);
        assert_eq!(s.cache_capacity, 100_000);
    }

    // ── Settings swap ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn settings_swap_is_visible_to_subsequent_readers() {
        let (_dir, db) = crate::test_support::temp_db().await;
        let state = ResolverState::hydrate(&db).await.expect("hydrate");

        // Original: null-ip mode.
        assert_eq!(state.settings().block_mode, BlockMode::null_ip());

        // Swap to NxDomain.
        let new_settings = RuntimeSettings {
            block_mode: BlockMode::NxDomain,
            ..(*state.settings_full()).clone()
        };
        state.store_settings(new_settings);

        // Subsequent reader observes the swap.
        assert_eq!(state.settings().block_mode, BlockMode::NxDomain);
    }

    #[tokio::test]
    async fn settings_swap_concurrent_reader_observes_new_value() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let (_dir, db) = crate::test_support::temp_db().await;
        let state = Arc::new(ResolverState::hydrate(&db).await.expect("hydrate"));

        let state_r = Arc::clone(&state);
        let seen_nxdomain = Arc::new(AtomicBool::new(false));
        let seen_r = Arc::clone(&seen_nxdomain);

        // Spawn a reader that polls until it sees the NxDomain mode.
        let reader = tokio::spawn(async move {
            loop {
                if state_r.settings().block_mode == BlockMode::NxDomain {
                    seen_r.store(true, Ordering::Relaxed);
                    break;
                }
                tokio::task::yield_now().await;
            }
        });

        // Swap to NxDomain.
        let new_settings = RuntimeSettings {
            block_mode: BlockMode::NxDomain,
            ..(*state.settings_full()).clone()
        };
        state.store_settings(new_settings);

        reader.await.expect("reader task panicked");
        assert!(
            seen_nxdomain.load(Ordering::Relaxed),
            "reader must have observed NxDomain after swap"
        );
    }

    // ── Pause control (E12) ───────────────────────────────────────────────────

    #[tokio::test]
    async fn pause_sets_future_deadline_and_resume_clears_it() {
        let (_dir, db) = crate::test_support::temp_db().await;
        let state = ResolverState::hydrate(&db).await.expect("hydrate");

        // Fresh state is active.
        assert!(!state.blocking_paused());
        assert_eq!(state.paused_until(), None);

        // Pausing sets a future deadline.
        state.pause_for_secs(300);
        assert!(state.blocking_paused());
        let deadline = state.paused_until().expect("paused deadline");
        assert!(
            deadline >= Clock::now_secs(),
            "deadline must be in the future"
        );

        // Resuming clears it.
        state.resume();
        assert!(!state.blocking_paused());
        assert_eq!(state.paused_until(), None);
    }

    #[tokio::test]
    async fn expired_deadline_reads_as_active() {
        let (_dir, db) = crate::test_support::temp_db().await;
        let state = ResolverState::hydrate(&db).await.expect("hydrate");

        // Force a deadline in the past via the public API (negative seconds
        // resolves to 0/active), so drive the atomic through a tiny pause then
        // simulate expiry by storing a past deadline directly.
        state
            .paused_until
            .store(Clock::now_secs() - 1, Ordering::Relaxed);

        assert!(
            !state.blocking_paused(),
            "past deadline must read as active"
        );
        assert_eq!(state.paused_until(), None);
    }

    #[tokio::test]
    async fn pause_with_nonpositive_secs_is_immediate_resume() {
        let (_dir, db) = crate::test_support::temp_db().await;
        let state = ResolverState::hydrate(&db).await.expect("hydrate");

        state.pause_for_secs(300);
        assert!(state.blocking_paused());

        // Non-positive duration clears the pause rather than setting a past
        // deadline.
        state.pause_for_secs(0);
        assert!(!state.blocking_paused());
        assert_eq!(state.paused_until(), None);
    }

    // ── Hydration with no rows ─────────────────────────────────────────────────

    #[tokio::test]
    async fn hydration_empty_db_succeeds() {
        let (_dir, db) = crate::test_support::temp_db().await;
        let state = ResolverState::hydrate(&db).await.expect("hydrate empty db");

        assert!(state.blacklist().is_empty());
        assert!(state.allowlist().is_empty());
        assert!(state.blocklist().is_empty());
        // Local lookup for any name should miss.
        assert_eq!(
            state.local().lookup(&name("any.example.com"), Qtype::A),
            LocalMatch::Miss
        );
    }

    // ── Debug impl ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn resolver_state_debug_does_not_panic() {
        let (_dir, db) = crate::test_support::temp_db().await;
        let state = ResolverState::hydrate(&db).await.expect("hydrate");
        let s = format!("{state:?}");
        assert!(!s.is_empty());
    }

    // ── settings_full outlives await point ────────────────────────────────────

    #[tokio::test]
    async fn settings_full_arc_outlives_swap() {
        let (_dir, db) = crate::test_support::temp_db().await;
        let state = ResolverState::hydrate(&db).await.expect("hydrate");

        // Hold a full Arc to the old settings snapshot.
        let old_settings = state.settings_full();
        let old_block_mode = old_settings.block_mode.clone();

        // Swap in new settings.
        let new_settings = RuntimeSettings {
            block_mode: BlockMode::NxDomain,
            ..(*state.settings_full()).clone()
        };
        state.store_settings(new_settings);

        // The old Arc is unaffected.
        assert_eq!(old_block_mode, BlockMode::null_ip());
        // The live view reflects the new settings.
        assert_eq!(state.settings().block_mode, BlockMode::NxDomain);
    }
}
