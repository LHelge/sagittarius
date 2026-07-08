//! Applying a [`ConfigSnapshot`] to a secondary (SPEC §13, E18.8).
//!
//! Each section is written **through to the local SQLite** and then the live
//! in-memory state is swapped via the *same* seams the web admin handlers use
//! (`store_settings`, `reload_blacklist`, `rebuild_upstream_pool`,
//! `rebuild_forward_zones`, `refresh.trigger()`, …).  Because the DNS hot path
//! reads only the arc-swapped in-memory snapshots — never the DB directly — the
//! swap is the atomic visibility point: a section performs all its DB writes and
//! only then swaps, so a query never observes a torn set even though the DB
//! writes themselves are not wrapped in one transaction.
//!
//! Local-only state is deliberately untouched: the moka DNS cache, the query
//! log, sessions, and the offline blocklist cache stay per-instance.  Blocklist
//! **sources** are mirrored, but the aggregated set is rebuilt by the secondary's
//! own [`BlocklistScheduler`](crate::blocklist::scheduler) — the applier only
//! fires its refresh trigger.

use std::collections::HashSet;

use crate::{
    resolver::state::RuntimeSettings,
    storage::{
        admin_users::{AdminUserRepository, Role},
        blocklists::{BlocklistFormat, BlocklistRepository, NewBlocklist},
        forward_zones::{ForwardZoneRepository, NewForwardZone},
        lists::{AllowlistRepository, BlacklistRepository},
        local_records::{LocalRecordRepository, NewLocalRecord, RecordType},
        settings::{Settings, SettingsRepository},
        upstreams::{NewUpstream, Transport, UpstreamRepository},
    },
    sync::{
        SyncError,
        dto::{ConfigSnapshot, UpstreamDto},
    },
    web::AppState,
};

/// Map a live-swap (`WebResult`) failure into a [`SyncError::Apply`].
fn apply_err(e: impl std::fmt::Display) -> SyncError {
    SyncError::Apply(e.to_string())
}

/// Map a decode / parse failure into a [`SyncError::Decode`].
fn decode_err(e: impl std::fmt::Display) -> SyncError {
    SyncError::Decode(e.to_string())
}

impl AppState {
    /// Apply a full [`ConfigSnapshot`] to this secondary.
    ///
    /// Sections are applied in an order that lets later ones observe earlier
    /// changes (settings before the upstream-pool rebuild; everything before the
    /// blocklist refresh trigger).  Any error aborts the remaining sections and
    /// bubbles up so the caller keeps the last-good version (no partial success
    /// is recorded).
    pub(crate) async fn apply_config_snapshot(
        &self,
        snap: &ConfigSnapshot,
    ) -> Result<(), SyncError> {
        // ── Settings ───────────────────────────────────────────────────────────
        // Applied first so the upstream-pool rebuild below reads the mirrored
        // selection strategy. Cache capacity is fixed at build time (needs a
        // restart); the TTL bounds are pushed live like the settings handler.
        let settings = Settings::try_from(&snap.settings).map_err(decode_err)?;
        self.db.settings().update(&settings).await?;
        self.resolver
            .store_settings(RuntimeSettings::from(&settings));
        self.resolver
            .cache()
            .set_ttl_bounds(settings.cache_min_ttl, settings.cache_max_ttl);

        self.apply_upstreams(&snap.upstreams).await?;
        self.apply_blacklist(&snap.blacklist).await?;
        self.apply_allowlist(&snap.allowlist).await?;
        self.apply_local_records(&snap.local_records).await?;
        self.apply_forward_zones(&snap.forward_zones).await?;
        self.apply_admin_users(&snap.admin_users).await?;
        // Blocklist sources last: this only reconciles the source rows and fires
        // the secondary's own scheduler, which fetches + aggregates locally.
        self.apply_blocklists(&snap.blocklists).await?;

        Ok(())
    }

    /// Replace all upstreams, then rebuild the live pool.
    ///
    /// Every DTO is parsed **before** any database write, and the write itself
    /// is a single transactional [`replace_all`](UpstreamRepository::replace_all)
    /// — so a bad token from a version-skewed primary (or a crash mid-apply)
    /// can never leave a torn upstream table behind for the next restart to
    /// hydrate from.
    async fn apply_upstreams(&self, want: &[UpstreamDto]) -> Result<(), SyncError> {
        let rows = want
            .iter()
            .map(|dto| {
                Ok(NewUpstream {
                    address: dto.address.clone(),
                    transport: dto.transport.parse::<Transport>().map_err(decode_err)?,
                    tls_server_name: dto.tls_server_name.clone(),
                    enabled: dto.enabled,
                    sort_order: dto.sort_order,
                })
            })
            .collect::<Result<Vec<_>, SyncError>>()?;

        self.db.upstreams().replace_all(&rows).await?;
        self.rebuild_upstream_pool().await.map_err(apply_err)
    }

    /// Reconcile the admin blacklist to `want` (add missing, drop extra), swap.
    async fn apply_blacklist(&self, want: &[String]) -> Result<(), SyncError> {
        let have: Vec<String> = self
            .db
            .blacklist()
            .list()
            .await?
            .into_iter()
            .map(|e| e.domain)
            .collect();
        let want_set: HashSet<&str> = want.iter().map(String::as_str).collect();
        let have_set: HashSet<&str> = have.iter().map(String::as_str).collect();
        for d in &have {
            if !want_set.contains(d.as_str()) {
                self.db.blacklist().remove(d).await?;
            }
        }
        for d in want {
            if !have_set.contains(d.as_str()) {
                self.db.blacklist().add(d).await?;
            }
        }
        self.reload_blacklist().await.map_err(apply_err)
    }

    /// Reconcile the allowlist to `want`, swap.
    async fn apply_allowlist(&self, want: &[String]) -> Result<(), SyncError> {
        let have: Vec<String> = self
            .db
            .allowlist()
            .list()
            .await?
            .into_iter()
            .map(|e| e.domain)
            .collect();
        let want_set: HashSet<&str> = want.iter().map(String::as_str).collect();
        let have_set: HashSet<&str> = have.iter().map(String::as_str).collect();
        for d in &have {
            if !want_set.contains(d.as_str()) {
                self.db.allowlist().remove(d).await?;
            }
        }
        for d in want {
            if !have_set.contains(d.as_str()) {
                self.db.allowlist().add(d).await?;
            }
        }
        self.reload_allowlist().await.map_err(apply_err)
    }

    /// Replace all local records, then swap (also invalidates the reverse cache).
    ///
    /// Parse-first + transactional [`replace_all`](LocalRecordRepository::replace_all),
    /// for the same torn-table reason as [`apply_upstreams`](Self::apply_upstreams).
    async fn apply_local_records(
        &self,
        want: &[crate::sync::dto::LocalRecordDto],
    ) -> Result<(), SyncError> {
        let rows = want
            .iter()
            .map(|dto| {
                Ok(NewLocalRecord {
                    name: dto.name.clone(),
                    record_type: dto.record_type.parse::<RecordType>().map_err(decode_err)?,
                    value: dto.value.clone(),
                    ttl: dto.ttl,
                })
            })
            .collect::<Result<Vec<_>, SyncError>>()?;

        self.db.local_records().replace_all(&rows).await?;
        self.reload_local_records().await.map_err(apply_err)
    }

    /// Reconcile forward zones by `zone_suffix` (set target/enabled, insert new,
    /// delete absent), then rebuild the live forwarders.
    async fn apply_forward_zones(
        &self,
        want: &[crate::sync::dto::ForwardZoneDto],
    ) -> Result<(), SyncError> {
        let have = self.db.forward_zones().list().await?;
        let want_suffixes: HashSet<&str> = want.iter().map(|z| z.zone_suffix.as_str()).collect();

        for dto in want {
            match have.iter().find(|z| z.zone_suffix == dto.zone_suffix) {
                Some(existing) => {
                    if existing.target.as_deref() != dto.target.as_deref() {
                        self.db
                            .forward_zones()
                            .set_target(existing.id, dto.target.as_deref())
                            .await?;
                    }
                    if existing.enabled != dto.enabled {
                        self.db
                            .forward_zones()
                            .set_enabled(existing.id, dto.enabled)
                            .await?;
                    }
                }
                None => {
                    self.db
                        .forward_zones()
                        .insert(NewForwardZone {
                            zone_suffix: dto.zone_suffix.clone(),
                            target: dto.target.clone(),
                            enabled: dto.enabled,
                            sort_order: dto.sort_order,
                        })
                        .await?;
                }
            }
        }
        for z in &have {
            if !want_suffixes.contains(z.zone_suffix.as_str()) {
                self.db.forward_zones().delete(z.id).await?;
            }
        }
        self.rebuild_forward_zones().await.map_err(apply_err)
    }

    /// Reconcile admin users by username (upsert wanted, delete absent).
    async fn apply_admin_users(
        &self,
        want: &[crate::sync::dto::AdminUserDto],
    ) -> Result<(), SyncError> {
        let want_names: HashSet<&str> = want.iter().map(|u| u.username.as_str()).collect();
        for dto in want {
            let role: Role = dto.role.parse().map_err(decode_err)?;
            self.db
                .admin_users()
                .upsert(&dto.username, &dto.password_hash, role)
                .await?;
        }
        for name in self.db.admin_users().list_usernames().await? {
            if !want_names.contains(name.as_str()) {
                self.db.admin_users().delete_by_username(&name).await?;
            }
        }
        Ok(())
    }

    /// Reconcile blocklist **source rows** by URL, preserving the offline cache
    /// of unchanged sources, then fire the local refresh scheduler.
    async fn apply_blocklists(
        &self,
        want: &[crate::sync::dto::BlocklistSourceDto],
    ) -> Result<(), SyncError> {
        let have = self.db.blocklists().list().await?;
        let want_urls: HashSet<&str> = want.iter().map(|b| b.url.as_str()).collect();

        for dto in want {
            let format: BlocklistFormat = dto.format.parse().map_err(decode_err)?;
            match have.iter().find(|b| b.url == dto.url) {
                Some(existing) if existing.format == format => {
                    if existing.enabled != dto.enabled {
                        self.db
                            .blocklists()
                            .set_enabled(existing.id, dto.enabled)
                            .await?;
                    }
                }
                // New source, or the format changed: (re)insert. A format change
                // drops the old row's cached content (ON DELETE CASCADE), which
                // the next scheduler pass re-fetches — rare and acceptable.
                Some(existing) => {
                    self.db.blocklists().remove(existing.id).await?;
                    self.insert_blocklist(dto, format).await?;
                }
                None => self.insert_blocklist(dto, format).await?,
            }
        }
        for b in &have {
            if !want_urls.contains(b.url.as_str()) {
                self.db.blocklists().remove(b.id).await?;
            }
        }

        // The secondary keeps its own aggregated set + cache; the scheduler
        // fetches/parses/aggregates locally on this trigger.
        self.refresh.trigger();
        Ok(())
    }

    async fn insert_blocklist(
        &self,
        dto: &crate::sync::dto::BlocklistSourceDto,
        format: BlocklistFormat,
    ) -> Result<(), SyncError> {
        self.db
            .blocklists()
            .insert(NewBlocklist {
                url: dto.url.clone(),
                format,
                enabled: dto.enabled,
            })
            .await?;
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use crate::{
        codec::name::Name,
        storage::{
            admin_users::AdminUserRepository, blocklists::BlocklistRepository,
            local_records::LocalRecordRepository, settings::SettingsRepository,
            upstreams::UpstreamRepository,
        },
        sync::dto::{
            AdminUserDto, BlocklistSourceDto, ConfigSnapshot, ForwardZoneDto, LocalRecordDto,
            SettingsDto, UpstreamDto,
        },
        web::AppState,
    };
    use tempfile::TempDir;

    async fn state() -> (TempDir, AppState) {
        let (dir, db) = crate::test_support::temp_db().await;
        (dir, AppState::for_test(db).await)
    }

    fn snapshot() -> ConfigSnapshot {
        ConfigSnapshot {
            settings: SettingsDto {
                cache_min_ttl: 5,
                cache_max_ttl: 7200,
                cache_negative_ttl_cap: 300,
                cache_capacity: 50_000,
                blocking_mode: "nxdomain".to_owned(),
                custom_block_ipv4: None,
                custom_block_ipv6: None,
                blocklist_refresh_interval: 3600,
                ui_theme: "dark".to_owned(),
                query_log_enabled: true,
                query_log_retention_days: 14,
                upstream_selection_strategy: "random".to_owned(),
                upstream_parallel_fanout: 2,
            },
            upstreams: vec![UpstreamDto {
                address: "9.9.9.9".to_owned(),
                transport: "udp".to_owned(),
                tls_server_name: None,
                enabled: true,
                sort_order: 0,
            }],
            blacklist: vec!["ads.example.com.".to_owned()],
            allowlist: vec!["safe.example.com.".to_owned()],
            local_records: vec![LocalRecordDto {
                name: "nas.home.lan.".to_owned(),
                record_type: "A".to_owned(),
                value: "192.168.1.9".to_owned(),
                ttl: 300,
            }],
            forward_zones: vec![ForwardZoneDto {
                zone_suffix: "168.192.in-addr.arpa".to_owned(),
                target: Some("192.168.1.1".to_owned()),
                enabled: true,
                sort_order: 1,
            }],
            blocklists: vec![BlocklistSourceDto {
                url: "https://example.com/hosts.txt".to_owned(),
                format: "hosts".to_owned(),
                enabled: true,
            }],
            admin_users: vec![AdminUserDto {
                username: "admin".to_owned(),
                password_hash: "$argon2id$v=19$m=19456,t=2,p=1$abc$def".to_owned(),
                role: "admin".to_owned(),
            }],
        }
    }

    #[tokio::test]
    async fn apply_mirrors_all_sections_into_db_and_live_state() {
        let (_d, st) = state().await;
        st.apply_config_snapshot(&snapshot()).await.expect("apply");

        // Settings → DB + live snapshot.
        let s = st.db.settings().get().await.unwrap();
        assert_eq!(s.cache_max_ttl, 7200);
        assert_eq!(s.ui_theme, "dark");
        assert_eq!(
            st.resolver.settings().cache_max_ttl,
            7200,
            "live settings snapshot must reflect the applied config"
        );

        // Upstreams replaced (seed had 2 Cloudflare; snapshot has 1 Quad9).
        let ups = st.db.upstreams().list().await.unwrap();
        assert_eq!(ups.len(), 1);
        assert_eq!(ups[0].address, "9.9.9.9");

        // Blacklist/allowlist → DB + live sets.
        let bl: Name = "ads.example.com".parse().unwrap();
        assert!(st.resolver.blacklist().contains(&bl));
        let al: Name = "safe.example.com".parse().unwrap();
        assert!(st.resolver.allowlist().contains(&al));

        // Local record present and live.
        assert!(
            st.db
                .local_records()
                .list()
                .await
                .unwrap()
                .iter()
                .any(|r| r.name == "nas.home.lan.")
        );

        // Admin user mirrored, so login on the secondary works.
        assert!(
            st.db
                .admin_users()
                .find_by_username("admin")
                .await
                .unwrap()
                .is_some()
        );

        // Blocklist source mirrored.
        assert_eq!(st.db.blocklists().list().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn apply_is_idempotent_and_reconciles_removals() {
        let (_d, st) = state().await;
        st.apply_config_snapshot(&snapshot()).await.expect("first");
        // Applying the same snapshot twice must not duplicate rows.
        st.apply_config_snapshot(&snapshot()).await.expect("second");
        assert_eq!(st.db.upstreams().list().await.unwrap().len(), 1);
        assert_eq!(st.db.blocklists().list().await.unwrap().len(), 1);

        // A later snapshot that drops the blacklist entry must remove it locally.
        let mut snap2 = snapshot();
        snap2.blacklist.clear();
        st.apply_config_snapshot(&snap2).await.expect("third");
        let bl: Name = "ads.example.com".parse().unwrap();
        assert!(
            !st.resolver.blacklist().contains(&bl),
            "removed entries must be reconciled away"
        );
    }

    #[tokio::test]
    async fn apply_rejects_a_bad_enum_token() {
        let (_d, st) = state().await;
        let mut snap = snapshot();
        snap.settings.blocking_mode = "bogus".to_owned();
        assert!(matches!(
            st.apply_config_snapshot(&snap).await,
            Err(crate::sync::SyncError::Decode(_))
        ));
    }

    /// Regression (review finding): a snapshot carrying an unknown transport or
    /// record-type token — e.g. from a version-skewed, newer primary — must
    /// fail WITHOUT touching the existing rows. Previously the applier deleted
    /// every row before parsing, so the failure left a torn table that survived
    /// restarts.
    #[tokio::test]
    async fn bad_token_leaves_existing_rows_untouched() {
        let (_d, st) = state().await;

        // Unknown upstream transport: the seeded Cloudflare rows must survive.
        let mut snap = snapshot();
        snap.upstreams[0].transport = "doq".to_owned();
        assert!(matches!(
            st.apply_config_snapshot(&snap).await,
            Err(crate::sync::SyncError::Decode(_))
        ));
        let ups = st.db.upstreams().list().await.unwrap();
        assert_eq!(ups.len(), 2, "seeded upstreams must survive a bad token");

        // Unknown local record type: pre-seeded records must survive.
        st.db
            .local_records()
            .add(crate::storage::local_records::NewLocalRecord {
                name: "keep.home.lan".to_owned(),
                record_type: crate::storage::local_records::RecordType::A,
                value: "10.0.0.1".to_owned(),
                ttl: 60,
            })
            .await
            .unwrap();
        let mut snap = snapshot();
        snap.local_records[0].record_type = "CNAME".to_owned();
        assert!(matches!(
            st.apply_config_snapshot(&snap).await,
            Err(crate::sync::SyncError::Decode(_))
        ));
        assert!(
            st.db
                .local_records()
                .list()
                .await
                .unwrap()
                .iter()
                .any(|r| r.name == "keep.home.lan."),
            "existing local records must survive a bad token"
        );
    }
}
