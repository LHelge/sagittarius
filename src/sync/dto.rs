//! The config-sync wire contract (SPEC §13, E18.3).
//!
//! A [`ConfigSnapshot`] is the full **mirror-worthy** configuration of a primary
//! instance, serialized as JSON for a secondary to apply.  It deliberately
//! excludes everything that is per-instance or hot-path-local: sessions, the
//! query log, the offline blocklist cache, the moka DNS cache, and the pause
//! deadline (see SPEC §13).
//!
//! # Why DTOs (not serde on the storage types)
//!
//! The storage structs ([`Settings`], [`Upstream`], …) stay serde-free; the wire
//! form lives here as a set of DTOs with `From<&StorageType>` conversions.  This
//! keeps the storage layer decoupled from the wire, pins the field/`enum`
//! encoding in one place, and lets the version hash below stay stable.
//!
//! # Versioning
//!
//! There are no `updated_at`/revision columns on the config tables, so change
//! detection uses a **content hash**: [`ConfigSnapshot::version`] is the hex
//! SHA-256 of the snapshot's JSON.  The primary returns it as an `ETag`; the
//! secondary sends it back as `If-None-Match` to skip re-applying an unchanged
//! config.  Determinism relies on serde emitting struct fields in declaration
//! order and every `Vec` being built in a stable order by the snapshot builder
//! (see [`crate::web::sync`]).

use std::net::{Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    storage::{
        admin_users::AdminUser,
        blocklists::Blocklist,
        forward_zones::ForwardZone,
        local_records::LocalRecord,
        settings::{BlockingMode, SelectionStrategy, Settings},
        upstreams::Upstream,
    },
    web::crypto::ToHex,
};

// ── SettingsDto ───────────────────────────────────────────────────────────────

/// The singleton settings row, without its `id`.  Enum-valued columns are
/// carried as their canonical DB strings so the wire form is independent of the
/// Rust enum layout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettingsDto {
    pub cache_min_ttl: u32,
    pub cache_max_ttl: u32,
    pub cache_negative_ttl_cap: u32,
    pub cache_capacity: u64,
    pub blocking_mode: String,
    pub custom_block_ipv4: Option<String>,
    pub custom_block_ipv6: Option<String>,
    pub blocklist_refresh_interval: u32,
    pub ui_theme: String,
    pub query_log_enabled: bool,
    pub query_log_retention_days: u32,
    pub upstream_selection_strategy: String,
    pub upstream_parallel_fanout: u32,
}

impl From<&Settings> for SettingsDto {
    fn from(s: &Settings) -> Self {
        Self {
            cache_min_ttl: s.cache_min_ttl,
            cache_max_ttl: s.cache_max_ttl,
            cache_negative_ttl_cap: s.cache_negative_ttl_cap,
            cache_capacity: s.cache_capacity,
            blocking_mode: s.blocking_mode.as_str().to_owned(),
            custom_block_ipv4: s.custom_block_ipv4.map(|ip| ip.to_string()),
            custom_block_ipv6: s.custom_block_ipv6.map(|ip| ip.to_string()),
            blocklist_refresh_interval: s.blocklist_refresh_interval,
            ui_theme: s.ui_theme.clone(),
            query_log_enabled: s.query_log_enabled,
            query_log_retention_days: s.query_log_retention_days,
            upstream_selection_strategy: s.upstream_selection_strategy.as_str().to_owned(),
            upstream_parallel_fanout: s.upstream_parallel_fanout,
        }
    }
}

/// Inverse of [`From<&Settings>`]: parse a [`SettingsDto`] back into a storage
/// [`Settings`] for the secondary's applier.  Fails on an unknown enum token or
/// an unparseable custom IP.
impl TryFrom<&SettingsDto> for Settings {
    type Error = String;

    fn try_from(d: &SettingsDto) -> Result<Self, String> {
        let blocking_mode = d
            .blocking_mode
            .parse::<BlockingMode>()
            .map_err(|e| e.to_string())?;
        let custom_block_ipv4 = d
            .custom_block_ipv4
            .as_deref()
            .map(str::parse::<Ipv4Addr>)
            .transpose()
            .map_err(|e| format!("custom_block_ipv4: {e}"))?;
        let custom_block_ipv6 = d
            .custom_block_ipv6
            .as_deref()
            .map(str::parse::<Ipv6Addr>)
            .transpose()
            .map_err(|e| format!("custom_block_ipv6: {e}"))?;
        let upstream_selection_strategy = d
            .upstream_selection_strategy
            .parse::<SelectionStrategy>()
            .map_err(|e| e.to_string())?;

        Ok(Settings {
            cache_min_ttl: d.cache_min_ttl,
            cache_max_ttl: d.cache_max_ttl,
            cache_negative_ttl_cap: d.cache_negative_ttl_cap,
            cache_capacity: d.cache_capacity,
            blocking_mode,
            custom_block_ipv4,
            custom_block_ipv6,
            blocklist_refresh_interval: d.blocklist_refresh_interval,
            ui_theme: d.ui_theme.clone(),
            query_log_enabled: d.query_log_enabled,
            query_log_retention_days: d.query_log_retention_days,
            upstream_selection_strategy,
            upstream_parallel_fanout: d.upstream_parallel_fanout,
        })
    }
}

// ── UpstreamDto ───────────────────────────────────────────────────────────────

/// An upstream resolver definition, without its per-instance `id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpstreamDto {
    pub address: String,
    pub transport: String,
    pub tls_server_name: Option<String>,
    pub enabled: bool,
    pub sort_order: i64,
}

impl From<&Upstream> for UpstreamDto {
    fn from(u: &Upstream) -> Self {
        Self {
            address: u.address.clone(),
            transport: u.transport.as_str().to_owned(),
            tls_server_name: u.tls_server_name.clone(),
            enabled: u.enabled,
            sort_order: u.sort_order,
        }
    }
}

// ── LocalRecordDto ────────────────────────────────────────────────────────────

/// A local DNS record, without its per-instance `id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalRecordDto {
    pub name: String,
    pub record_type: String,
    pub value: String,
    pub ttl: u32,
}

impl From<&LocalRecord> for LocalRecordDto {
    fn from(r: &LocalRecord) -> Self {
        Self {
            name: r.name.clone(),
            record_type: r.record_type.as_str().to_owned(),
            value: r.value.clone(),
            ttl: r.ttl,
        }
    }
}

// ── ForwardZoneDto ────────────────────────────────────────────────────────────

/// A conditional-forward zone, without its per-instance `id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardZoneDto {
    pub zone_suffix: String,
    pub target: Option<String>,
    pub enabled: bool,
    pub sort_order: i64,
}

impl From<&ForwardZone> for ForwardZoneDto {
    fn from(z: &ForwardZone) -> Self {
        Self {
            zone_suffix: z.zone_suffix.clone(),
            target: z.target.clone(),
            enabled: z.enabled,
            sort_order: z.sort_order,
        }
    }
}

// ── BlocklistSourceDto ────────────────────────────────────────────────────────

/// A blocklist **source definition** only — url, format, enabled.  Fetched
/// content, entry counts, and HTTP validators are per-instance (the secondary
/// re-fetches independently), so they are deliberately excluded from the wire
/// form and from the version hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlocklistSourceDto {
    pub url: String,
    pub format: String,
    pub enabled: bool,
}

impl From<&Blocklist> for BlocklistSourceDto {
    fn from(b: &Blocklist) -> Self {
        Self {
            url: b.url.clone(),
            format: b.format.as_str().to_owned(),
            enabled: b.enabled,
        }
    }
}

// ── AdminUserDto ──────────────────────────────────────────────────────────────

/// An admin credential: username, Argon2id hash, and role.  The per-instance
/// `id` and timestamps are excluded (ids differ across instances; timestamps
/// would churn the version hash).  The secondary reconciles by username.
///
/// The hash is a password-equivalent secret — the sync hop must be TLS-fronted
/// (SPEC §11, §13).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminUserDto {
    pub username: String,
    pub password_hash: String,
    pub role: String,
}

impl From<&AdminUser> for AdminUserDto {
    fn from(u: &AdminUser) -> Self {
        Self {
            username: u.username.clone(),
            password_hash: u.password_hash.clone(),
            role: u.role.as_str().to_owned(),
        }
    }
}

// ── ConfigSnapshot ────────────────────────────────────────────────────────────

/// The full mirror-worthy configuration of a primary instance.
///
/// Field and `Vec` order is significant: it fixes the JSON byte sequence that
/// [`version`](Self::version) hashes.  The snapshot builder
/// ([`crate::web::sync`]) sorts each `Vec` by a stable key so the hash depends
/// only on content, not on DB row order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigSnapshot {
    pub settings: SettingsDto,
    pub upstreams: Vec<UpstreamDto>,
    pub blacklist: Vec<String>,
    pub allowlist: Vec<String>,
    pub local_records: Vec<LocalRecordDto>,
    pub forward_zones: Vec<ForwardZoneDto>,
    pub blocklists: Vec<BlocklistSourceDto>,
    pub admin_users: Vec<AdminUserDto>,
}

impl ConfigSnapshot {
    /// The content version: hex SHA-256 of the snapshot's canonical JSON.
    ///
    /// Returned by the primary as an `ETag` and echoed by the secondary as
    /// `If-None-Match` to skip re-applying unchanged config.
    #[must_use]
    pub fn version(&self) -> String {
        // Serialization of a plain data struct with only owned primitives cannot
        // fail; treat a failure as a bug rather than a runtime condition.
        let bytes = serde_json::to_vec(self).expect("ConfigSnapshot serializes to JSON");
        Sha256::digest(&bytes).to_hex()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ConfigSnapshot {
        ConfigSnapshot {
            settings: SettingsDto {
                cache_min_ttl: 1,
                cache_max_ttl: 86_400,
                cache_negative_ttl_cap: 3_600,
                cache_capacity: 100_000,
                blocking_mode: "null-ip".to_owned(),
                custom_block_ipv4: None,
                custom_block_ipv6: None,
                blocklist_refresh_interval: 86_400,
                ui_theme: "auto".to_owned(),
                query_log_enabled: true,
                query_log_retention_days: 30,
                upstream_selection_strategy: "random".to_owned(),
                upstream_parallel_fanout: 2,
            },
            upstreams: vec![UpstreamDto {
                address: "1.1.1.1".to_owned(),
                transport: "udp".to_owned(),
                tls_server_name: None,
                enabled: true,
                sort_order: 0,
            }],
            blacklist: vec!["ads.example.com.".to_owned()],
            allowlist: vec!["safe.example.com.".to_owned()],
            local_records: vec![LocalRecordDto {
                name: "router.home.lan.".to_owned(),
                record_type: "A".to_owned(),
                value: "192.168.1.1".to_owned(),
                ttl: 300,
            }],
            forward_zones: vec![ForwardZoneDto {
                zone_suffix: "168.192.in-addr.arpa".to_owned(),
                target: Some("192.168.1.1".to_owned()),
                enabled: true,
                sort_order: 0,
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

    #[test]
    fn json_round_trips() {
        let snap = sample();
        let json = serde_json::to_vec(&snap).expect("serialize");
        let back: ConfigSnapshot = serde_json::from_slice(&json).expect("deserialize");
        assert_eq!(snap, back);
    }

    #[test]
    fn version_is_hex_sha256_and_stable() {
        let snap = sample();
        let v = snap.version();
        assert_eq!(v.len(), 64, "hex SHA-256 is 64 chars");
        assert!(v.chars().all(|c| c.is_ascii_hexdigit()));
        // Recomputing over an identical snapshot yields the same version.
        assert_eq!(v, sample().version());
    }

    #[test]
    fn version_changes_when_content_changes() {
        let v0 = sample().version();
        let mut snap = sample();
        snap.blacklist.push("tracker.evil.net.".to_owned());
        assert_ne!(
            v0,
            snap.version(),
            "a config change must change the version"
        );
    }

    #[test]
    fn settings_dto_round_trips_through_storage_settings() {
        let dto = sample().settings;
        let settings = Settings::try_from(&dto).expect("dto → Settings");
        let back = SettingsDto::from(&settings);
        assert_eq!(dto, back);
    }

    #[test]
    fn settings_dto_try_from_rejects_bad_enum_and_ip() {
        let mut dto = sample().settings;
        dto.blocking_mode = "bogus".to_owned();
        assert!(Settings::try_from(&dto).is_err());

        let mut dto = sample().settings;
        dto.blocking_mode = "custom".to_owned();
        dto.custom_block_ipv4 = Some("not-an-ip".to_owned());
        assert!(Settings::try_from(&dto).is_err());
    }

    #[test]
    fn settings_dto_maps_enum_and_ip_fields() {
        use crate::storage::settings::{BlockingMode, SelectionStrategy, Settings};

        let settings = Settings {
            cache_min_ttl: 1,
            cache_max_ttl: 10,
            cache_negative_ttl_cap: 5,
            cache_capacity: 9,
            blocking_mode: BlockingMode::Custom,
            custom_block_ipv4: Some("203.0.113.1".parse().unwrap()),
            custom_block_ipv6: Some("2001:db8::1".parse().unwrap()),
            blocklist_refresh_interval: 100,
            ui_theme: "dark".to_owned(),
            query_log_enabled: false,
            query_log_retention_days: 7,
            upstream_selection_strategy: SelectionStrategy::Parallel,
            upstream_parallel_fanout: 3,
        };
        let dto = SettingsDto::from(&settings);
        assert_eq!(dto.blocking_mode, "custom");
        assert_eq!(dto.custom_block_ipv4.as_deref(), Some("203.0.113.1"));
        assert_eq!(dto.custom_block_ipv6.as_deref(), Some("2001:db8::1"));
        assert_eq!(dto.upstream_selection_strategy, "parallel");
    }
}
