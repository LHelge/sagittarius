//! Repository for the `forward_zones` table — conditional-forward zones.
//!
//! Provides the [`ForwardZoneRepository`] trait and its
//! [`SqliteForwardZoneRepo`] implementation.  A forward zone maps a DNS name
//! suffix (e.g. `168.192.in-addr.arpa`) to a `target` resolver; a query whose
//! name falls under an enabled zone is forwarded to that target instead of the
//! default upstream pool (E13.4).  All DB interaction uses compile-time-checked
//! `sqlx` macros against the `forward_zones` table defined in its migration.

use std::future::Future;

use sqlx::SqlitePool;

use super::Error;

// ── Result alias ────────────────────────────────────────────────────────────

pub type Result<T> = std::result::Result<T, Error>;

// ── ForwardZone ──────────────────────────────────────────────────────────────

/// A conditional-forward zone row.
#[derive(Debug, Clone, PartialEq)]
pub struct ForwardZone {
    /// Row primary key.
    pub id: i64,
    /// Name suffix the zone matches, e.g. `168.192.in-addr.arpa` (normalized,
    /// no leading or trailing dot).
    pub zone_suffix: String,
    /// Target resolver as `IP` or `IP:port`; `None` until the admin sets one.
    pub target: Option<String>,
    /// Whether this zone participates in routing.
    pub enabled: bool,
    /// Ordering key; lower values sort first in the admin UI.
    pub sort_order: i64,
}

/// Data required to insert a new forward zone (no `id` — assigned by the DB).
#[derive(Debug, Clone)]
pub struct NewForwardZone {
    /// Name suffix the zone matches.
    pub zone_suffix: String,
    /// Target resolver as `IP` or `IP:port`; `None` to leave unset.
    pub target: Option<String>,
    /// Whether this zone is active.
    pub enabled: bool,
    /// Ordering key.
    pub sort_order: i64,
}

// ── Private row struct ────────────────────────────────────────────────────────

/// Private projection for `query_as!` — primitive SQLite types only.
///
/// The non-null INTEGER columns use sqlx's `AS "col!"` override so they decode
/// to `i64`/`bool` rather than the conservative `Option<_>` sqlx-SQLite would
/// otherwise infer (it cannot always prove NOT NULL through a `WHERE`).
struct ForwardZoneRow {
    id: i64,
    zone_suffix: String,
    target: Option<String>,
    enabled: bool,
    sort_order: i64,
}

impl From<ForwardZoneRow> for ForwardZone {
    fn from(row: ForwardZoneRow) -> Self {
        ForwardZone {
            id: row.id,
            zone_suffix: row.zone_suffix,
            target: row.target,
            enabled: row.enabled,
            sort_order: row.sort_order,
        }
    }
}

// ── ForwardZoneRepository trait ──────────────────────────────────────────────

/// Repository for reading and writing conditional-forward zone rows.
///
/// Methods are declared as `fn(…) -> impl Future<…>` rather than `async fn` for
/// the same reason as the other repositories (see [`super::upstreams`]): it
/// avoids the `async_fn_in_trait` lint without forcing a `Send` bound onto every
/// implementation, while concrete call sites still get `Send` where needed.
pub trait ForwardZoneRepository {
    /// List all zones ordered by `sort_order`.
    fn list(&self) -> impl Future<Output = Result<Vec<ForwardZone>>>;

    /// List the **actionable** zones for the resolver hot path (E13.4): those
    /// that are enabled *and* have a target set, ordered by `sort_order`.
    ///
    /// An enabled zone with a `NULL` target has nowhere to forward, so it is
    /// excluded here rather than forcing every caller to filter it out.
    fn list_enabled(&self) -> impl Future<Output = Result<Vec<ForwardZone>>>;

    /// Set the `target` resolver of the zone with the given `id` (or clear it
    /// with `None`).
    fn set_target(&self, id: i64, target: Option<&str>) -> impl Future<Output = Result<()>>;

    /// Set the `enabled` flag on the zone with the given `id`.
    fn set_enabled(&self, id: i64, enabled: bool) -> impl Future<Output = Result<()>>;

    /// Insert a new (custom) zone and return the inserted row including its
    /// assigned `id`.  Future-friendly: the seeded reverse zones cover the
    /// common case, but the admin may add split-horizon forward zones later.
    fn insert(&self, zone: NewForwardZone) -> impl Future<Output = Result<ForwardZone>>;

    /// Delete the zone with the given `id`.
    fn delete(&self, id: i64) -> impl Future<Output = Result<()>>;
}

// ── SqliteForwardZoneRepo ─────────────────────────────────────────────────────

/// SQLite-backed [`ForwardZoneRepository`].
pub struct SqliteForwardZoneRepo {
    pool: SqlitePool,
}

impl SqliteForwardZoneRepo {
    /// Construct a new repository from an open [`crate::storage::Db`] pool.
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

impl ForwardZoneRepository for SqliteForwardZoneRepo {
    async fn list(&self) -> Result<Vec<ForwardZone>> {
        let rows = sqlx::query_as!(
            ForwardZoneRow,
            r#"SELECT
                id          AS "id!",
                zone_suffix,
                target,
                enabled     AS "enabled!: bool",
                sort_order  AS "sort_order!"
            FROM forward_zones
            ORDER BY sort_order"#
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(ForwardZone::from).collect())
    }

    async fn list_enabled(&self) -> Result<Vec<ForwardZone>> {
        let rows = sqlx::query_as!(
            ForwardZoneRow,
            r#"SELECT
                id          AS "id!",
                zone_suffix,
                target,
                enabled     AS "enabled!: bool",
                sort_order  AS "sort_order!"
            FROM forward_zones
            WHERE enabled = 1 AND target IS NOT NULL
            ORDER BY sort_order"#
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(ForwardZone::from).collect())
    }

    async fn set_target(&self, id: i64, target: Option<&str>) -> Result<()> {
        sqlx::query!(
            "UPDATE forward_zones SET target = ? WHERE id = ?",
            target,
            id,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn set_enabled(&self, id: i64, enabled: bool) -> Result<()> {
        let enabled_int = enabled as i64;
        sqlx::query!(
            "UPDATE forward_zones SET enabled = ? WHERE id = ?",
            enabled_int,
            id,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn insert(&self, zone: NewForwardZone) -> Result<ForwardZone> {
        let enabled = zone.enabled as i64;

        let id = sqlx::query!(
            r#"INSERT INTO forward_zones (zone_suffix, target, enabled, sort_order)
            VALUES (?, ?, ?, ?)
            RETURNING id"#,
            zone.zone_suffix,
            zone.target,
            enabled,
            zone.sort_order,
        )
        .fetch_one(&self.pool)
        .await?
        .id;

        Ok(ForwardZone {
            id,
            zone_suffix: zone.zone_suffix,
            target: zone.target,
            enabled: zone.enabled,
            sort_order: zone.sort_order,
        })
    }

    async fn delete(&self, id: i64) -> Result<()> {
        sqlx::query!("DELETE FROM forward_zones WHERE id = ?", id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Db;
    use tempfile::TempDir;

    async fn open_repo() -> (TempDir, SqliteForwardZoneRepo) {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("test.db");
        let db = Db::connect(&path).await.expect("connect");
        let repo = SqliteForwardZoneRepo::new(db.pool().clone());
        (dir, repo)
    }

    #[tokio::test]
    async fn seed_zones_present_disabled_and_untargeted() {
        let (_dir, repo) = open_repo().await;
        let zones = repo.list().await.expect("list");

        // 1 (/8) + 1 (/16) + 16 (/12) + 2 (ULA) = 20 seeded reverse zones.
        assert_eq!(zones.len(), 20, "all private reverse zones must be seeded");

        for z in &zones {
            assert!(!z.enabled, "{} must be seeded disabled", z.zone_suffix);
            assert!(
                z.target.is_none(),
                "{} must be seeded with a NULL target",
                z.zone_suffix
            );
        }

        // Spot-check representative suffixes are present.
        for suffix in [
            "10.in-addr.arpa",
            "168.192.in-addr.arpa",
            "16.172.in-addr.arpa",
            "31.172.in-addr.arpa",
            "c.f.ip6.arpa",
            "d.f.ip6.arpa",
        ] {
            assert!(
                zones.iter().any(|z| z.zone_suffix == suffix),
                "seed must contain {suffix}"
            );
        }
    }

    #[tokio::test]
    async fn list_is_ordered_by_sort_order() {
        let (_dir, repo) = open_repo().await;
        let zones = repo.list().await.expect("list");
        let mut prev = i64::MIN;
        for z in &zones {
            assert!(z.sort_order >= prev, "zones must be returned in sort order");
            prev = z.sort_order;
        }
    }

    #[tokio::test]
    async fn set_target_and_enabled_round_trip() {
        let (_dir, repo) = open_repo().await;
        let zones = repo.list().await.expect("list");
        let id = zones
            .iter()
            .find(|z| z.zone_suffix == "168.192.in-addr.arpa")
            .expect("seed zone")
            .id;

        repo.set_target(id, Some("192.168.1.1"))
            .await
            .expect("set target");
        repo.set_enabled(id, true).await.expect("enable");

        let after = repo.list().await.expect("list after");
        let zone = after.iter().find(|z| z.id == id).expect("zone present");
        assert_eq!(zone.target.as_deref(), Some("192.168.1.1"));
        assert!(zone.enabled);

        // Clearing the target with None must persist as NULL.
        repo.set_target(id, None).await.expect("clear target");
        let after = repo.list().await.expect("list after clear");
        let zone = after.iter().find(|z| z.id == id).expect("zone present");
        assert!(zone.target.is_none(), "target must be cleared to NULL");
    }

    #[tokio::test]
    async fn list_enabled_filters_disabled_and_untargeted() {
        let (_dir, repo) = open_repo().await;

        // Nothing is actionable initially (all seeds are disabled + NULL target).
        assert!(
            repo.list_enabled().await.expect("list_enabled").is_empty(),
            "no zone is actionable before configuration"
        );

        let zones = repo.list().await.expect("list");
        let id = zones[0].id;

        // Enabled but still no target → still excluded.
        repo.set_enabled(id, true).await.expect("enable");
        assert!(
            repo.list_enabled().await.expect("list_enabled").is_empty(),
            "enabled-but-untargeted zone must be excluded"
        );

        // Enabled + target → now actionable.
        repo.set_target(id, Some("10.0.0.1"))
            .await
            .expect("set target");
        let enabled = repo.list_enabled().await.expect("list_enabled");
        assert_eq!(enabled.len(), 1);
        assert_eq!(enabled[0].id, id);
        assert_eq!(enabled[0].target.as_deref(), Some("10.0.0.1"));

        // Disabling again removes it from the actionable set.
        repo.set_enabled(id, false).await.expect("disable");
        assert!(
            repo.list_enabled().await.expect("list_enabled").is_empty(),
            "disabled zone must be excluded even with a target"
        );
    }

    #[tokio::test]
    async fn insert_and_delete_custom_zone() {
        let (_dir, repo) = open_repo().await;

        let new = NewForwardZone {
            zone_suffix: "corp.internal".to_owned(),
            target: Some("10.0.0.53".to_owned()),
            enabled: true,
            sort_order: 100,
        };
        let inserted = repo.insert(new).await.expect("insert");
        assert!(inserted.id > 0);
        assert_eq!(inserted.zone_suffix, "corp.internal");

        // It should appear in list_enabled (enabled + target).
        let enabled = repo.list_enabled().await.expect("list_enabled");
        assert!(enabled.iter().any(|z| z.id == inserted.id));

        repo.delete(inserted.id).await.expect("delete");
        let after = repo.list().await.expect("list after delete");
        assert!(
            !after.iter().any(|z| z.id == inserted.id),
            "deleted zone must be gone"
        );
    }

    #[tokio::test]
    async fn duplicate_zone_suffix_is_rejected() {
        let (_dir, repo) = open_repo().await;
        let new = NewForwardZone {
            zone_suffix: "10.in-addr.arpa".to_owned(), // already seeded
            target: None,
            enabled: false,
            sort_order: 0,
        };
        assert!(
            repo.insert(new).await.is_err(),
            "duplicate zone_suffix must fail the UNIQUE constraint"
        );
    }
}
