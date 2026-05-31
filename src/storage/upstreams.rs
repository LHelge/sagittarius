//! Repository for the `upstreams` table — DNS resolver definitions.
//!
//! Provides the [`UpstreamRepository`] trait and its [`SqliteUpstreamRepo`]
//! implementation.  All DB interaction uses compile-time-checked `sqlx` macros
//! against the `upstreams` table defined in the schema migration.

use std::{fmt, future::Future, str::FromStr};

use sqlx::SqlitePool;

use super::Error;

// ── Result alias ────────────────────────────────────────────────────────────

pub type Result<T> = std::result::Result<T, Error>;

// ── Transport ────────────────────────────────────────────────────────────────

/// Transport protocol used to reach an upstream resolver.
///
/// Maps to/from the `transport` TEXT column values `'udp'`, `'tcp'`, `'dot'`,
/// and `'doh'`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::IntoStaticStr)]
pub enum Transport {
    /// Plain UDP (RFC 1035).
    #[strum(serialize = "udp")]
    Udp,
    /// Plain TCP (RFC 1035).
    #[strum(serialize = "tcp")]
    Tcp,
    /// DNS-over-TLS (RFC 7858).
    #[strum(serialize = "dot")]
    Dot,
    /// DNS-over-HTTPS (RFC 8484).
    #[strum(serialize = "doh")]
    Doh,
}

impl Transport {
    /// Returns the canonical TEXT representation stored in the database.
    ///
    /// Driven by `#[strum(serialize)]` ([`strum::IntoStaticStr`]); the
    /// value-carrying [`FromStr`] below is the inverse.
    pub fn as_str(&self) -> &'static str {
        self.into()
    }
}

impl fmt::Display for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Transport {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "udp" => Ok(Self::Udp),
            "tcp" => Ok(Self::Tcp),
            "dot" => Ok(Self::Dot),
            "doh" => Ok(Self::Doh),
            other => Err(Error::Decode(format!("unknown transport value: {other:?}"))),
        }
    }
}

// ── Upstream ─────────────────────────────────────────────────────────────────

/// A DNS upstream resolver row.
#[derive(Debug, Clone, PartialEq)]
pub struct Upstream {
    /// Row primary key.
    pub id: i64,
    /// IP address or hostname of the upstream resolver.
    pub address: String,
    /// Transport protocol.
    pub transport: Transport,
    /// TLS server name (SNI) for DoT/DoH; `None` for UDP/TCP.
    pub tls_server_name: Option<String>,
    /// Whether this upstream is used during resolution.
    pub enabled: bool,
    /// Ordering key; lower values are tried first.
    pub sort_order: i64,
}

/// Data required to insert a new upstream (no `id` — assigned by the DB).
#[derive(Debug, Clone)]
pub struct NewUpstream {
    /// IP address or hostname of the upstream resolver.
    pub address: String,
    /// Transport protocol.
    pub transport: Transport,
    /// TLS server name (SNI) for DoT/DoH; `None` for UDP/TCP.
    pub tls_server_name: Option<String>,
    /// Whether this upstream is active.  Defaults to `true` when creating.
    pub enabled: bool,
    /// Ordering key.
    pub sort_order: i64,
}

// ── Private row struct ────────────────────────────────────────────────────────

/// Private projection for `query_as!` — primitive SQLite types only.
///
/// The `SELECT`s use sqlx's non-null override (`AS "col!"`) on the NOT NULL
/// INTEGER columns. Without it, sqlx-SQLite's conservative nullability
/// inference types them as `Option<i64>` (it can't always prove NOT NULL,
/// especially with a `WHERE` on another integer column). The overrides let
/// these fields match the schema's real types; `enabled` is decoded straight
/// to `bool` via `AS "enabled!: bool"`.
struct UpstreamRow {
    id: i64,
    address: String,
    transport: String,
    tls_server_name: Option<String>,
    enabled: bool,
    sort_order: i64,
}

impl TryFrom<UpstreamRow> for Upstream {
    type Error = Error;

    fn try_from(row: UpstreamRow) -> Result<Self> {
        Ok(Upstream {
            id: row.id,
            address: row.address,
            transport: row.transport.parse::<Transport>()?,
            tls_server_name: row.tls_server_name,
            enabled: row.enabled,
            sort_order: row.sort_order,
        })
    }
}

/// Convert a `Vec<UpstreamRow>` into a `Vec<Upstream>`, propagating any decode
/// error.
fn rows_to_upstreams(rows: Vec<UpstreamRow>) -> Result<Vec<Upstream>> {
    rows.into_iter().map(Upstream::try_from).collect()
}

// ── UpstreamRepository trait ─────────────────────────────────────────────────

/// Repository for reading and writing upstream resolver rows.
///
/// # `impl Future` instead of `async fn`
///
/// The repository traits declare methods as `fn(…) -> impl Future<Output = …>`
/// rather than `async fn`. The two are equivalent for callers and the `impl`
/// blocks still write `async fn`, but the explicit form avoids the
/// `async_fn_in_trait` lint without committing every implementation to a `Send`
/// bound. All call sites are concrete, so `Send` still leaks through where it is
/// needed (axum handlers, spawned subsystems).
pub trait UpstreamRepository {
    /// List all upstreams ordered by `sort_order`.
    fn list(&self) -> impl Future<Output = Result<Vec<Upstream>>>;

    /// List only enabled upstreams ordered by `sort_order`.
    ///
    /// This is the hot-path read used by the resolver (Epic E5).
    fn list_enabled(&self) -> impl Future<Output = Result<Vec<Upstream>>>;

    /// Insert a new upstream and return the inserted row (including the new `id`).
    fn insert(&self, upstream: NewUpstream) -> impl Future<Output = Result<Upstream>>;

    /// Persist all mutable fields of an existing upstream row.
    fn update(&self, upstream: &Upstream) -> impl Future<Output = Result<()>>;

    /// Delete the upstream with the given `id`.
    fn delete(&self, id: i64) -> impl Future<Output = Result<()>>;

    /// Set the `enabled` flag on the upstream with the given `id`.
    fn set_enabled(&self, id: i64, enabled: bool) -> impl Future<Output = Result<()>>;
}

// ── SqliteUpstreamRepo ────────────────────────────────────────────────────────

/// SQLite-backed [`UpstreamRepository`].
pub struct SqliteUpstreamRepo {
    pool: SqlitePool,
}

impl SqliteUpstreamRepo {
    /// Construct a new repository from an open [`crate::storage::Db`].
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

impl UpstreamRepository for SqliteUpstreamRepo {
    async fn list(&self) -> Result<Vec<Upstream>> {
        let rows = sqlx::query_as!(
            UpstreamRow,
            r#"SELECT
                id              AS "id!",
                address,
                transport,
                tls_server_name,
                enabled         AS "enabled!: bool",
                sort_order      AS "sort_order!"
            FROM upstreams
            ORDER BY sort_order"#
        )
        .fetch_all(&self.pool)
        .await?;

        rows_to_upstreams(rows)
    }

    async fn list_enabled(&self) -> Result<Vec<Upstream>> {
        let rows = sqlx::query_as!(
            UpstreamRow,
            r#"SELECT
                id              AS "id!",
                address,
                transport,
                tls_server_name,
                enabled         AS "enabled!: bool",
                sort_order      AS "sort_order!"
            FROM upstreams
            WHERE enabled = 1
            ORDER BY sort_order"#
        )
        .fetch_all(&self.pool)
        .await?;

        rows_to_upstreams(rows)
    }

    async fn insert(&self, upstream: NewUpstream) -> Result<Upstream> {
        let transport = upstream.transport.as_str();
        let enabled = upstream.enabled as i64;

        let id = sqlx::query!(
            r#"INSERT INTO upstreams (address, transport, tls_server_name, enabled, sort_order)
            VALUES (?, ?, ?, ?, ?)
            RETURNING id"#,
            upstream.address,
            transport,
            upstream.tls_server_name,
            enabled,
            upstream.sort_order,
        )
        .fetch_one(&self.pool)
        .await?
        .id;

        Ok(Upstream {
            id,
            address: upstream.address,
            transport: upstream.transport,
            tls_server_name: upstream.tls_server_name,
            enabled: upstream.enabled,
            sort_order: upstream.sort_order,
        })
    }

    async fn update(&self, upstream: &Upstream) -> Result<()> {
        let transport = upstream.transport.as_str();
        let enabled = upstream.enabled as i64;

        sqlx::query!(
            r#"UPDATE upstreams SET
                address         = ?,
                transport       = ?,
                tls_server_name = ?,
                enabled         = ?,
                sort_order      = ?
            WHERE id = ?"#,
            upstream.address,
            transport,
            upstream.tls_server_name,
            enabled,
            upstream.sort_order,
            upstream.id,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete(&self, id: i64) -> Result<()> {
        sqlx::query!("DELETE FROM upstreams WHERE id = ?", id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn set_enabled(&self, id: i64, enabled: bool) -> Result<()> {
        let enabled_int = enabled as i64;
        sqlx::query!(
            "UPDATE upstreams SET enabled = ? WHERE id = ?",
            enabled_int,
            id,
        )
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

    async fn open_repo() -> (TempDir, SqliteUpstreamRepo) {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("test.db");
        let db = Db::connect(&path).await.expect("connect");
        let repo = SqliteUpstreamRepo::new(db.pool().clone());
        (dir, repo)
    }

    // ── Transport unit tests ──────────────────────────────────────────────────

    #[test]
    fn transport_display() {
        assert_eq!(Transport::Udp.to_string(), "udp");
        assert_eq!(Transport::Tcp.to_string(), "tcp");
        assert_eq!(Transport::Dot.to_string(), "dot");
        assert_eq!(Transport::Doh.to_string(), "doh");
    }

    #[test]
    fn transport_from_str_valid() {
        assert_eq!("udp".parse::<Transport>().unwrap(), Transport::Udp);
        assert_eq!("tcp".parse::<Transport>().unwrap(), Transport::Tcp);
        assert_eq!("dot".parse::<Transport>().unwrap(), Transport::Dot);
        assert_eq!("doh".parse::<Transport>().unwrap(), Transport::Doh);
    }

    #[test]
    fn transport_from_str_invalid() {
        let err = "grpc".parse::<Transport>();
        assert!(err.is_err(), "invalid transport must fail");
        let msg = err.unwrap_err().to_string();
        assert!(
            msg.contains("grpc"),
            "error must mention the bad value: {msg}"
        );
    }

    // ── list() / list_enabled() ───────────────────────────────────────────────

    #[tokio::test]
    async fn list_returns_seeded_upstreams_in_order() {
        let (_dir, repo) = open_repo().await;
        let upstreams = repo.list().await.expect("list");

        assert_eq!(upstreams.len(), 2);
        assert_eq!(upstreams[0].address, "1.1.1.1");
        assert_eq!(upstreams[1].address, "1.0.0.1");
        assert!(upstreams[0].sort_order <= upstreams[1].sort_order);
    }

    #[tokio::test]
    async fn list_enabled_returns_only_enabled() {
        let (_dir, repo) = open_repo().await;

        // Both seeded upstreams are enabled.
        let enabled = repo.list_enabled().await.expect("list_enabled");
        assert_eq!(enabled.len(), 2, "both seeded upstreams must be enabled");

        // Disable one and verify it's excluded.
        let id_to_disable = enabled[1].id;
        repo.set_enabled(id_to_disable, false)
            .await
            .expect("set_enabled");

        let enabled_after = repo
            .list_enabled()
            .await
            .expect("list_enabled after disable");
        assert_eq!(enabled_after.len(), 1);
        assert_ne!(enabled_after[0].id, id_to_disable);
    }

    #[tokio::test]
    async fn seed_upstreams_transport_is_udp_and_enabled() {
        let (_dir, repo) = open_repo().await;
        let upstreams = repo.list().await.expect("list");

        for u in &upstreams {
            assert_eq!(u.transport, Transport::Udp, "{} must use UDP", u.address);
            assert!(u.enabled, "{} must be enabled", u.address);
        }
    }

    // ── insert() ──────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn insert_dot_upstream_round_trips() {
        let (_dir, repo) = open_repo().await;

        let new = NewUpstream {
            address: "9.9.9.9".to_owned(),
            transport: Transport::Dot,
            tls_server_name: Some("dns.quad9.net".to_owned()),
            enabled: true,
            sort_order: 10,
        };

        let inserted = repo.insert(new).await.expect("insert");

        assert!(inserted.id > 0);
        assert_eq!(inserted.address, "9.9.9.9");
        assert_eq!(inserted.transport, Transport::Dot);
        assert_eq!(inserted.tls_server_name.as_deref(), Some("dns.quad9.net"));
        assert!(inserted.enabled);
        assert_eq!(inserted.sort_order, 10);

        // Verify it round-trips through the DB.
        let all = repo.list().await.expect("list after insert");
        let found = all
            .iter()
            .find(|u| u.id == inserted.id)
            .expect("inserted upstream in list");
        assert_eq!(found.transport, Transport::Dot);
        assert_eq!(found.tls_server_name.as_deref(), Some("dns.quad9.net"));
    }

    #[tokio::test]
    async fn insert_doh_upstream_round_trips() {
        let (_dir, repo) = open_repo().await;

        let new = NewUpstream {
            address: "https://cloudflare-dns.com/dns-query".to_owned(),
            transport: Transport::Doh,
            tls_server_name: Some("cloudflare-dns.com".to_owned()),
            enabled: false,
            sort_order: 99,
        };

        let inserted = repo.insert(new).await.expect("insert DoH");
        assert_eq!(inserted.transport, Transport::Doh);
        assert!(!inserted.enabled);
    }

    // ── update() ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn update_upstream() {
        let (_dir, repo) = open_repo().await;

        let mut upstreams = repo.list().await.expect("list");
        let mut first = upstreams.remove(0);

        first.address = "8.8.8.8".to_owned();
        first.transport = Transport::Tcp;
        first.sort_order = 50;

        repo.update(&first).await.expect("update");

        let all = repo.list().await.expect("list after update");
        let updated = all.iter().find(|u| u.id == first.id).expect("updated row");
        assert_eq!(updated.address, "8.8.8.8");
        assert_eq!(updated.transport, Transport::Tcp);
        assert_eq!(updated.sort_order, 50);
    }

    // ── delete() ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn delete_upstream() {
        let (_dir, repo) = open_repo().await;

        let upstreams = repo.list().await.expect("list");
        let id_to_delete = upstreams[0].id;

        repo.delete(id_to_delete).await.expect("delete");

        let remaining = repo.list().await.expect("list after delete");
        assert_eq!(remaining.len(), 1);
        assert_ne!(remaining[0].id, id_to_delete);
    }

    // ── set_enabled() ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn set_enabled_false_then_true() {
        let (_dir, repo) = open_repo().await;

        let upstreams = repo.list().await.expect("list");
        let id = upstreams[0].id;

        // Disable.
        repo.set_enabled(id, false).await.expect("disable");
        let after_disable = repo.list().await.expect("list after disable");
        let row = after_disable.iter().find(|u| u.id == id).unwrap();
        assert!(!row.enabled);

        // Re-enable.
        repo.set_enabled(id, true).await.expect("re-enable");
        let after_enable = repo.list().await.expect("list after re-enable");
        let row = after_enable.iter().find(|u| u.id == id).unwrap();
        assert!(row.enabled);
    }
}
