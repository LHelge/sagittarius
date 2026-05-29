//! Persistent storage backed by SQLite.
//!
//! Acts as the durable system of record for configuration: upstreams, admin
//! credentials and sessions, blocklist source definitions, the admin
//! blacklist/allowlist, and local DNS records (see SPEC §4).
//!
//! Access is provided through [`sqlx`] with compile-time-checked queries
//! (`query!` / `query_as!`).  Embedded migrations are applied at startup via
//! `sqlx::migrate!` so the schema is always up-to-date.
//!
//! At startup the relevant tables are read into the in-memory data structures
//! held by the `app` module.  Subsequent writes go to SQLite first, then
//! refresh the live in-memory snapshot.

/// Errors that can occur while opening, migrating, reading, or writing
/// the SQLite database.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The database file could not be opened or created.
    #[error("could not open database at {path}: {source}")]
    Open {
        path: std::path::PathBuf,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    /// A schema migration failed.
    #[error("migration failed: {0}")]
    Migration(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_variants_display() {
        let e = Error::Migration("version mismatch".into());
        assert!(e.to_string().contains("version mismatch"));
    }
}
