-- Initial schema (DDL only — no seed data; seed lives in the seed_defaults
-- migration).
--
-- Conventions used throughout:
--   * Timestamps are stored as INTEGER unix-epoch seconds via DEFAULT (unixepoch()).
--   * Booleans are INTEGER with CHECK (col IN (0, 1)).
--   * Foreign keys are relied upon; the pool enables PRAGMA foreign_keys = ON.

-- ── settings ──────────────────────────────────────────────────────────────────
-- Singleton configuration row.  The CHECK (id = 1) guard (and the PRIMARY KEY
-- uniqueness) together ensure at most one row can ever exist.

CREATE TABLE settings (
    id                          INTEGER PRIMARY KEY CHECK (id = 1),

    -- Cache bounds
    cache_min_ttl               INTEGER NOT NULL,
    cache_max_ttl               INTEGER NOT NULL,
    cache_negative_ttl_cap      INTEGER NOT NULL,
    cache_capacity              INTEGER NOT NULL,

    -- Blocking
    blocking_mode               TEXT NOT NULL
                                    CHECK (blocking_mode IN ('nxdomain', 'null-ip', 'custom')),
    custom_block_ipv4           TEXT,   -- used only when blocking_mode = 'custom'
    custom_block_ipv6           TEXT,   -- used only when blocking_mode = 'custom'

    -- Refresh
    blocklist_refresh_interval  INTEGER NOT NULL,   -- seconds

    -- UI preferences
    ui_theme                    TEXT NOT NULL DEFAULT 'auto'
);

-- ── upstreams ─────────────────────────────────────────────────────────────────

CREATE TABLE upstreams (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    address         TEXT    NOT NULL,
    transport       TEXT    NOT NULL
                                CHECK (transport IN ('udp', 'tcp', 'dot', 'doh')),
    tls_server_name TEXT,           -- required for DoT/DoH; nullable otherwise
    enabled         INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    sort_order      INTEGER NOT NULL DEFAULT 0
);

-- Speed-up the hot-path query that loads all enabled upstreams in order.
CREATE INDEX idx_upstreams_enabled_sort ON upstreams (enabled, sort_order);

-- ── admin_users ───────────────────────────────────────────────────────────────
-- Auth logic (Argon2id hashing, CRUD) is implemented in Epic E8.

CREATE TABLE admin_users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'admin',
    created_at    INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at    INTEGER NOT NULL DEFAULT (unixepoch())
);

-- ── sessions ──────────────────────────────────────────────────────────────────
-- Session logic is implemented in Epic E8.
-- id is an opaque random string; only the hash of the bearer token is stored.

CREATE TABLE sessions (
    id          TEXT    PRIMARY KEY,        -- opaque session identifier
    token_hash  TEXT    NOT NULL,           -- NEVER store the raw token
    user_id     INTEGER NOT NULL REFERENCES admin_users (id) ON DELETE CASCADE,
    created_at  INTEGER NOT NULL DEFAULT (unixepoch()),
    expires_at  INTEGER NOT NULL
);

CREATE INDEX idx_sessions_user_id    ON sessions (user_id);
CREATE INDEX idx_sessions_expires_at ON sessions (expires_at);

-- ── blocklists ────────────────────────────────────────────────────────────────
-- Source definitions for subscribed blocklists.

CREATE TABLE blocklists (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    url           TEXT    NOT NULL UNIQUE,
    format        TEXT    NOT NULL CHECK (format IN ('hosts', 'domain-list')),
    enabled       INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    entry_count   INTEGER NOT NULL DEFAULT 0,
    last_updated  INTEGER,        -- unix epoch; NULL until first successful fetch
    etag          TEXT,           -- HTTP ETag for conditional requests
    last_modified TEXT            -- HTTP Last-Modified for conditional requests
);

-- ── blocklist_cache ───────────────────────────────────────────────────────────
-- One cached copy of the raw fetched content per blocklist source.
-- Allows the service to start and parse lists while offline.

CREATE TABLE blocklist_cache (
    blocklist_id  INTEGER NOT NULL PRIMARY KEY
                            REFERENCES blocklists (id) ON DELETE CASCADE,
    content       BLOB    NOT NULL,
    fetched_at    INTEGER NOT NULL DEFAULT (unixepoch())
);

-- ── blacklist ─────────────────────────────────────────────────────────────────
-- Domains the admin has explicitly blocked (highest precedence).

CREATE TABLE blacklist (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    domain     TEXT    NOT NULL UNIQUE,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- ── allowlist ─────────────────────────────────────────────────────────────────
-- Domains the admin has explicitly allowed (suppresses blocklist matches).

CREATE TABLE allowlist (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    domain     TEXT    NOT NULL UNIQUE,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- ── local_records ─────────────────────────────────────────────────────────────
-- Authoritative local DNS records; name may be a wildcard (e.g. *.home.lan).
-- A single name may carry both an A and an AAAA record, hence the composite
-- UNIQUE constraint rather than a UNIQUE on name alone.

CREATE TABLE local_records (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,   -- may be a wildcard like *.home.lan
    record_type TEXT    NOT NULL,   -- e.g. 'A', 'AAAA'
    value       TEXT    NOT NULL,
    ttl         INTEGER NOT NULL,
    UNIQUE (name, record_type)
);
