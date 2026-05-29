-- Seed working defaults (DML only — DDL lives in the schema migration).
--
-- Every statement uses ON CONFLICT … DO NOTHING so that:
--   * a fresh database gets sensible defaults immediately (no first-run logic),
--   * re-running this SQL against an already-seeded database is a complete no-op
--     and never clobbers admin-changed values.
--
-- sqlx runs each migration exactly once; the idempotency guard here is
-- defence-in-depth and enables the test that verifies "re-apply preserves edits".

-- ── settings ──────────────────────────────────────────────────────────────────
-- The singleton row (id = 1 enforced by the schema CHECK).
-- ui_theme relies on the column DEFAULT ('auto') defined in the schema; we set
-- it explicitly here for clarity and consistency.

INSERT INTO settings (
    id,
    cache_min_ttl,
    cache_max_ttl,
    cache_negative_ttl_cap,
    cache_capacity,
    blocking_mode,
    custom_block_ipv4,
    custom_block_ipv6,
    blocklist_refresh_interval,
    ui_theme
) VALUES (
    1,
    1,          -- cache_min_ttl: 1 second (floor — never serve staler than this)
    86400,      -- cache_max_ttl: 24 h (ceiling — cap excessively long TTLs)
    3600,       -- cache_negative_ttl_cap: 1 h cap on NXDOMAIN / NODATA answers
    100000,     -- cache_capacity: 100 k entries
    'null-ip',  -- blocking_mode: respond with 0.0.0.0 / :: (safe default)
    NULL,       -- custom_block_ipv4: unused when blocking_mode != 'custom'
    NULL,       -- custom_block_ipv6: unused when blocking_mode != 'custom'
    86400,      -- blocklist_refresh_interval: 24 h
    'auto'      -- ui_theme: follow the browser's colour-scheme preference
) ON CONFLICT(id) DO NOTHING;

-- ── upstreams ─────────────────────────────────────────────────────────────────
-- Cloudflare public resolvers as default upstreams.
-- Explicit ids (1, 2) give ON CONFLICT(id) a stable target without requiring a
-- UNIQUE constraint on address — the schema is not modified.

INSERT INTO upstreams (
    id,
    address,
    transport,
    tls_server_name,
    enabled,
    sort_order
) VALUES (
    1,
    '1.1.1.1',
    'udp',
    NULL,   -- tls_server_name: not needed for plain UDP
    1,      -- enabled: true
    0       -- sort_order: primary
) ON CONFLICT(id) DO NOTHING;

INSERT INTO upstreams (
    id,
    address,
    transport,
    tls_server_name,
    enabled,
    sort_order
) VALUES (
    2,
    '1.0.0.1',
    'udp',
    NULL,   -- tls_server_name: not needed for plain UDP
    1,      -- enabled: true
    1       -- sort_order: secondary
) ON CONFLICT(id) DO NOTHING;
