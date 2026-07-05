-- E18.1: API keys for the secondary/fallback sync surface.
--
-- A secondary instance authenticates to the primary's read-only config-sync
-- API with a bearer key minted here.  Modelled on the `sessions` table: the
-- wire key is `{id}.{token}`, but only the SHA-256 hash of the token is stored,
-- so a database read alone cannot mint a usable key.  Keys are created, listed,
-- and revoked from the primary admin UI.

CREATE TABLE api_keys (
    id           TEXT    PRIMARY KEY,        -- opaque random id (the key's public prefix)
    token_hash   TEXT    NOT NULL,           -- hex SHA-256 of the bearer token; NEVER the raw token
    label        TEXT    NOT NULL,           -- operator-facing name, e.g. 'fallback-nas'
    created_at   INTEGER NOT NULL DEFAULT (unixepoch()),
    last_used_at INTEGER,                    -- unix epoch of the last successful auth; NULL until used
    revoked_at   INTEGER                     -- unix epoch when revoked; NULL while active (row kept for audit)
);

-- Speed up the auth-path lookup of active keys (revoked_at IS NULL).
CREATE INDEX idx_api_keys_active ON api_keys (revoked_at);
