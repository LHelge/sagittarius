-- Persistent per-query log (Epic E10).
--
-- Replaces the in-memory 1000-entry ring buffer as the single source of truth
-- for query history and restart-surviving dashboard telemetry. Writes are
-- decoupled from the DNS hot path by a dedicated batching writer task (E10.4);
-- this migration only provides the durable schema.
--
-- Conventions (see the schema migration):
--   * Booleans are INTEGER with CHECK (col IN (0, 1)).
--   * Timestamps are INTEGER epoch. NOTE: query_log.ts is epoch *milliseconds*
--     (finer-grained ordering for a high-rate event stream), unlike the
--     epoch-seconds columns elsewhere.

-- ── query_log ─────────────────────────────────────────────────────────────────
-- One row per resolved query. id is the chronological order key and the keyset
-- pagination cursor (E10.3); no extra index is needed for pagination.

CREATE TABLE query_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          INTEGER NOT NULL,   -- receipt time, epoch milliseconds
    client      TEXT    NOT NULL,   -- client IP (no port)
    qname       TEXT    NOT NULL,
    qtype       TEXT    NOT NULL,
    outcome     TEXT    NOT NULL,   -- stable token from Outcome::as_str (E10.2)
    rcode       INTEGER,            -- response code; NULL when not applicable
    upstream    TEXT,               -- answering upstream; NULL when not forwarded
    latency_ms  INTEGER NOT NULL
);

-- Retention purge (E10.5) deletes by ts; pagination uses the PK instead.
CREATE INDEX idx_query_log_ts ON query_log (ts);

-- ── settings ──────────────────────────────────────────────────────────────────
-- Privacy controls for the query log. The singleton row (id = 1) picks up these
-- defaults automatically via the column DEFAULT clauses.

ALTER TABLE settings
    ADD COLUMN query_log_enabled INTEGER NOT NULL DEFAULT 1
        CHECK (query_log_enabled IN (0, 1));

ALTER TABLE settings
    ADD COLUMN query_log_retention_days INTEGER NOT NULL DEFAULT 30;
