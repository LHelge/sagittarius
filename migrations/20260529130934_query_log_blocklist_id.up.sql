-- Per-list blocklist attribution (Epic E11).
--
-- Records which blocklist source was responsible for each block, so the admin
-- can see per-list effectiveness ("list X blocked N requests in the last 24h").
--
-- Design (E11 locked decisions):
--   * Stored as a PLAIN INTEGER, not a foreign key. A write-heavy query_log
--     with ON DELETE CASCADE / SET NULL would erase historical attribution the
--     moment a list is deleted; storing the bare id preserves history (the read
--     path LEFT JOINs blocklists and renders unknown ids as "removed list") and
--     keeps inserts cheap.
--   * Nullable: only BlockedByBlocklist rows carry an id; every other outcome
--     leaves it NULL.
--   * No extra index — the effectiveness query is windowed
--     (WHERE ts >= ? GROUP BY blocklist_id), already covered by idx_query_log_ts.

ALTER TABLE query_log
    ADD COLUMN blocklist_id INTEGER;
