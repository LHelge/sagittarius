-- Allow the `adblock` blocklist format (E19) in `blocklists.format`.
--
-- The initial schema's CHECK only admitted 'hosts' and 'domain-list', so
-- subscribing an AdBlock-format source was rejected by the database. SQLite
-- cannot alter a CHECK constraint in place, so the table is rebuilt.
--
-- `blocklist_cache` references `blocklists (id) ON DELETE CASCADE`; dropping
-- the parent with foreign keys enabled would cascade-delete the cached
-- content, so the cache is set aside and rebuilt around the new parent.

CREATE TABLE blocklist_cache_backup AS
    SELECT blocklist_id, content, fetched_at FROM blocklist_cache;

DROP TABLE blocklist_cache;

CREATE TABLE blocklists_new (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    url           TEXT    NOT NULL UNIQUE,
    format        TEXT    NOT NULL CHECK (format IN ('hosts', 'domain-list', 'adblock')),
    enabled       INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    entry_count   INTEGER NOT NULL DEFAULT 0,
    last_updated  INTEGER,        -- unix epoch; NULL until first successful fetch
    etag          TEXT,           -- HTTP ETag for conditional requests
    last_modified TEXT,           -- HTTP Last-Modified for conditional requests
    skipped_count INTEGER NOT NULL DEFAULT 0
);

INSERT INTO blocklists_new
    (id, url, format, enabled, entry_count, last_updated, etag, last_modified, skipped_count)
SELECT id, url, format, enabled, entry_count, last_updated, etag, last_modified, skipped_count
FROM blocklists;

-- Carry the AUTOINCREMENT high-water mark over so ids of previously removed
-- sources are never reused (`query_log.blocklist_id` still refers to them).
DELETE FROM sqlite_sequence WHERE name = 'blocklists_new';
INSERT INTO sqlite_sequence (name, seq)
    SELECT 'blocklists_new', seq FROM sqlite_sequence WHERE name = 'blocklists';

DROP TABLE blocklists;
ALTER TABLE blocklists_new RENAME TO blocklists;

CREATE TABLE blocklist_cache (
    blocklist_id  INTEGER NOT NULL PRIMARY KEY
                            REFERENCES blocklists (id) ON DELETE CASCADE,
    content       BLOB    NOT NULL,
    fetched_at    INTEGER NOT NULL DEFAULT (unixepoch())
);

INSERT INTO blocklist_cache (blocklist_id, content, fetched_at)
    SELECT blocklist_id, content, fetched_at FROM blocklist_cache_backup;

DROP TABLE blocklist_cache_backup;
