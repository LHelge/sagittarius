-- Reverse of 20261115231300_blocklist_adblock_format.up.sql.
--
-- Rebuilds `blocklists` with the original CHECK ('hosts', 'domain-list').
-- Sources in the `adblock` format cannot be represented under that
-- constraint, so they (and their cached content) are removed.

CREATE TABLE blocklist_cache_backup AS
    SELECT c.blocklist_id, c.content, c.fetched_at
    FROM blocklist_cache c
    JOIN blocklists b ON b.id = c.blocklist_id
    WHERE b.format IN ('hosts', 'domain-list');

DROP TABLE blocklist_cache;

CREATE TABLE blocklists_old (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    url           TEXT    NOT NULL UNIQUE,
    format        TEXT    NOT NULL CHECK (format IN ('hosts', 'domain-list')),
    enabled       INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    entry_count   INTEGER NOT NULL DEFAULT 0,
    last_updated  INTEGER,        -- unix epoch; NULL until first successful fetch
    etag          TEXT,           -- HTTP ETag for conditional requests
    last_modified TEXT,           -- HTTP Last-Modified for conditional requests
    skipped_count INTEGER NOT NULL DEFAULT 0
);

INSERT INTO blocklists_old
    (id, url, format, enabled, entry_count, last_updated, etag, last_modified, skipped_count)
SELECT id, url, format, enabled, entry_count, last_updated, etag, last_modified, skipped_count
FROM blocklists
WHERE format IN ('hosts', 'domain-list');

DELETE FROM sqlite_sequence WHERE name = 'blocklists_old';
INSERT INTO sqlite_sequence (name, seq)
    SELECT 'blocklists_old', seq FROM sqlite_sequence WHERE name = 'blocklists';

DROP TABLE blocklists;
ALTER TABLE blocklists_old RENAME TO blocklists;

CREATE TABLE blocklist_cache (
    blocklist_id  INTEGER NOT NULL PRIMARY KEY
                            REFERENCES blocklists (id) ON DELETE CASCADE,
    content       BLOB    NOT NULL,
    fetched_at    INTEGER NOT NULL DEFAULT (unixepoch())
);

INSERT INTO blocklist_cache (blocklist_id, content, fetched_at)
    SELECT blocklist_id, content, fetched_at FROM blocklist_cache_backup;

DROP TABLE blocklist_cache_backup;
