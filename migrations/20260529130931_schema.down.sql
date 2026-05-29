-- Reverse of the initial schema: drop every table it created.
-- Order matters — drop tables that hold foreign keys before the tables they
-- reference. (Dropping a table also drops its indexes.)

DROP TABLE IF EXISTS local_records;
DROP TABLE IF EXISTS allowlist;
DROP TABLE IF EXISTS blacklist;
DROP TABLE IF EXISTS blocklist_cache;  -- FK → blocklists
DROP TABLE IF EXISTS blocklists;
DROP TABLE IF EXISTS sessions;         -- FK → admin_users
DROP TABLE IF EXISTS admin_users;
DROP TABLE IF EXISTS upstreams;
DROP TABLE IF EXISTS settings;
