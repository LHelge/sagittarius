-- Inverse of 20260529130933_query_log.up.sql.
-- Drop the settings columns first, then the index and the table.

ALTER TABLE settings DROP COLUMN query_log_retention_days;
ALTER TABLE settings DROP COLUMN query_log_enabled;

DROP INDEX IF EXISTS idx_query_log_ts;
DROP TABLE IF EXISTS query_log;
