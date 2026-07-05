-- Reverse of 20260705123646_api_keys.up.sql (drop index then table).

DROP INDEX IF EXISTS idx_api_keys_active;
DROP TABLE IF EXISTS api_keys;
