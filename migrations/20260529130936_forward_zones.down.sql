-- Reverse of the up migration: drop the index, then the table (which takes its
-- seeded rows with it).
DROP INDEX IF EXISTS idx_forward_zones_enabled_sort;
DROP TABLE IF EXISTS forward_zones;
