-- Reverse of the up migration: drop the two columns (reverse order).
ALTER TABLE settings DROP COLUMN upstream_parallel_fanout;
ALTER TABLE settings DROP COLUMN upstream_selection_strategy;
