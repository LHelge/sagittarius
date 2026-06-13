-- E15.5: operator-selectable upstream selection strategy + parallel fan-out.
--
-- `upstream_selection_strategy` chooses how the pool picks an upstream per query:
--   'random'           — uniform shuffle (the v0.1 default behaviour),
--   'latency-weighted' — bias toward faster, healthier upstreams,
--   'parallel'         — race the first N upstreams, take the first success.
-- `upstream_parallel_fanout` is the N used in 'parallel' mode (ignored otherwise).
ALTER TABLE settings
    ADD COLUMN upstream_selection_strategy TEXT NOT NULL DEFAULT 'random'
        CHECK (upstream_selection_strategy IN ('random', 'latency-weighted', 'parallel'));

ALTER TABLE settings
    ADD COLUMN upstream_parallel_fanout INTEGER NOT NULL DEFAULT 2
        CHECK (upstream_parallel_fanout >= 1);
