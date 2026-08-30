-- E19.4: per-source unsupported-rule accounting for AdBlock-format lists.
--
-- The scheduler records how many content lines a source's parser recognized
-- as rules but could not represent (options, wildcards, regex, …) alongside
-- the accepted-rule count in `entry_count`, so the admin can see how much of
-- a subscribed list is actually in effect.

ALTER TABLE blocklists ADD COLUMN skipped_count INTEGER NOT NULL DEFAULT 0;
