-- Reverse of the seed migration: remove the seeded default rows.
-- (A rollback intentionally discards these defaults along with any admin edits
-- to them, which is the expected semantics of reverting the seed.)

DELETE FROM upstreams WHERE id IN (1, 2);
DELETE FROM settings WHERE id = 1;
