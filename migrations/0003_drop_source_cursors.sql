-- 0003_drop_source_cursors.sql — retire the OSSF Malicious Packages source.
--
-- Applied by `python -m app.migrate upgrade` (ADR-0007). The API only verifies
-- the schema version; it never creates DDL.
--
-- `source_cursors` held one row per source: the last commit SHA processed by
-- the OpenSSF Malicious Packages source (ADR-0008). That source was retired, and
-- no other source ever wrote a cursor: conditional GET / cadence state lives in
-- `source_state`. Dropping the table also drops its grants and RLS policy, so
-- `feed_app` keeps DML only on the tables it still uses.
--
-- The source's fetch-state row is stale too; removing it keeps a future
-- `source_state` audit honest. Historical `feed_items` rows are intentionally
-- kept (they are real advisories) and age out through RETENTION_DAYS.
--
-- Every statement is idempotent, so a re-run is a no-op.

DELETE FROM source_state WHERE source_id = 'ossf-malicious';

DROP TABLE IF EXISTS source_cursors;
