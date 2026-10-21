-- 0004_remove_stale_zdi_helm_source_state.sql — retire the ZDI and Helm sources.
--
-- Applied by `python -m app.migrate upgrade` (ADR-0007). The API only verifies
-- the schema version; it never creates DDL.
--
-- The ZDI Published, ZDI Upcoming and GHSA—Helm sources were retired
-- (ADR-0009). Their fetch-state rows in `source_state` (conditional-GET
-- validators, cadence timestamp, capped last payload) are stale; removing them
-- keeps a future `source_state` audit honest. Historical `feed_items` rows are
-- intentionally kept (they are real advisories) and age out through
-- RETENTION_DAYS. SQLite deployments carry no migration runner; stale rows
-- there are harmless because no source id ever reads them again.
--
-- The statement is idempotent, so a re-run is a no-op.

DELETE FROM source_state WHERE source_id IN ('zeroday', 'zeroday-upcoming', 'ghsa-helm');
