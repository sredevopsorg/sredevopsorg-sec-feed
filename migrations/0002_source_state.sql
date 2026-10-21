-- 0002_source_state.sql — per-source fetch state (conditional GET + cadence).
--
-- Applied by `python -m app.migrate upgrade` (ADR-0007). The API only verifies
-- the schema version; it never creates DDL. Every statement is idempotent so a
-- re-run is a no-op.
--
-- Why: several upstream feeds are large (Amazon Linux ALAS ~1.5 MB, CISA
-- ~1.4 MB) and change far less often than the 10-minute refresh. Storing the
-- validators lets a 304 skip the body, and `last_payload` lets a 304 still
-- produce feed items instead of emptying the source. `last_fetched_at` backs
-- the per-source minimum interval.

CREATE TABLE IF NOT EXISTS source_state (
    source_id TEXT PRIMARY KEY,
    etag TEXT,
    last_modified TEXT,
    last_fetched_at TIMESTAMPTZ,
    last_ok_at TIMESTAMPTZ,
    last_error TEXT,
    last_payload JSONB
);

-- Retention (RETENTION_DAYS) scans this column.
CREATE INDEX IF NOT EXISTS idx_feed_items_last_seen ON feed_items(last_seen DESC);

-- Same least-privilege contract as 0001: DML only for the runtime role.
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE source_state TO feed_app;

ALTER TABLE source_state ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS feed_app_rw ON source_state;
CREATE POLICY feed_app_rw ON source_state FOR ALL TO feed_app USING (true) WITH CHECK (true);
