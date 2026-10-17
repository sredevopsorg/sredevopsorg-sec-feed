-- 0001_baseline.sql — baseline schema for the PostgreSQL/Supabase backend.
--
-- Applied once by `python -m app.migrate upgrade` (see app/migrate.py). The API
-- only verifies that the latest migration is applied; it never creates DDL at
-- startup. The migration is written to converge both a fresh database and the
-- existing hosted project (tables/columns/indexes are IF NOT EXISTS).
--
-- Admin role: the runner must connect as a role that can create roles and
-- alter default privileges (the Supabase `postgres` role has CREATEROLE).

-- The runtime role is created without a password so the grants and RLS
-- policies below can reference it. `python -m app.migrate bootstrap-role` sets
-- LOGIN and a password out of band; the password never lives in this file.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'feed_app') THEN
        CREATE ROLE feed_app NOLOGIN;
    END IF;
END
$$;

CREATE SCHEMA IF NOT EXISTS extensions;
CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA extensions;

CREATE TABLE IF NOT EXISTS feed_items (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    summary TEXT NOT NULL DEFAULT '',
    url TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT '',
    source_url TEXT NOT NULL DEFAULT '',
    published TIMESTAMPTZ,
    tags JSONB NOT NULL DEFAULT '[]',
    cves JSONB NOT NULL DEFAULT '[]',
    severity TEXT NOT NULL DEFAULT 'unknown',
    urgent BOOLEAN NOT NULL DEFAULT FALSE,
    kev BOOLEAN NOT NULL DEFAULT FALSE,
    epss_score DOUBLE PRECISION,
    is_sample BOOLEAN NOT NULL DEFAULT FALSE,
    osv_affected JSONB NOT NULL DEFAULT '[]',
    osv_fixed JSONB NOT NULL DEFAULT '[]',
    osv_severity TEXT,
    patch_status TEXT NOT NULL DEFAULT 'unknown',
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS alerted_items (
    item_id TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS source_cursors (
    source_id TEXT PRIMARY KEY,
    cursor TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

-- Columns added to databases created before the current model.
ALTER TABLE feed_items ADD COLUMN IF NOT EXISTS is_sample BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE feed_items ADD COLUMN IF NOT EXISTS kev BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE feed_items ADD COLUMN IF NOT EXISTS epss_score DOUBLE PRECISION;
ALTER TABLE feed_items ADD COLUMN IF NOT EXISTS osv_affected JSONB NOT NULL DEFAULT '[]';
ALTER TABLE feed_items ADD COLUMN IF NOT EXISTS osv_fixed JSONB NOT NULL DEFAULT '[]';
ALTER TABLE feed_items ADD COLUMN IF NOT EXISTS osv_severity TEXT;
ALTER TABLE feed_items ADD COLUMN IF NOT EXISTS patch_status TEXT NOT NULL DEFAULT 'unknown';

CREATE INDEX IF NOT EXISTS idx_feed_items_published ON feed_items(published DESC);
CREATE INDEX IF NOT EXISTS idx_feed_items_urgent ON feed_items(urgent DESC);
CREATE INDEX IF NOT EXISTS idx_feed_items_tags ON feed_items USING gin (tags jsonb_path_ops);
-- The trigram operator classes live in the `extensions` schema, which is not
-- on the default search_path of a plain postgres:16-alpine database.
CREATE INDEX IF NOT EXISTS idx_feed_items_title_trgm ON feed_items USING gin (title extensions.gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_feed_items_summary_trgm ON feed_items USING gin (summary extensions.gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_feed_items_cves_trgm ON feed_items USING gin ((cves::text) extensions.gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_feed_items_severity ON feed_items (severity);

-- RLS stays enabled as defence in depth. The owner (postgres) bypasses it; the
-- runtime role gets explicit policies below.
ALTER TABLE feed_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE alerted_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE source_cursors ENABLE ROW LEVEL SECURITY;

-- Supabase's default privileges grant anon/authenticated ALL on every new table
-- in `public`, including TRUNCATE (which RLS does not cover). Reclaim the app
-- tables explicitly and stop future tables from inheriting those grants.
-- The roles only exist on Supabase, so guard every statement for plain
-- Postgres (CI, local development).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
        EXECUTE 'REVOKE ALL ON TABLE feed_items, alerted_items, source_cursors, feed_schema_migrations FROM anon';
        EXECUTE 'ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public REVOKE ALL ON TABLES FROM anon';
        EXECUTE 'ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public REVOKE ALL ON SEQUENCES FROM anon';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
        EXECUTE 'REVOKE ALL ON TABLE feed_items, alerted_items, source_cursors, feed_schema_migrations FROM authenticated';
        EXECUTE 'ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public REVOKE ALL ON TABLES FROM authenticated';
        EXECUTE 'ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public REVOKE ALL ON SEQUENCES FROM authenticated';
    END IF;
END
$$;

-- Runtime role: DML on the three app tables plus read-only access to the
-- migration ledger (used by the startup schema check). No DDL, no other
-- schemas, no TRUNCATE.
GRANT USAGE ON SCHEMA public TO feed_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE feed_items, alerted_items, source_cursors TO feed_app;
GRANT SELECT ON TABLE feed_schema_migrations TO feed_app;

-- Policies so the non-owner runtime role passes RLS. Drop first so the
-- baseline is safe to re-run if it was ever applied manually.
DROP POLICY IF EXISTS feed_app_rw ON feed_items;
CREATE POLICY feed_app_rw ON feed_items FOR ALL TO feed_app USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS feed_app_rw ON alerted_items;
CREATE POLICY feed_app_rw ON alerted_items FOR ALL TO feed_app USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS feed_app_rw ON source_cursors;
CREATE POLICY feed_app_rw ON source_cursors FOR ALL TO feed_app USING (true) WITH CHECK (true);
