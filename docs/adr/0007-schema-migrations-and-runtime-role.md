# ADR-0007: Versioned schema migrations and a DML-only runtime role

- Status: Accepted (implemented 2026-10-17)
- Relates to: ADR-0003 (storage port and adapters), ADR-0005 (hosted Supabase)

## Context

The PostgreSQL adapter created its schema at API startup: `init_db()` ran the
three `CREATE TABLE IF NOT EXISTS` statements, seven `ALTER TABLE … ADD COLUMN
IF NOT EXISTS` statements, the `pg_trgm` extension, eight indexes and RLS on
every boot. On the hosted Supabase project this had already executed **40
times**, including `CREATE TABLE`/`CREATE INDEX` work on every container start.
That design has three problems:

1. It requires the runtime role to own the schema. The API was connecting as
   `postgres` (full project access, `BYPASSRLS`, `CREATEROLE`); a leaked runtime
   DSN would reach every schema and role in the project.
2. It races when more than one API replica starts, and it makes a deploy that
   adds an index take table locks as a side effect of serving traffic.
3. There was no record of what schema version a database was on, so a failed or
   partial upgrade was indistinguishable from a current one.

Supabase's default privileges also granted `anon` and `authenticated` **ALL** on
every new table in `public`, including `TRUNCATE`, which RLS does not cover.
RLS was enabled with no policies, which blocked the Data API but left those
table-level grants in place.

## Decision

1. **Plain SQL migrations, applied by a Python runner.**
   `migrations/NNNN_*.sql` is the single source of truth. `python -m app.migrate
   upgrade` connects with the privileged `ADMIN_DATABASE_URL`, serializes
   runners with a session advisory lock, records applied versions in
   `feed_schema_migrations`, and applies each file in one transaction.
   `python -m app.migrate check` exits non-zero when the database is behind.
   The API's `init_db()` verifies the latest version and the required tables; it
   performs no DDL. Compose runs a one-shot `migrate` service before the API;
   Kubernetes has an optional `migrate-job.yaml` (off by default because the
   shipped default is SQLite).
2. **A DML-only runtime role.** `feed_app` gets `USAGE` on `public`, DML on the
   three app tables, and `SELECT` on the migration ledger. It owns nothing, has
   no `TRUNCATE`, no DDL and no `auth`/`storage`/`realtime` access, and is
   capped at ten connections. The role is created `NOLOGIN` by migration 0001;
   `python -m app.migrate bootstrap-role` sets `LOGIN` and a password supplied
   through `FEED_APP_PASSWORD`, so the secret never lives in a migration.
3. **Reclaim the Data API grants.** Migration 0001 revokes all privileges on
   the app tables from `anon`/`authenticated` (guarded so plain Postgres in CI
   still applies) and revokes future default privileges in `public`. RLS stays
   enabled; explicit policies allow the non-owner `feed_app` role.
4. **The API never receives the admin DSN.** Compose passes
   `ADMIN_DATABASE_URL` only to the `migrate` service; the API gets
   `DATABASE_URL` (the `feed_app` DSN).

The Supabase CLI migration workflow remains a valid alternative; it was not
chosen because this repository is Python/container-first and CI already has a
Postgres service. The Python runner needs no new toolchain, no additional CI
secret, and no committed lockfile for a Node CLI. If the project later adopts
declarative schemas, ADR-0005's process can be revisited together with this one.

## Consequences

- Deploys must run migrations before the API starts. Compose does this
  automatically; Kubernetes operators run the optional Job. The API fails fast
  with an actionable message if the schema is behind.
- Schema changes are reviewable as SQL diffs and are recorded in a table. A
  failed file rolls back completely; re-running is safe.
- Runtime compromise is bounded to DML on three tables. The admin DSN is used
  only by a short-lived job.
- The local SQLite path still creates its own schema; the adapter contract is
  unchanged.
- `DB_PREPARE_THRESHOLD` remains off by default. Hosted Supabase uses the
  session pooler and sets it to `5`; transaction mode must keep it unset.
