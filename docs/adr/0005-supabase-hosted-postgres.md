# ADR-0005: Move the PostgreSQL backend to hosted Supabase

- Status: **Proposed** (not implemented)
- Date: 2026-09-16
- Relates to: ADR-0003 (storage port and adapters)

## Context

The project ships PostgreSQL as its primary store and SQLite as the local,
zero-setup fallback (ADR-0003). The Postgres adapter
(`app/postgres_store.py`, 328 lines) is selected when `DATABASE_URL` is set and
uses `psycopg` 3.3.5. In practice:

- The Compose `postgres` service has **no backup story**: losing
  `./mount/postgres-data` loses the archive.
- The Kubernetes default does not even run Postgres — `deploy/k8s/postgres.yaml`
  is commented out of `kustomization.yaml` and `DATABASE_URL` is commented out
  of `deploy/k8s/secret.yaml`, so the shipped default is SQLite on a PVC.
- The adapter opens **a new connection per operation** (11 call sites of
  `_connect()`), and `_live_count()` adds a second round trip to every read.
  `stats()` issues 7 queries including a full `SELECT tags` scan aggregated in
  Python. This is tolerable at ~1 ms against a local socket and is the main
  obstacle to a remote database.
- The schema is duplicated between the two adapters, with hand-maintained
  `ALTER TABLE ... IF NOT EXISTS` lists and no versioned migrations.
- The project has no metrics, traces, or operational dashboards. This gap is not
  recorded anywhere in `docs/architecture.md` — it was found during the analysis
  for this decision, and it is a gap by omission rather than a documented
  trade-off.

The full analysis and evidence are in
[`docs/supabase-migration-plan.md`](../supabase-migration-plan.md).

## Decision

Adopt **hosted Supabase Postgres** as the supported production database,
connecting with `psycopg` through the **shared pooler in session mode**
(`aws-N-<region>.pooler.supabase.com:5432`) rather than the transaction pooler.

Rationale for session mode over the alternatives:

- It is IPv4-capable on every plan, so no IPv6 cluster networking and no paid
  IPv4 add-on is required. This removes a deployment prerequisite that cannot be
  fixed from inside the repository.
- It supports prepared statements, so `psycopg`'s autoprepare can stay at its
  default instead of being disabled.
- It preserves session state, which keeps `pg_advisory_lock` available for
  electing a single refresher across replicas.

The direct connection (`db.<ref>.supabase.co:5432`) is the intended end state
once the deployment target's IPv6 reachability is confirmed, since Supabase
recommends direct connections for persistent backends and it removes a hop.

The migration is gated on two prerequisites that are valuable independently:

1. **Connection pooling** (`psycopg_pool`) with an explicit `prepare_threshold`,
   `connect_timeout`, `sslmode=require`, and `application_name`.
2. **Versioned migrations** (Supabase CLI `supabase/migrations/`), reducing
   `init_db()` from "create the schema at container start" to "assert the
   expected migration is applied". The multi-statement `SCHEMA` constant must not
   survive as the schema mechanism: it only works by falling back to the simple
   query protocol when unprepared, and would break once autoprepare triggers.

Runtime connects as a least-privilege `feed_app` role that owns no objects;
migrations run as `postgres`. Tables are **not** exposed through the Data API,
so RLS is defence in depth rather than the only control.

## Consequences

- Daily backups and optional PITR replace an unbacked-up Docker volume. This,
  not the SQL of the migration, is the substantive benefit.
- One fewer service to operate; observability comes from the Supabase dashboard
  instead of `docker logs` on a single host.
- Reads gain 30–80 ms of network latency per round trip unless pooling lands
  first, which is why Phase 1 is a prerequisite rather than an optimization.
- Session mode pins one Postgres connection per pooled client for the life of
  the session; the application pool must stay small (`max_size=4`) against the
  60-connection ceiling of a Nano/Micro instance.
- The adapter stays provider-agnostic (ADR-0003), so self-hosted Postgres
  remains a documented and testable fallback and rollback is a `DATABASE_URL`
  change. `deploy/k8s/postgres.yaml` and the Compose `postgres` service are
  retained until the rollback window closes.
- Supabase is a hosted dependency with a frequent breaking-change cadence, so
  the CLI version is pinned and documentation claims are re-verified at
  implementation time.

## Alternatives considered

- **Stay on self-hosted Postgres, add backups (pgBackRest/WAL-G).** The honest
  competitor. Rejected for now because it adds operational work to a project
  whose stated goal is zero extra infrastructure, but it is the fallback if the
  plan cost or the vendor dependency is judged unacceptable.
- **Shared pooler, transaction mode (port 6543).** Rejected: no prepared
  statements, no session-level advisory locks, and no benefit here — the
  workload is a persistent backend, which is the case transaction mode is not
  designed for. A further reason discovered during analysis: psycopg cannot
  detect a pooler (PgBouncer declined to self-identify), so prepared statements
  must be disabled in code, and the required setting cannot be expressed in the
  connection string — libpq rejects `prepare_threshold` and `pgbouncer` as
  parameters. `executemany()`, used by `upsert_items()` and `mark_alerted()`,
  forces a named prepared statement on its *first* execution rather than after
  the default threshold of five, so this would fail on the first refresh rather
  than subtly later.
- **Dedicated pooler or direct connection with the IPv4 add-on.** Rejected as a
  starting point: it adds a paid add-on and DNS behaviour (the add-on swaps the
  AAAA record for an A record) before we know we need the lower latency.
- **Supabase Data API (PostgREST) as the frontend read path.** Rejected: the API
  must hold a database connection anyway, so this duplicates rather than removes
  a layer, and it would push the `is_sample` visibility rule and `time_ago`
  computation into RLS policies and frontend JavaScript.
- **Supabase Realtime instead of SSE.** Rejected, though not for the reason first
  assumed: Supabase publishes the Realtime wire protocol, so a plain `WebSocket`
  satisfies the dependency-free frontend invariant and no npm/CDN dependency is
  required — the invariant blocks the `supabase-js` *client library*, not
  Supabase. It is still rejected because Postgres Changes authorizes every event
  against every subscriber on a single thread (Supabase directs heavy fan-out to
  Broadcast), and because Broadcast, while viable, would replace a working,
  tested SSE broker with a hand-rolled protocol client — heartbeat, rejoin
  backoff and a 24-hour connection cap — living in a frontend file with no test
  suite, for no capability we currently need.
- **Supabase Edge Functions for the refresh pipeline.** Rejected: TypeScript on
  Deno with a 150 s wall clock and blocked outbound ports 25/587; it would
  reimplement the Python pipeline in a second language and break the SMTP alert
  channel. See ADR-0004 on one-way pipeline dependencies.
- **Self-hosted Supabase.** Rejected: heavier than plain Postgres and delivers
  none of the managed benefits that motivate this decision.
