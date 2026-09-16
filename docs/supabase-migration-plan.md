# Proposal — Supabase as the Postgres provider, and which Supabase features earn their place

Status: **Proposed** (not implemented, no code written)
Date: 2026-09-16
Supersedes: nothing. Amends nothing yet — see [ADR-0005](./adr/0005-supabase-hosted-postgres.md) for the decision record stub.

> Every Supabase claim below was verified against the current official docs on
> 2026-09-16 (URLs inline). Supabase ships breaking changes frequently, so
> re-verify before implementing.

## 1. What we actually have today (measured, not assumed)

`app/postgres_store.py` is **328 lines** exposing **11 functions** through the
`Storage` port in `app/store.py` (ADR-0003):

| Group | Functions |
|---|---|
| Schema | `init_db`, `seed_if_empty` |
| Write | `upsert_items` |
| Read | `query_feed`, `search_feed`, `stats` |
| Alerts | `unalerted_urgent_items`, `mark_alerted` |
| Source state | `get_source_cursor`, `set_source_cursor` |

Tables: `feed_items`, `alerted_items`, `source_cursors`. Three indexes.

Findings that dominate the cost of any move:

### 1.1 A new database connection per operation — the single biggest obstacle

`_connect()` (line 62) returns a fresh `psycopg.connect(...)` and every one of
the 11 functions opens its own:

```
$ grep -c "_connect()" app/postgres_store.py
11
```

With `postgres:16-alpine` on the Compose bridge network, connecting is ~1 ms,
so this is invisible. Against a **remote** provider it becomes a TLS handshake
of roughly 30–80 ms *per operation*, and the op count per request is worse than
it looks:

| Call | Round trips |
|---|---|
| `query_feed` | 2 (`_live_count` + the query) — `_live_count` runs on **every** call |
| `search_feed` | 2 (same `_live_count` prefix) |
| `unalerted_urgent_items` | 2 (`_live_count` + join) |
| `stats` | **7** (total, live, by-severity, *`SELECT tags` full table scan*, urgent, max, + connect) |
| `init_db` / `seed_if_empty` | 2 connections + 1 more if seeding |

`stats()` at line 260 does `SELECT tags FROM feed_items` and aggregates the tag
counts **in Python** — it transfers every row of the archive to compute a tag
histogram. It is called by `/api/stats` *and* by `/health`.

**Conclusion: connection pooling is a prerequisite of the migration, not a task
inside it.** It is also a standalone win against the current local Postgres.

### 1.2 The schema and every query are duplicated

`app/sqlite_store.py:24` and `app/postgres_store.py:25` hold the same schema
twice; both also carry ad-hoc `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`
migration lists (postgres_store.py:85-94) that must be kept in step by hand.
Observation 6 in `docs/architecture.md` already records this as **deferred**.
There is no versioned migration mechanism at all — `init_db` is the only
schema-management story.

### 1.3 The "sample rows" workaround is encoded in the storage layer

`_live_count()` is consulted before every read so `is_sample = TRUE` rows can be
hidden once live rows exist. Invariants 4 and 14 in `AGENTS.md` both exist to
police this, and `search.sync_archive()` carries a purge path
(`fix/search-sample-purge-recovery`, commit `fe52196`) purely to keep the index
consistent with it. Sample data belongs at the API edge, not in the archive.

### 1.4 Refresh scheduling is per-process and request-driven

`pipeline.schedule_refresh()` is a module-global `asyncio.Task` and `get_feed()`
only schedules when `CACHE.fetched_at` is stale **in that process**
(`pipeline.py:146-154`). Consequences: two replicas refresh twice; a restart
loses `fetched_at` and triggers an immediate refresh; a deployment with no
traffic goes stale, because nothing refreshes unless someone asks for `/api/feed`.

### 1.5 The `is_sample`/stateful read path is what makes the frontend safe today

Nothing in the frontend depends on SQL specifics, which is good — the migration
is server-side only. Keep it that way (see §4.2).

## 2. Connection strategy — the decision that matters most

Supabase offers four ways in
([Connect to your database](https://supabase.com/docs/guides/database/connecting-to-postgres)):

| Mode | Host:Port | Protocol | Prepared statements | Session state |
|---|---|---|---|---|
| Direct | `db.<ref>.supabase.co:5432` | IPv6 (IPv4 only with add-on) | ✅ | ✅ |
| Shared pooler, session | `aws-N-<region>.pooler.supabase.com:5432` | IPv4 | ✅ | ✅ |
| Shared pooler, transaction | `aws-N-<region>.pooler.supabase.com:6543` | IPv4 | ❌ | ❌ |
| Dedicated pooler (paid) | `db.<ref>.supabase.co:6543` | IPv6 | ❌ | ❌ |

Username differs by mode: `postgres` for direct, `postgres.<ref>` for the shared
pooler. Transaction mode loses prepared statements, `WITH HOLD` cursors, `SET`,
`LISTEN`/`NOTIFY`, temp tables and **session-level advisory locks**.

### Recommendation: shared pooler, session mode (`:5432`)

Reasoning:

1. It is **IPv4 on every plan**, so it works from a Docker bridge network and
   from any Kubernetes cluster without the paid IPv4 add-on or an IPv6
   cluster CIDR — a deployment prerequisite we would otherwise have to verify
   and could not fix from inside the repo.
2. It **supports prepared statements**, so we do not have to disable
   `psycopg`'s autoprepare (the Supabase guidance for transaction mode is
   `prepare_threshold=None`,
   [Disabling prepared statements](https://supabase.com/docs/guides/troubleshooting/disabling-prepared-statements-qL8lEL)).
3. It **preserves session state**, which keeps `pg_advisory_lock` available for
   cross-replica refresh coordination (§4.4) instead of forcing us into
   transaction-scoped locks only.

Direct connection over IPv6 is the better end state — no pooler hop, lower
latency, and the docs explicitly recommend direct connections for "persistent
backends, such as VMs and long-running containers". Move to it once the
deployment target's IPv6 reachability is confirmed; it is a one-line DSN change
plus dropping `prepare_threshold=None` if we had set it.

Budget note: session mode pins one Postgres connection per pooled client for the
life of the session. Nano/Micro allow **60** Postgres connections and **200**
pooler clients
([Compute and disk](https://supabase.com/docs/guides/platform/compute-and-disk)).
Keep the application pool at `max_size=4` and this is not close to binding —
but it is the reason not to set a large `max_size` "just in case".

### Required code changes (all in `postgres_store.py` + `config.py`)

1. **Add `psycopg_pool`** and replace `_connect()` with a module-level
   `ConnectionPool`. `psycopg_pool` is a separate distribution — it is *not*
   installed by `psycopg[binary]` today (verified: no `psycopg_pool` in the
   environment).
2. **Explicitly set `prepare_threshold`.** Do not rely on inference:
   `None` for transaction mode, leave the default (5) for session/direct. Make
   it a setting so the DSN and the driver cannot disagree.
3. **`sslmode=require` minimum.** libpq defaults to `prefer`, which silently
   falls back to plaintext. `verify-full` + `sslrootcert` once we hold the
   project CA.
4. **`application_name`** on the connection, so the Supabase *Database
   Connections* dashboard breaks our traffic out from PostgREST/Auth/Storage.
5. **Do not use the multi-statement `SCHEMA` constant over a pooler.** It works
   today only because `psycopg` falls back to the simple query protocol when
   there are no parameters *and* the query is not prepared
   (`psycopg/_cursor_base.py`, `_execute_send`, line 457 in 3.3.5). At the default
   `prepare_threshold=5` that constant would eventually be sent prepared, and
   `CREATE TABLE` inside a prepared statement is invalid. `init_db` becomes a
   version check once real migrations exist (§3).
6. **Retire the `db_path` parameter** on the Postgres adapter's functions. It is
   vestigial on this backend and is currently accepted-and-ignored in 11
   signatures.

## 3. Phased plan

Each phase is independently shippable and independently reversible. Phases 1–3
have **no Supabase account requirement** — they are improvements to the current
self-hosted Postgres that happen to be prerequisites.

### Phase 0 — Instrument before moving (small)

- Add a `tests/test_postgres_store.py` that runs against a real Postgres in CI
  via a `services:` container. Today the Postgres adapter has **zero** test
  coverage; `tests/test_store.py` exercises SQLite only. Migrating an untested
  adapter to a remote provider is how you discover its bugs in production.
- Record a baseline: p50/p95 for `/api/feed`, `/api/stats`, `/api/search`, and
  the refresh wall-clock, plus database size and row count.

**Exit criteria:** the Postgres adapter is covered by tests that fail if
`query_feed` stops hiding sample rows, if `upsert_items` stops being idempotent,
or if `stats()` drifts from `query_feed`'s row visibility.

### Phase 1 — Connection pooling (prerequisite, standalone win)

- Introduce `psycopg_pool.ConnectionPool` in `postgres_store.py`, opened on
  FastAPI startup and closed on shutdown (extend the existing `lifespan` in
  `app/main.py:26`).
- Fold `_live_count()` into its callers as a single query, removing one round
  trip from every read.
- Rewrite `stats()` as one SQL statement using `jsonb_array_elements` instead of
  shipping the archive to Python.

**Exit criteria:** `/api/stats` issues 1 query; a refresh cycle issues a bounded
number of queries; the adapter test suite passes against both a local container
and (once available) a Supabase project.

### Phase 2 — Real migrations (prerequisite)

- Adopt the Supabase CLI migration workflow
  ([CLI reference](https://supabase.com/docs/reference/cli/introduction)),
  even while the database is still self-hosted: `supabase/migrations/*.sql`
  checked into the repo becomes the single source of truth.
- Author migration `0001` as the current schema **including the ad-hoc
  `ALTER TABLE` columns**, so a fresh database and an upgraded database converge.
- `init_db()` shrinks to "verify the expected migration version is applied; fail
  loudly otherwise". Schema creation must not be a runtime side effect of
  starting an API container, especially not one that may run several replicas.
- Keep SQLite working (invariant 12) by leaving `sqlite_store.py`'s schema alone
  for now; collapsing the duplication is Phase 5.

**Exit criteria:** `supabase db push` against a throwaway database produces a
schema identical to `postgres_store.SCHEMA` plus the ALTER columns, verified by
`pg_dump --schema-only` diff.

### Phase 3 — Cut over

- Create the Supabase project. Region: pick the one matching where the API runs;
  every query in this app is latency-sensitive now that reads happen per request.
- Create a least-privilege application role (`feed_app`) owning nothing, with
  `SELECT/INSERT/UPDATE/DELETE` on the three tables — **not** `postgres`.
  Migrations run as `postgres`; runtime does not.
- Set `DATABASE_URL` to the session-mode pooler string with
  `sslmode=require&application_name=security-feed`.
- Verify: `/health` `db_total` matches the old database; `/api/feed`,
  `/api/items`, `/api/search`, `/api/stats` return identical payloads (diff the
  JSON against the pre-cutover responses); a full refresh round-trips.
- **Rollback:** point `DATABASE_URL` back at the self-hosted Postgres. Keep it
  running and receiving writes for one full refresh cycle, then demote it to a
  read-only snapshot. The adapter is provider-agnostic, so this is a real
  rollback rather than a hope.
- Do **not** delete `deploy/k8s/postgres.yaml` or the Compose `postgres` service
  until the rollback window closes. Note that both are already commented out of
  their defaults (`deploy/k8s/kustomization.yaml`, `deploy/k8s/secret.yaml`),
  so the shipped Kubernetes default is SQLite on a PVC — the Supabase path is a
  *new* opt-in, not a replacement of the default.

**Exit criteria:** rollback window closed; `docker compose up --build` still
works with no `DATABASE_URL` (SQLite path); the Kubernetes manifests document
the Supabase option next to the commented-out self-hosted one.

### Phase 4 — Remove the reason the migration was risky

- Apply the §4.1 item-3 change (drop `is_sample` from the archive) so
  `_live_count` disappears from both adapters, along with invariants 4 and 14
  and the index-purge path.
- Add `ingest_runs` (§4.4) and make `/health` report last-ingest age from the
  database rather than from process memory.

### Phase 5 — Optional consolidation

- Collapse `sqlite_store.py` and `postgres_store.py` onto one SQL dialect if and
  only if the duplication actually causes a bug. ADR-0003 already rejected a
  single ORM "for now"; the Supabase move does not by itself change that
  calculus, and this phase should be dropped if Phase 4 removes most of the
  drift.

## 4. Supabase feature evaluation against the project's goals

The goals, read off `README.md` and `docs/architecture.md`: aggregate and
normalize security content; always return a non-empty feed quickly; enrich with
KEV/EPSS/OSV; search; alert on urgent items; run with zero extra infrastructure;
and keep a dependency-free frontend.

### 4.1 Adopt — clear wins

**1. Managed backups and PITR.**
Today the self-hosted Postgres in `docker-compose.yml` has **no backup story at
all** — a lost `./mount/postgres-data` volume is a lost archive. Hosted Supabase
gives daily backups plus optional PITR
([Backups](https://supabase.com/docs/guides/platform/backups)). This is the
strongest single argument for the move, and it is worth making explicitly rather
than treating the migration as a lateral swap.

**2. Postgres indexes we should have written anyway.**
`query_feed` does `tags @> %s::jsonb` with **no index on `tags`**; `search_feed`
does `ILIKE '%q%'` across four columns, which cannot use any index. On a modest
archive this is fine; it is also the first thing that will hurt. Add a GIN index
for the JSONB containment, and either `pg_trgm` GIN indexes or a generated
`tsvector` column plus GIN index for text search.

A caution that matters for *this* domain: standard `to_tsvector` tokenization is
a poor fit for CVE identifiers, and the current `/api/search` behaviour is
substring matching that users rely on (`CVE-2024-2` should match
`CVE-2024-21626`). If full-text search is adopted, **`ILIKE`/`pg_trgm` must stay
as the path for CVE-shaped queries**, or partial-ID search silently regresses.
This is the one place where "use the fancier Postgres feature" can make the
product worse.

**3. A materialized `stats` view + `pg_cron`.**
`/api/stats` currently scans the whole table. `pg_cron` can refresh a
materialized view hourly, and can also do retention pruning and `VACUUM`
([Cron](https://supabase.com/docs/guides/cron)). Keep a plain-view fallback for
the SQLite path.

**4. Observability.**
The project has no metrics, traces, or operational dashboards — a gap found
during this analysis and noted nowhere in `docs/architecture.md`. The Supabase
dashboard's Database Connections, query performance and Index Advisor are a
strictly better operational position than "docker logs on one host"
([Monitoring and debugging](https://supabase.com/docs/guides/monitoring-and-debugging)).
Worth doing regardless of the provider, but cheaper to get here than to build.

### 4.2 Reject — would break invariants or buy nothing

**1. Realtime (Postgres Changes / Broadcast) for live updates — reject.**
The frontend must stay dependency-free (invariant 1, ADR-0001). Using
Supabase Realtime means either adding `@supabase/supabase-js` (an npm/CDN
dependency — forbidden) or hand-implementing the Phoenix-channel WebSocket
protocol in `frontend/app.js`, which trades a working, tested SSE broker
(`app/events.py`, `/api/events`) for a hand-rolled protocol client with no test
coverage. It also requires enabling replication and RLS policies on every
exposed table, and Postgres Changes is a poor shape for a refresh that mutates
many rows at once. **Keep SSE.** The correct use of Realtime here would be
"something changed → refetch", which is exactly what our existing
`feed_updated` event already does.

**2. The Data API (PostgREST) as the frontend's read path — reject.**
It would move reads off our API, but the API is not a bottleneck: it serves from
the store in milliseconds and the frontend already reverse-proxies through
nginx. Adopting it would require RLS on `public` tables, hand-maintained
`GRANT`s (new tables in `public` are no longer auto-exposed —
[changelog 2026-04-28](https://supabase.com/changelog/45329-breaking-change-tables-not-exposed-to-data-and-graphql-api-automatically)),
and would forfeit server-side `time_ago` computation and the `is_sample`
visibility rule — i.e. it would recreate, in RLS policies and frontend JS, logic
that currently has tests. Our API must keep a database connection regardless, so
the Data API is duplication, not simplification.

Related: **do not expose these tables to the Data API** at all. Leaving them
unexposed means RLS is defence-in-depth rather than the only thing standing
between the public internet and the archive.

**3. Edge Functions for the refresh pipeline — reject.**
The pipeline is Python: `httpx`, `feedparser`, our normalization, KEV/EPSS/OSV
enrichment. Edge Functions are TypeScript on Deno, 256 MB, 150 s wall clock on
Free
([Limits](https://supabase.com/docs/guides/functions/limits)). Rewriting would
duplicate the pipeline in a second language and a second deployable, in direct
tension with ADR-0004. Two further disqualifiers: outbound ports 25/587 are
blocked, which would kill the SMTP email alert channel, and the pipeline would
then depend on both the FastAPI service (for the initial fetch and for alerts)
and the platform. Rejected.

**4. pgvector / semantic search — defer, do not adopt now.**
Tempting for "find advisories like this one", but it requires an embedding model,
a per-item cost on every refresh, and a new failure mode. The dominant search
pattern for this product is identifier lookup, which embeddings are bad at.
YAGNI.

**5. Queues (pgmq) for a job queue — reject.**
There is exactly one job, it is single-flight by design, and it runs every ten
minutes. `pgmq`
([Queues](https://supabase.com/docs/guides/queues)) is a durable-queue solution
to a problem this project does not have. A cron tick plus an advisory lock is the
whole requirement.

**6. Database Webhooks — reject.**
They fire on row changes and would invoke an HTTP endpoint to tell us what we
just wrote. No use case here.

**7. Self-hosted Supabase — reject.**
It is a strictly heavier footprint than `postgres:16-alpine` (Envoy became the
default gateway, `analytics`/`vector` are opt-in, Studio ownership changed —
[changelog 2026-07-17](https://supabase.com/changelog/48048-self-hosted-supabase-envoy-becomes-the-default-api-gateway-b),
[changelog 2026-05-18](https://supabase.com/changelog/46084-self-hosted-supabase-making-analytics-and-vector-opt-in))
and delivers none of the managed benefits that justify the migration. If we want
self-hosted, keep plain Postgres.

### 4.3 Adopt with care

**Supabase Auth** would be a genuine improvement over nothing — there is no
authentication of any kind today — but there is nothing to protect: the feed is
public by design and the frontend is read-only. It becomes worth adopting only
if per-user alerting (watchlists, "alert me about Kubernetes only") lands on the
roadmap. A static dependency-free frontend can talk to `/auth/v1/*` over plain
`fetch`, but the session handling that `supabase-js` provides would have to be
written by hand, with the usual cookie/JWT-expiry/refresh pitfalls. **Defer
until a user-facing authentication requirement exists.**

### 4.4 A fifth goal the migration unlocks: a single-refresher guarantee

Once `ingest_runs` exists (one row per refresh: start, end, source errors, item
count), two things become possible that are not today:

- **Cross-replica single-flight.** `pg_try_advisory_lock` (session-scoped, so it
  requires session mode or a direct connection — see §2) elects one refresher.
  Two replicas then cost one upstream fetch, not two. This matters for honouring
  source rate limits, which invariant 5 exists to protect.
- **Refresh on a schedule rather than on demand.** `pg_cron` + `pg_net`
  `http_post` to a token-protected `/api/refresh`
  ([pg_net](https://supabase.com/docs/guides/database/extensions/pg_net)) gives a
  quiet deployment fresh data. The endpoint must return **immediately** — `pg_net`
  has a 2000 ms default timeout and a full fetch cycle is slower, so a timeout in
  `net._http_response` is expected and benign, not an error. The advisory lock is
  what makes a redundant tick harmless (the second attempt returns 409).

`/health` should then report last-ingest age **from the database**, so a
scheduler or replica failure is visible instead of silently serving stale data
from a warm process cache.

## 5. Risks and open questions

| # | Risk | Mitigation |
|---|---|---|
| 1 | Adapter has zero Postgres test coverage | Phase 0, before anything touches Supabase |
| 2 | Session mode pins backend connections | `max_size=4`; revisit only with evidence |
| 3 | Latency regression from a remote database | Phase 1 removes 1–6 round trips per call; measure in Phase 0 |
| 4 | Kubernetes egress could be IPv4-only | Session-mode pooler is IPv4 on every plan — no IPv6 dependency |
| 5 | Deploy target may restrict outbound 5432 | Verify before cutover; pooler is a different host/port to test |
| 6 | Supabase breaking changes | Re-verify all docs links at implementation time; pin the CLI version |
| 7 | Ties the project to a hosted vendor | Adapter is provider-agnostic; self-hosted Postgres stays a documented, tested fallback. The runtime role owns nothing, so `pg_dump`/restore is clean |

Open questions requiring a decision before Phase 3:

1. **Plan.** Free (Nano, 500 MB, 60 connections, projects pause when idle) or
   Pro (~$10/mo Micro, 10 GB, daily backups + PITR)? For an always-on service,
   pausing is a functional problem, not just an inconvenience. **Pro is the
   recommendation**, which makes the cost/benefit versus self-hosted Postgres the
   real decision — and the benefit is backups, PITR, observability and one less
   service to run.
2. **Region**, matched to where the API actually runs.
3. **Is a second fixed database worth it**, given that the shipped Kubernetes
   default is SQLite on a PVC and Postgres is already opt-in? If Postgres is
   rarely used in practice, the honest answer may be to improve the SQLite path
   and document Supabase as the supported production option rather than to
   migrate.
