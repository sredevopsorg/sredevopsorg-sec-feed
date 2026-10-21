# Proposal — caching, search, and Supabase features for the security feed

Status: **Proposal** (nothing in this document is implemented)
Date: 2026-10-21
Relates to: [ADR-0005](./adr/0005-supabase-hosted-postgres.md) (hosted Postgres),
[ADR-0007](./adr/0007-schema-migrations-and-runtime-role.md) (migrations and the
runtime role), [ADR-0008](./adr/0008-retire-openssf-malicious-packages-source.md)
(source retirement), and the hosted-Postgres analysis in
[supabase-migration-plan.md](./supabase-migration-plan.md).

This document evaluates the next round of improvements against the code as it
exists today, not against an imagined architecture. Every recommendation names
the file and function it touches, the trade-off it accepts, and how to verify
it. Nothing is added "because Supabase has it": a feature is rejected when the
current design already solves the problem with less machinery.

Where this document says **P0/P1/P2**, it means:

- **P0** — independent of replica count; small diff; measurable win now.
- **P1** — becomes worth it when the deployment runs more than one API replica
  or needs to stay fresh without request traffic.
- **P2** — evaluate only after the P0/P1 work is measured; may never be worth it.

## 1. Current state (read from the code)

| Area | What exists today | Consequence |
|---|---|---|
| Feed cache | `pipeline.FeedCache`, a module global; `pipeline.get_feed()` returns it and schedules a single-flight refresh when `FEED_CACHE_TTL` has elapsed | A quiet deployment never refreshes; a restart loses `fetched_at`; every replica refreshes independently |
| Read path | `/api/feed` and `/api/items` call `store.query_feed()` on every request; `/api/stats` has a 30 s in-process cache (`main._STATS_CACHE`) | Repeat reads pay a database round trip even when the cache is warm; stats expiry has no single-flight, so a burst runs the aggregate several times |
| HTTP caching | No `ETag` / `Cache-Control` on JSON endpoints; nginx proxies `/api/` with `proxy_cache off` | Browsers and any intermediary cannot revalidate; every page load refetches the full payload |
| Search (SQL) | `postgres_store.search_feed()` / `sqlite_store.search_feed()`: `ILIKE '%q%'` over title, summary, source and `cves::text` | Correct and dependency-free, but page-ordered only: no relevance, no total, no pagination |
| Search indexes | `migrations/0001_baseline.sql` creates `pg_trgm` indexes on `title`, `summary` and `cves::text`, plus a GIN index on `tags` | `source ILIKE` has no index; the OR can still use the other trigram indexes |
| Search (OpenSearch) | Optional `search._search_opensearch()` with its own sort (`urgent DESC, published DESC`) | SQL and OpenSearch disagree on ordering; `_bulk()` does not check the response's `errors` field |
| Search contract | `search.search()` returns `count` = number of returned hits; `_search_opensearch` requests no total | Callers cannot tell "50 of 50" from "50 of 5,000" |
| Conditional GET | `source_state` stores `ETag` / `Last-Modified` and a capped last payload; `_is_due()` enforces per-source intervals | Already the right pattern for upstream fetches; keep it |
| Database | `psycopg_pool` in session-mode Supavisor, per-session timeouts applied with a committed `SET`, versioned migrations, DML-only `feed_app`, RLS as defence in depth, tables not exposed to the Data API | The connection and security story is settled; do not reopen it without evidence |
| Realtime | In-process SSE broker (`events.py`, `/api/events`) with a polling fallback | Works; events do not cross replicas |

## 2. Caching

### C1 — P0: conditional GET and an in-process response cache

**Problem.** `/api/feed` and `/api/items` rebuild the same JSON on every
request. The payload changes only when a refresh completes (`generated_at`) or
when retention/ingest changes the archive, yet no cache validator is emitted, so
the browser refetches everything on every load.

**Proposal.**

1. Add a small helper (see C2) keyed by `(path, tag, severity, limit)` that
   stores the serialized payload plus a weak `ETag` derived from
   `pipeline.CACHE.generated_at` (feed) or `stats()["latest_seen"]` (archive),
   the query parameters, and a schema/version constant.
2. Emit `ETag`, `Cache-Control: public, max-age=0, must-revalidate` for
   `/api/feed` and `/api/items`, and
   `Cache-Control: public, max-age=15, stale-while-revalidate=30` for
   `/api/stats`. `/api/sources` can be `public, max-age=3600` — it is static.
3. Answer `If-None-Match` with `304 Not Modified` **after** checking the cache,
   so a revalidating client costs no database query.
4. Invalidate the cache when `pipeline.refresh_feed()` finishes (bump a
   generation counter checked by the key). A stale entry must never survive a
   refresh.
5. Keep `/api/events` `no-cache`; SSE must not be buffered or cached.

**Trade-offs.** The cache is per process and adds memory proportional to
`distinct query keys × payload size`. Bound it (for example 128 entries, LRU) and
remember that `tag`/`severity`/`limit` are the natural cardinality. ETag equality
across replicas is safe because it is content-derived; cache freshness is not
shared, which is what C3 addresses.

**Tests.** `ETag`/`304` round trip; a refresh invalidates the entry; a sample
row cannot leak through a cached response after live rows arrive (this is
invariant 4 applied to the new cache); `/api/events` is still uncached.

**Acceptance.** Repeated `/api/feed` requests within one refresh generation
issue zero database queries; a conditional request returns `304` with an empty
body.

### C2 — P0: one cache helper, not three ad-hoc ones

**Problem.** `_STATS_CACHE` in `main.py` is a bespoke tuple cache. C1 would add
a second. `pipeline` and `search` already carry module-level throttles
(`_last_prune_at`, `_last_sync_at`), each with its own expiry logic.

**Proposal.** Add `app/cache.py` (about 30 lines, no dependency): a `TTLCache`
with `get(key)`, `put(key, value)`, `invalidate()`, a max size, and an
`asyncio.Lock`-based `get_or_create(key, factory)` for stampede control. Migrate
`_STATS_CACHE` to it and use it for C1. Do **not** turn this into a general
abstraction: three call sites do not justify a framework.

**Acceptance.** A burst of N concurrent `/api/stats` requests after expiry runs
`store.stats()` once.

### C3 — P1: freshness that does not depend on traffic

**Problem.** `pipeline.get_feed()` only schedules a refresh when a request sees
a stale cache. A deployment with no traffic serves an ever-staler feed, and N
replicas each perform their own refresh, multiplying upstream requests against
the rate limits that invariant 5 protects.

**Proposal.**

1. Add an `ingest_runs` table (started_at, finished_at, item_count, errors,
   trigger) written by `pipeline.refresh_feed()` and read by `/health` so
   last-ingest age comes from the database, not process memory.
2. Elect one refresher per cycle with `pg_try_advisory_lock` on a connection
   taken from the application pool, held for the refresh and released on the
   same connection. Session mode (or a direct connection) is required for a
   session-scoped lock; this is one more reason the pooler stays in session
   mode. `pg_advisory_xact_lock` is the fallback if transaction mode is ever
   adopted, but a refresh is not one transaction, so it is a poorer fit.
3. Add a token-protected `POST /api/refresh` that takes the lock, schedules the
   existing background refresh, and returns `202` immediately. It must never
   await the fetch (invariant 3).

**Acceptance.** Two replicas, one cron tick: one upstream refresh and one
`ingest_runs` row per cycle; `/health` reports a last-ingest age that survives a
restart.

### C4 — P1: `pg_cron` + `pg_net` scheduling and retention

**Problem.** Nothing refreshes without traffic (C3), and retention runs in the
application (`pipeline._prune`, throttled per process), so every replica prunes
and the schedule is tied to refresh traffic.

**Proposal.**

- Enable the Supabase `pg_cron` and `pg_net` extensions and schedule
  `net.http_post()` to the protected `/api/refresh` every refresh interval.
  `pg_net`'s default 2000 ms timeout is expected and benign: the refresh
  outlives it by design, the endpoint answers `202`, and the advisory lock makes
  a duplicate tick a no-op. Verify the response in `net._http_response` only to
  detect a misconfigured URL/token.
- Schedule retention as SQL (`DELETE FROM feed_items WHERE last_seen < now() -
  interval '…'`, plus the orphaned `alerted_items` cleanup) around the same
  time. Keep the application path for SQLite, where `pg_cron` does not exist.
- Repeat the existing guardrails: the cron job owns no new privileges; it uses
  the same runtime URL/token, not the admin DSN.

**Trade-offs.** Supabase-specific scheduling leaves the self-hosted Postgres
path without a scheduler; keep the on-demand refresh as the portable path and
treat cron as an option, not a requirement.

**Acceptance.** A quiet deployment ingests on schedule; `ingest_runs` shows one
run per interval; retention deletes exactly the expected rows and never sample
rows.

### C5 — P2: stats snapshot (measure first)

**Problem.** `store.stats()` scans `feed_items` and unnests `tags` on every
cache miss. At the current 30 s cache this is likely acceptable; at a large
archive it is the most expensive statement in the application.

**Proposal.** Do not add a materialized view yet. Measure `stats()` p95 with
`pg_stat_statements`/Supabase query performance first. If it exceeds a stated
budget (for example 100 ms at p95), add either:

- a `pg_cron`-refreshed snapshot table written by one SQL statement and read by
  `stats()`, or
- a materialized view with a unique index and `REFRESH MATERIALIZED VIEW
  CONCURRENTLY`.

The snapshot table is simpler for key/value aggregates; the MV needs a natural
unique key that this aggregate does not have.

**Acceptance.** `stats()` p95 under budget; the API contract (`total`, `live`,
`sample`, `urgent`, `by_severity`, `by_tag`, `enriched`, `latest_seen`) is
unchanged.

### C6 — P2: cross-replica SSE coherence

**Problem.** `events.Broker` is in-process. With more than one replica, a
refresh on replica A does not notify clients connected to replica B; they wait
for the polling fallback.

**Proposal (only when replicas > 1).** Either `LISTEN`/`NOTIFY` on a dedicated
connection (not a pooled one — `LISTEN` needs a stable session) that fans the
`feed_updated` event out through the existing broker, or Supabase Realtime
Broadcast used send-only from the pipeline. Keep SSE as the browser transport:
it is native `EventSource`, needs no client library (invariant 1), and already
has a subscriber cap. Do not adopt Realtime Postgres Changes; Supabase's own
guidance routes high-fan-out workloads to Broadcast, and a refresh mutates many
rows at once.

**Acceptance.** A refresh on any replica reaches subscribers on every replica
within one heartbeat interval; the subscriber cap still returns `503`.

## 3. Search

### S1 — P0: one deterministic ordering contract

**Problem.** SQL search orders by `published DESC, urgent DESC, last_seen DESC`;
OpenSearch orders by `urgent DESC, published DESC`. The two backends can return
different first pages for the same query, and neither has a unique tiebreaker,
so pagination would be non-deterministic. The README also describes the feed as
"urgent first", which matches neither adapter exactly.

**Proposal.** Define one contract — publication time primary, urgency as a
badge/tiebreaker, `id` as the final tiebreaker — and apply it in
`postgres_store.search_feed()`, `sqlite_store.search_feed()` (ISO strings sort
correctly), and `search._search_opensearch()` (`sort` on `published`, `urgent`,
`id`). Update the README wording.

**Acceptance.** The same fixed dataset returns the same order through both
backends; a repeated query is stable.

### S2 — P0: a result contract callers can trust

**Problem.** `/api/search` returns `count` = number of returned items and no
total, so a UI cannot say "showing 50 of 1,200". There is no pagination and no
`source`/`kev`/date filter.

**Proposal.**

- Add only the filters that map to existing columns/indexes: `source`, `kev`,
  `urgent`, and a `published_after` date. Keep the route bounded and
  rate-limited (invariant 16).
- Return `total` from `COUNT(*) OVER ()` in the same SQL statement (the
  `query_feed` / `search_feed` pattern already sorts and limits, so the window
  function adds no round trip), and from `track_total_hits` in OpenSearch.
- Add a bounded `offset` (or, better, a keyset cursor on
  `(published, id)`) so deep pages stay cheap. With S1 in place, keyset paging
  is deterministic.
- Keep `count` = number of items in this response and document `total`
  explicitly; this is a contract change for `/api/search` only, and the
  frontend must not need to change to keep working.

**Acceptance.** `/api/search?q=…&limit=10` reports `count=10`, a truthful
`total`, and page 2 does not repeat page 1.

### S3 — P0: rank results without losing CVE substring search

**Problem.** A search for `CVE-2024-2` must still match `CVE-2024-21626`; that
is the dominant identifier-lookup pattern. A `tsvector`-only rewrite breaks it,
because full-text tokenization does not treat a CVE id as a prefix-searchable
token.

**Proposal.**

1. Keep the `ILIKE` / trigram filter as the recall mechanism.
2. Rank inside that filter:
   - exact `cves` containment (`cves @> jsonb_build_array(upper(q))`) first;
   - then a title trigram similarity (`similarity(title, q)`);
   - then publication recency and `urgent`.
3. Normalize the input: trim, cap length, and detect a CVE-shaped query
   (`^CVE-\d{4}-\d{4,7}$`) for the exact arm.
4. Defer a generated `tsvector` column. It is a reasonable secondary ranking
   signal for prose, but it must not replace the substring path — and this is
   exactly the place where "the fancier Postgres feature" would make the
   product worse.

**Trade-offs.** `similarity()` on every candidate row costs CPU; the trigram
filter keeps the candidate set small, and the ranking expressions only run on
those rows. Measure with `EXPLAIN (ANALYZE, BUFFERS)`.

**Acceptance.** `CVE-2024-2` still finds partial ids; an exact CVE id ranks
first; result order is stable.

### S4 — P0: the indexes this workload actually needs

**Problem.** The existing trigram indexes cover title, summary and
`cves::text`, but not `source`; there is no partial index for the common
urgent/KEV filters; and there is no `(published, id)` index to support keyset
paging.

**Proposal (proposed migration `0004_search_indexes.sql`, not part of this
change).**

```sql
CREATE INDEX IF NOT EXISTS idx_feed_items_source_trgm
    ON feed_items USING gin (source extensions.gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_feed_items_published_id
    ON feed_items (published DESC NULLS LAST, id);
CREATE INDEX IF NOT EXISTS idx_feed_items_kev_urgent
    ON feed_items (kev, urgent) WHERE kev OR urgent;
```

Skip the composite indexes if `EXPLAIN` shows the planner ignores them. The
`extensions` schema prefix is required: `pg_trgm` lives there on Supabase and on
the plain `postgres:16-alpine` test database.

**Acceptance.** Before/after `EXPLAIN (ANALYZE, BUFFERS)` for the three search
shapes (CVE id, keyword, tag + severity) is recorded in the PR; no sequential
scan on `feed_items` for a bounded limit.

### S5 — P2: freeze OpenSearch, or retire it deliberately

**Problem.** OpenSearch duplicates search infrastructure for queries Postgres
can already answer, and the two paths have started to diverge (S1, `_bulk`
error handling, archive sync capped at 10,000 rows, no index refresh before
search). Keeping it first-class means maintaining two search contracts, two
orderings and an index-sync job.

**Proposal.** Freeze it as an opt-in escape hatch: fix `_bulk` to inspect the
`errors` field and request a refresh before searching; do not add new query
features to it. If usage stays at zero, retire it in a future ADR along with
`docker-compose`'s `search` profile and the Kubernetes manifest, rather than
extending it. The SQL path must remain first-class either way (AGENTS "Adding
a source" item 8).

**Acceptance (if kept).** A partial bulk failure is logged and surfaced as a
degraded step, not silently ignored; `/api/search` returns the S1/S2 contract
from both backends.

## 4. Other Supabase features — verdicts

| Feature | Verdict | Rationale | Prerequisite / verification |
|---|---|---|---|
| Hosted Postgres + Supavisor session pooler | **Adopted** | IPv4 everywhere, prepared statements, session state for advisory locks | Keep `DB_POOL_MAX_SIZE=4`; measure connection count |
| Versioned migrations + DML-only `feed_app` | **Adopted** | Removes boot-time DDL and the schema race | `python -m app.migrate check` |
| Backups + PITR | **Adopt, decide plan** | The archive currently has no backup story; this is the strongest managed argument | Operator decision: Pro (PITR) vs daily backups; record the RPO/RTO |
| `pg_cron` + `pg_net` | **Adopt (P1)** | Traffic-independent refresh and retention without a second scheduler | C3's `/api/refresh` + advisory lock first |
| Index Advisor / query performance / `pg_stat_statements` | **Adopt** | Cheapest observability available; replaces guessing about `stats()` and search plans | Enable and record a baseline before C5/S4 |
| Log drains | **Adopt when leaving single-host** | Centralised application logs without building collectors | Provider choice; not a code change |
| `verify-full` TLS + project CA | **Adopt** | `require` encrypts but does not verify the server | `DB_SSLROOTCERT` + dashboard CA |
| Direct connection (IPv6) | **Revisit** | One less pooler hop; Supabase recommends direct connections for long-running backends | Only after confirming IPv6 reachability from the deploy target; one-line DSN change |
| `ingest_runs` + advisory lock | **Adopt with C3** | Single-refresher guarantee and restart-safe health | Session mode or direct connection |
| `pg_cron`-owned retention | **Adopt with C4** | One scheduler, no per-replica pruning | Keep the app path for SQLite |
| Supabase Auth | **Defer** | Nothing to protect yet: the feed is public and read-only. Becomes worthwhile only with per-user watchlists/alerts | Revisit with a user-facing auth requirement; a dependency-free frontend would need hand-rolled session handling |
| pgvector / semantic search | **Defer** | Requires an embedding model and a per-item cost; identifier lookup is the dominant query and embeddings are bad at it | Revisit only with a "similar advisories" product requirement |
| Realtime (Postgres Changes) | **Reject** | Wrong mechanism for a bulk row change; Broadcast is the documented high-fan-out path. SSE already covers the need | Revisit only for cross-replica coherence (C6) |
| Data API / PostgREST exposure | **Reject** | Tables stay unexposed; adopting it would recreate `time_ago`, `is_sample` visibility and RLS logic in a second layer. Auto-exposure is opt-in and enforced from 2026-10-30 | Keep `anon`/`authenticated` revoked |
| Edge Functions for the pipeline | **Reject** | The pipeline is Python; a Deno rewrite duplicates it in a second language and blocks SMTP ports | — |
| `pgmq` queues | **Reject** | Exactly one job, single-flight, on a timer; an advisory lock plus cron is the whole requirement | — |
| Supabase Storage | **Reject** | No binary assets in the product | — |
| Supabase Vault for webhook secrets | **Reject for now** | Adds a database read on the alert path to replace environment secrets; env/secret manager is simpler | Revisit only if secrets must be rotated without a redeploy |
| Read replicas | **Reject** | One small read-mostly service; the pooler and cache cover it | Revisit with measured read saturation |
| Supabase CLI / branching | **Optional** | The in-repo migration runner already fits a Python/container-first repo; preview branches could validate migrations in CI if the team adopts the CLI | Only with a concrete migration-testing gap |

## 5. Prioritized roadmap

| # | Item | Priority | Effort | Risk | Depends on | Verification |
|---|---|---|---|---|---|---|
| 1 | C1 conditional GET + response cache | P0 | S | Low | C2 | 304/ETag tests; zero-DB repeat reads |
| 2 | C2 shared TTL cache helper | P0 | S | Low | — | stats stampede test |
| 3 | S1 deterministic ordering | P0 | S | Low | — | cross-backend order test |
| 4 | S2 `total` + bounded paging | P0 | M | Low | S1 | API contract test |
| 5 | S3 relevance ranking | P0 | M | Medium | S4 measured | partial-CVE regression test; `EXPLAIN` |
| 6 | S4 search indexes | P0 | S | Low | — | `EXPLAIN` before/after |
| 7 | C3 `ingest_runs` + advisory lock + `/api/refresh` | P1 | M | Medium | session mode | two-replica single-flight test |
| 8 | C4 `pg_cron`/`pg_net` refresh + retention | P1 | M | Medium | C3 | one run per interval; retention counts |
| 9 | C5 stats snapshot | P2 | M | Low | measurement | p95 under budget |
| 10 | C6 cross-replica SSE | P2 | M | Medium | >1 replica | event fan-out test |
| 11 | S5 OpenSearch fix or retirement | P2 | S/M | Low | S1/S2 | bulk-error test; ADR if retired |

## 6. Explicit non-goals

- Replacing the feed cache with a shared cache service (Redis, etc.). The
  database plus a per-replica cache is sufficient for this read volume.
- Rewriting search on `tsvector` alone.
- Adding Supabase client libraries to the frontend (invariant 1).
- Moving the pipeline into Edge Functions or a queue.
- Exposing the tables through the Data API.
- Changing the storage port's shape beyond what the source retirement required.

## 7. Verification approach

Every item above lands with its own tests and a stated acceptance criterion. In
addition, the P0 set should be validated against a real Supabase project (not
only the local `postgres:16-alpine` test database), because the trigram schema,
`statement_timeout` and pooler behaviour are provider-specific:

1. `EXPLAIN (ANALYZE, BUFFERS)` for the three search shapes, before and after.
2. p50/p95 for `/api/feed`, `/api/items`, `/api/search`, `/api/stats`, and the
   refresh wall-clock, recorded before and after.
3. `pool.get_stats()` (or the Supabase dashboard) after a soak, so the
   cache/image work does not hide a connection-budget regression.
4. The full migration path: `0001`→`0004` on an empty database, and
   `apply_pending` on an already-migrated project, with
   `python -m app.migrate check` green.
