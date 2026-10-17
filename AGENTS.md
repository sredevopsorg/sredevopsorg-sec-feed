# AGENTS.md

Guidelines for AI coding agents (and human contributors) working in this
repository.

## Project in one sentence

A FastAPI-backed single-page feed that aggregates, normalizes, enriches,
persists to PostgreSQL (or SQLite), searches, alerts, and displays security
advisories, CVEs, and threats for Linux, cloud, and Kubernetes.

## Commands

Run these from the repository root. Development and production are
container-first (Docker/Podman); a host Python install is optional.

```bash
# Development (builds the web + api images from source; UI on :8080, API on :8000)
# Compose fails closed without credentials: copy the template once first.
cp .env.example .env   # then set POSTGRES_USER / POSTGRES_PASSWORD / POSTGRES_DB
docker compose up --build

# Hosted Supabase (uses DATABASE_URL + ADMIN_DATABASE_URL from .env; skips local DB)
docker compose -f docker-compose.yml -f docker-compose.supabase.yml up --build

# Schema migrations (the API never creates DDL; compose runs this as a job)
ADMIN_DATABASE_URL=... uv run python -m app.migrate upgrade
ADMIN_DATABASE_URL=... uv run python -m app.migrate check

# Run tests (host; requires uv 0.13.1+; set TEST_DATABASE_URL for Postgres tests)
uv sync --frozen
uv run --frozen pytest -q

# Refresh the lock after editing pyproject.toml
uv lock --upgrade
uv lock --check

# Production (published, non-root images; run `docker compose pull` first)
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# Deploy to Kubernetes (apply the optional migrate Job when using DATABASE_URL)
kubectl apply -k deploy/k8s
```

There is no linter or formatter configured yet. Keep code PEP 8-ish and
readable.

## Pull requests

- Target `main`. CI runs on pull requests and on pushes to `main`; both must
  be green.
- A stacked PR (base = another feature branch) keeps a reviewable diff, but
  it must be retargeted to `main` as soon as its base merges. Merging it into
  an already-merged base leaves the commit on a dead branch: `main` never
  receives it and its tests never run there.
- Check `gh pr view <n> --json baseRefName` before merging a PR that was
  stacked on another branch.

## Repository layout

```text
app/config.py      Centralized Settings (environment-driven; ADR-0002)
app/http_client.py Single outbound HTTP policy: shared user agent + bounded timeouts
app/models.py      Domain model (FeedItem) + serialization (ADR-0004)
app/main.py        FastAPI API routes and app startup (pure JSON API)
app/sources.py     Source definitions (add new feeds here)
app/fetcher.py     Fetching + normalization of upstream sources
app/pipeline.py    Refresh orchestration: fetch → enrich → persist → index → publish → alert
app/enrich.py      CISA KEV + FIRST EPSS enrichment, plus the KEV source (best-effort)
app/osv.py         OSV.dev enrichment (affected/fixed/severity, best-effort)
app/search.py      Search backend (OpenSearch if configured, SQL fallback)
app/ossf.py         OpenSSF Malicious Packages source (GitHub API + cursor)
app/store.py       Storage facade/port (selects sqlite or postgres backend)
app/sqlite_store.py    SQLite storage adapter
app/postgres_store.py  PostgreSQL storage adapter (pooling, no boot-time DDL)
app/errors.py      StoreUnavailable / SchemaNotMigrated (mapped to 503 / fail-fast)
app/migrate.py     Versioned migrations + feed_app role bootstrap (one-shot job)
migrations/        Versioned PostgreSQL schema (applied by app/migrate.py)
app/events.py      SSE pub/sub broker (capped subscriber count)
app/ratelimit.py   In-process fixed-window request rate limiting
app/alerts.py      Discord / Slack / email / log alerts for urgent items
frontend/          Single-page frontend (HTML + CSS + vanilla JS, no build step);
                   Dockerfile + nginx.conf + security-headers.conf serve it as
                   non-root nginx on 8080
tests/             Unit tests: feed/enrichment, models, store, search, config, HTTP
                   policy, API, pipeline, OSV/OSSF, alerts, rate limiting,
                   migrations (TEST_DATABASE_URL)
docs/              Architecture review (docs/architecture.md) + ADRs (docs/adr/)
                   and the Supabase migration analysis
                   (docs/supabase-migration-plan.md)
deploy/k8s/        Kubernetes manifests (api, frontend, NetworkPolicy;
                   postgres/PDB/Ingress/OpenSearch ship commented out of
                   kustomization.yaml; migrate-job.yaml is optional;
                   secret.example.yaml is a template and is NOT applied by kustomize)
.github/workflows/ CI (uv lock check, migrations, frozen pytest, pip-audit on Python 3.13),
                   CodeQL, container image builds
docker-compose.yml           Base services (local build; UI host port 8080; reads .env)
docker-compose.supabase.yml  Overlay: hosted Supabase, skips local postgres
docker-compose.prod.yml      Production overrides (digest-pinned GHCR images)
.env.example                 Template for the gitignored .env (local and Supabase credentials)
pyproject.toml               Direct dependencies + dev group + uv settings
uv.lock                      Committed, hash-locked dependency graph
```

## Critical invariants

1. **The frontend must stay dependency-free.** It is a static app in
   `frontend/` (`index.html`, `styles.css`, `app.js`, `config.js`) with no
   build step. Do not introduce npm, bundlers, or CDN scripts. Resolve API
   calls through the configured base URL rather than hardcoding `/api/...`.
2. **The feed must never render empty.** `fetcher.py` provides sample fallback
   data when all live sources fail. Preserve that behavior.
3. **Never block the API on a slow source.** `pipeline.get_feed()` returns the
   cache immediately and schedules a single-flight background refresh
   (`pipeline.schedule_refresh()`). No request path may await a refresh.
4. **Sample rows must stay hidden once live rows exist.** `store.query_feed()`
   excludes `is_sample=1` when `is_sample=0` rows are present.
5. **Respect source rate limits and terms.** All HTTP calls must keep the
   current `USER_AGENT` and a bounded timeout: build clients through
   `app.http_client.client()`. `tests/test_http.py` fails if any other module
   constructs an `httpx` client. A fetch retries at most once and only for
   transport-level failures (`FETCH_ATTEMPTS` in `app/fetcher.py`); HTTP error
   responses are never retried.
6. **Keep tests passing.** Every change to parsing/enrichment should add or
   update a test in `tests/test_feed.py`.

## Adding a source

1. Add a `Source` entry to `app/sources.py`.
2. If it is RSS/Atom, no new fetcher code is needed. If it is a new API shape,
   add a `_fetch_<kind>` function in `app/fetcher.py` and a branch in
   `_fetch_source()`. Current kinds: `rss`, `nvd`, `redhat-api`, `ghsa`,
   `kev`, `ossf-malicious`. Each GHSA entry costs one GitHub API request per
   refresh, so keep that curated list short.
3. Add relevance filtering if the feed is broader than Linux/cloud/Kubernetes
   (see `_is_relevant()`).
4. Add a unit test for the normalization/filtering logic with fixture data.
5. Update the Sources table in `README.md` (including source-specific tags such
   as `zeroday` for the ZDI feeds).
6. Enrichment (KEV/EPSS) is optional and best-effort; new enrichment goes in
   `app/enrich.py` and must never fail the whole refresh.
7. Alerting is opt-in. Discord webhook is the first/primary alert option
   (`DISCORD_WEBHOOK_URL`); Slack (`SLACK_WEBHOOK_URL`) and SMTP email are
   secondary channels. Without any channel configured, urgent items are logged
   only. Alert delivery must never break the refresh loop.
8. Search must work without extra infrastructure. `/api/search` falls back to
   SQL (Postgres `ILIKE` or SQLite `LIKE`) when `OPENSEARCH_URL` is not
   configured.
9. OSV enrichment is best-effort and capped per refresh. Never fetch OSV for
   every CVE in the archive.
10. The OSSF malicious-packages source must use the GitHub API cursor flow in
    `app/ossf.py`. Never clone the full repo in the app; it is over 1 GB.
11. `store.py` is the only storage API callers should use. When `DATABASE_URL`
    is set it delegates to `postgres_store.py`; otherwise it uses SQLite.
12. Keep the SQLite path working. Local tests rely on it.
13. **Production images run non-root.** The API image uses a non-root `app`
    user (UID 10001). The frontend image is `nginxinc/nginx-unprivileged`
    running as UID 101 and listening on 8080; Compose publishes it on host 8080
    and the Kubernetes Service exposes port 80. Do not add `USER root` to
    production images, and keep the nginx listen port in step with the image.
14. **The search index must match the SQL view.** Sample rows are never
    indexed, and `search.sync_archive()` purges them as soon as live rows
    exist, so `/api/search` cannot return rows the SQL paths hide.
15. **CORS fails closed.** `CORS_ORIGINS` defaults to empty, so the API denies
    every cross-origin caller. Only add an allow-list when the frontend is
    genuinely hosted on another origin, and update the frontend CSP
    `connect-src` to match.
16. **Public read endpoints stay bounded.** `/api/search` and `/api/events`
    carry the `app.ratelimit` dependency (per-process, `RATE_LIMIT_PER_MINUTE`,
    `0` disables), and `Broker.subscribe()` refuses new SSE subscribers past
    `MAX_SSE_SUBSCRIBERS`, returning `503`. Do not add unbounded work to those
    routes.
17. **Production images are digest-pinned and credentials never live in git.**
    Deployments/Compose/Dockerfiles reference `tag@sha256:…` (bump deliberately);
    Compose reads Postgres credentials from the gitignored `.env` and fails
    closed without them, and `deploy/k8s/secret.example.yaml` is a placeholder
    template that is intentionally **not** referenced by `kustomization.yaml`.
18. **Search input is escaped, not interpolated.** `%`/`_` in `/api/search`
    are escaped before being wrapped in `%...%`; keep both storage adapters in
    step and keep queries parameterized.
19. **Dependencies are locked and hash-verified.** `pyproject.toml` is the only
    direct-dependency input; `uv.lock` is the committed resolved graph. Docker
    and CI install with `uv sync --frozen`; a stale lock fails
    `uv lock --check`. Refresh with `uv lock --upgrade`, run the tests and
    runtime audit, and commit both files. Do not add `requirements*.txt` or
    install packages ad hoc.
20. **Schema changes go through `migrations/`.** The API never creates or alters
    schema at startup: `postgres_store.init_db()` only verifies the latest
    version and fails fast with the migration command. Add a new numbered
    `migrations/NNNN_*.sql` file; never edit an applied migration. Apply with
    `python -m app.migrate upgrade` (compose runs it as a one-shot job; the
    Kubernetes Job is optional). The migration runner connects with the
    privileged `ADMIN_DATABASE_URL`; the API never receives that DSN.
21. **The runtime database role is DML-only.** `DATABASE_URL` uses
    `feed_app.PROJECT-REF` (session-mode pooler) with
    `SELECT/INSERT/UPDATE/DELETE` on the three tables only. It must not be able
    to create roles/tables, `TRUNCATE`, or read `auth`/`storage`/`realtime`.
    The `postgres` role is for migrations and one-time bootstrap only. Keep
    `anon`/`authenticated` revoked on the app tables and keep the default
    privileges revoked in `public`.
22. **Health and readiness are separate.** `/health` is liveness only and must
    never touch the database (it used to run the full `stats()` aggregate on
    every probe). `/ready` is the database readiness check (`SELECT 1` with a
    short timeout, `503` when unavailable). `/api/stats` is cached; do not
    reintroduce an unbounded aggregate into a probe path.

## Feed item contract

Every item must be normalized to the `FeedItem` dataclass in
`app/models.py` (re-exported by `app/fetcher.py`):

- `id` — stable hash of URL + title
- `title`, `summary`, `url`, `source`, `source_url`
- `published` — timezone-aware UTC datetime or `None`
- `tags` — core set `linux`, `cloud`, `kubernetes`, `cve`, `exploit`,
  `patch`, `threat`; KEV enrichment and the KEV source add `kev`; the OpenSSF source adds
  `malware`, `supply-chain`, `malicious-packages` and the lowercased ecosystem
  (`go`, `npm`, …); the ZDI sources add `zeroday`
- `cves` — list of uppercase CVE IDs, e.g. `["CVE-2024-21626"]`
- `severity` — `critical` | `high` | `medium` | `low` | `unknown`
- `urgent` — boolean, drives the red dot in the UI
- `kev` — true when a CVE is in CISA's Known Exploited Vulnerabilities catalog
- `epss_score` — FIRST EPSS score when available; `None` when unknown (never
  use `0.0` as a stand-in for "not scored")
- `osv_affected`, `osv_fixed`, `osv_severity` — OSV.dev enrichment (best-effort,
  capped per refresh)
- `patch_status` — `fixed` | `affected` | `not-affected` | `deferred` | `unknown`
- `is_sample` — true for fallback/sample rows

The API returns these via `item_to_dict()`, which also computes `time_ago` and
emits `is_sample`.

## When changing the UI

- Mirror the existing dark "Live Intelligence Feed" aesthetic: dark panels,
  orange accent, uppercase header, left time column, tag chips, red urgent dot,
  `VIEW FULL LIVE FEED →` footer. The footer toggles between the recent feed
  (`/api/feed`) and the full archive (`/api/items`); keep both labels honest.
- Keep it responsive (the current layout collapses on narrow screens).
- Prefer server-provided `time_ago`; do not duplicate relative-time logic in
  JS unless there is a clear reason.
- Filter server-side: pass `tag`/`q` as query parameters instead of filtering
  the returned array in JS (the two views must not be able to disagree).
- Render untrusted values through `escapeHtml()` and links through
  `safeHref()`, which only allows http/https.

## Common pitfalls

- **Timezone-naive datetimes** break sorting. Always use
  `_ensure_aware()` before comparing `published`; it converts aware values to
  UTC, which the SQLite adapter needs because it orders rows by the stored ISO
  string.
- **Sample rows** must stay invisible once live rows exist (invariant 4), in
  the store *and* in the OpenSearch index (invariant 14).
- **HTML summaries** must be stripped/truncated with `_strip_html()` and
  `_truncate()` before rendering.
- **NVD keyword queries** return oldest-first. `_fetch_nvd()` queries a
  bounded `pubStartDate` window and sorts client-side; one page covers the
  window, and only an overflow falls back to the last page. Keep that shape
  instead of re-introducing a full-history `totalResults` probe.
- **KEV items can duplicate another source.** The KEV source hashes the NVD
  detail URL, so one CVE can appear both as a KEV item and as an NVD/GHSA item
  under different ids. That near-duplicate is expected; do not "fix" it by
  dropping the KEV item, which is the only one guaranteed to be urgent.
- **CISA feed noise.** CISA publishes ICS/OT advisories too; keep the
  topic filter in `_is_relevant()` when touching that source.
- **Lockfiles are generated.** Never hand-edit `uv.lock`; edit
  `pyproject.toml`, re-lock, and commit both files.
- **`SET` inside a transaction is rolled back.** The pool `configure` callback
  commits its session timeouts; the migration runner commits between files.
  Do not wrap a `SET` in an implicit transaction and expect it to survive.
- **Supavisor ignores DSN `options`** and reports its own `application_name`.
  Session guards (`statement_timeout`, idle-transaction timeout, lock timeout)
  must be applied with an explicit committed `SET`, not connection-string
  options.
- **`executemany()` prepares on the first execution** with psycopg, so keep
  `DB_PREPARE_THRESHOLD` unset for transaction mode and `5` only for
  direct/session mode.
- **Never point `TEST_DATABASE_URL` at a hosted database.** The Postgres tests
  truncate tables; they refuse remote hosts unless
  `ALLOW_REMOTE_TEST_DB=1` is set explicitly.

## Definition of done

- [ ] `uv lock --check`, `uv sync --frozen`, and `uv run --frozen pytest -q` are green
- [ ] Runtime audit is clean (CI runs `pip-audit`)
- [ ] `python -m app.migrate check` reports the schema current
- [ ] Server starts and `/health` returns `{"status":"ok"}` without a DB query
- [ ] `/ready` returns 200 with the database and 503 without it
- [ ] `/api/feed` returns valid items (or sample fallback) without waiting on a refresh
- [ ] Docker image builds from the frozen lock
- [ ] Frontend edits: `node --check frontend/app.js`, no new dependency, no `alert()` placeholders
- [ ] README (sources table, API tables, item schema) and AGENTS.md updated when
      behaviour, ports, invariants, or the item contract change
