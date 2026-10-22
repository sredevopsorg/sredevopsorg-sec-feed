# Security Intelligence Live Feed

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/sredevopsorg/sredevopsorg-sec-feed)

A real-time security intelligence feed for **Linux**, **cloud**, and
**Kubernetes** security content: security advisories, CVEs, threats, exploits,
and patches.

The UI mirrors the dark "Live Intelligence Feed" design with:

- relative timestamps (`6 hours`, `1 day`)
- colored topic/severity tags
- red "urgent" notification dots
- tag filters
- a `VIEW FULL LIVE FEED →` footer

![Security Intelligence Live Feed UI preview](screenshot.png)

## Status

The feed works end-to-end: live sources are fetched, normalized (including
distro patch status), enriched (CISA KEV + EPSS + OSV.dev), deduplicated,
prioritized, persisted to PostgreSQL (or SQLite locally), searchable
(`/api/search`), pushed to the browser over SSE, rendered in a single-page
frontend, and urgent items trigger alerts via Discord/Slack/email/log channels.

The architectural refactor is complete (see `docs/architecture.md`): the
frontend and backend are separate deployables, configuration is centralized, a
single `Storage` port backs SQLite/PostgreSQL adapters, the domain model is
extracted, and the refresh runs as an explicit
`fetch → enrich → persist → index → publish → alert` pipeline.

A follow-up audit fixed the correctness, redundancy and deployment/doc drift
found afterwards; those changes are listed in the
[architecture delivery record](docs/architecture.md#follow-up-audit-2025-09).

Dependencies are declared in `pyproject.toml` and hash-locked in the committed
`uv.lock`; Docker and CI install from that lock with `uv sync --frozen`
([ADR-0006](docs/adr/0006-uv-lock-and-dependency-policy.md)).

## Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.13, FastAPI, httpx, feedparser |
| Dependencies | `pyproject.toml` direct pins + committed `uv.lock` (hash-locked; `uv sync --frozen`) |
| Frontend | Static HTML/CSS/JS in `frontend/`, served by non-root nginx (UID 101, port 8080) — no build step, no CDN |
| Storage | PostgreSQL primary store, SQLite fallback, in-memory cache |
| Live updates | Server-Sent Events (`/api/events`) with polling fallback |
| Enrichment | CISA Known Exploited Vulnerabilities + FIRST EPSS + OSV.dev |
| Search | `/api/search` with SQL fallback (Postgres/SQLite) or optional OpenSearch |
| Alerting | Discord webhook (primary) / Slack webhook / SMTP email / log for urgent items |
| Deployment | Docker/Podman compose + Kubernetes manifests |

All roadmap items are complete for v1.4.0.

The frontend and backend are separate deployables: the backend is a pure JSON
API (`/api/*`, `/health`) and the frontend is a static app served by nginx that
reverse-proxies `/api` to the backend. They can also be hosted on different
origins via `window.__API_BASE_URL__` (see `frontend/config.js`) plus the
backend's `CORS_ORIGINS` setting. CORS **fails closed**: with `CORS_ORIGINS`
unset, no cross-origin caller is allowed, so set it explicitly when the frontend
is hosted on a different origin from the API.

## Sources

| Source | Kind | Focus |
|---|---|---|
| Ubuntu Security Notices | RSS | Linux |
| Debian Security Advisories | RSS | Linux |
| Red Hat CVE Database | JSON API | Linux / cloud |
| Kubernetes Official CVE Feed | RSS | Kubernetes |
| Google Cloud Security Bulletins | RSS | Cloud |
| Amazon Linux 2023 Advisories (ALAS) | RSS | Linux / cloud |
| AWS Security Bulletins | RSS | Cloud |
| CISA Cybersecurity Advisories (topic-filtered) | RSS | Threats |
| NVD CVE 2.0 (`linux kernel`, `kubernetes`, `cloud` queries) | JSON API | CVE |
| CISA KEV — newly exploited (last 7 days) | JSON API | Exploited in the wild |
| GHSA — containerd, runc, Argo CD, Istio, Envoy, Moby, CRI-O | GitHub Advisory API | Kubernetes / cloud-native |

### Notes on source handling

- The Kubernetes Official CVE Feed is generated from the `official-cve-feed`
  label on `kubernetes/kubernetes` issues; it replaces the old filtered
  Kubernetes Blog feed and carries CVE items directly.
- NVD queries use a bounded `pubStartDate` window (`NVD_WINDOW_DAYS`, default
  7). One page covers the whole window for every keyword we query, so a
  refresh costs one request per NVD source; a rare overflow probes the last
  page instead. The keyword queries start at least `NVD_STAGGER_SECONDS`
  (2 s) apart so concurrent fetches stay inside NVD's unauthenticated
  5-requests/30 s limit.
- CISA is the only broad feed still filtered for relevance: its ICS/OT
  advisories are dropped.
- The CISA KEV source publishes catalog entries added in the last
  `KEV_SOURCE_DAYS` (default 7) days. They are urgent by definition, and they
  close the gap for exploited CVEs that no keyword feed mentions — enrichment
  alone only flags CVEs another source already published. The KEV catalog and
  the GHSA sources cover confirmed exploitation and upstream advisories,
  which is also why the retired ZDI zero-day feeds are not replaced with a
  like-for-like source.
- The GHSA sources issue one GitHub Advisory Database query per curated
  package (`containerd`, `runc`, `argo-cd`, `istio`, `envoy`, `moby`,
  `cri-o`). Add a package by appending a `Source` in `app/sources.py`; set
  `GITHUB_TOKEN` to raise the unauthenticated 60-request/hour limit.
- Amazon Linux 2023 publishes its full errata history in one feed (~1.5 MB);
  items are capped by `max_items`.
- If a source fails, the rest of the feed continues. If **all** live sources
  fail, the server serves realistic sample items so the UI is always usable.

## Project layout

```text
.
├── app/
│   ├── __init__.py       # Package marker
│   ├── config.py         # Centralized Settings (ADR-0002)
│   ├── http_client.py    # Shared outbound user agent + bounded timeouts
│   ├── models.py         # Domain model (FeedItem) + serialization (ADR-0004)
│   ├── main.py           # FastAPI API routes (pure JSON API)
│   ├── sources.py        # Source definitions
│   ├── fetcher.py        # Fetching + normalization of upstream sources
│   ├── pipeline.py       # Refresh orchestration: fetch → enrich → persist → prune → index → publish → alert
│   ├── enrich.py         # CISA KEV + EPSS enrichment; KEV source builder
│   ├── osv.py            # OSV.dev enrichment (affected/fixed/severity)
│   ├── search.py         # Search backend (OpenSearch + SQL fallback)
│   ├── store.py          # Storage facade/port (selects backend; ADR-0003)
│   ├── sqlite_store.py   # SQLite storage adapter
│   ├── postgres_store.py # PostgreSQL storage adapter
│   ├── events.py         # SSE pub/sub broker
│   ├── ratelimit.py      # In-process fixed-window rate limiting
│   └── alerts.py         # Discord / Slack / email / log alerting
├── frontend/
│   ├── index.html        # Single-page frontend (markup)
│   ├── styles.css        # Styles
│   ├── app.js            # Frontend logic (consumes the JSON API)
│   ├── config.js         # Runtime config (API base URL)
│   ├── nginx.conf        # nginx config (serves the SPA, proxies /api)
│   ├── security-headers.conf # CSP + Permissions-Policy snippet (included by nginx.conf)
│   └── Dockerfile        # Frontend (nginx) image
├── tests/
│   ├── test_feed.py      # Feed normalization / dedup logic
│   ├── test_osv.py       # OSV enrichment
│   ├── test_alerts.py    # Alert formatting
│   ├── test_store.py     # SQLite persistence
│   ├── test_postgres_store.py # PostgreSQL adapter (needs TEST_DATABASE_URL)
│   ├── test_migrate.py   # Versioned migrations + feed_app grants
│   ├── test_search.py    # Search document mapping
│   ├── test_config.py    # Settings
│   ├── test_models.py    # Domain model + storage selection
│   ├── test_http.py      # Outbound HTTP policy (user agent + timeouts)
│   ├── test_api.py       # API surface (routes, CORS, rate limiting)
│   ├── test_events.py    # SSE broker subscriber cap
│   ├── test_ratelimit.py # Rate limiter
│   └── test_pipeline.py  # Refresh pipeline
├── migrations/           # Versioned PostgreSQL schema (applied by app.migrate)
├── docs/
│   ├── architecture.md   # Architecture review (C4) + delivery record
│   ├── adr/              # Architecture Decision Records
│   ├── supabase-migration-plan.md # Hosted-Postgres analysis
│   └── supabase-improvements.md   # Proposed caching / search / Supabase features
├── deploy/
│   └── k8s/              # Kubernetes manifests (api, frontend, NetworkPolicy,
│                         #   postgres/PDB/Ingress/OpenSearch optional;
│                         #   migrate-job.yaml optional; secret.example.yaml is a template)
├── Dockerfile            # API image (non-root, production)
├── docker-compose.yml    # Base services (local build; reads .env)
├── docker-compose.supabase.yml # Overlay: hosted Supabase, skips local postgres
├── docker-compose.prod.yml # Production overrides (digest-pinned images)
├── .env.example          # Template for the gitignored .env
├── pyproject.toml        # Project metadata + direct dependencies
├── uv.lock               # Committed hash-locked dependency graph
├── README.md
└── AGENTS.md
```

## Quickstart (container-first)

Only Docker (or Podman) is required — no host Python setup.

### Development

Compose takes credentials from a local `.env` file (gitignored); create it once
and set real values:

```bash
cp .env.example .env   # then edit POSTGRES_USER / POSTGRES_PASSWORD / POSTGRES_DB
docker compose up --build
```

This builds the `web` (nginx) and `api` (FastAPI) images from source, runs the
one-shot `migrate` job to create/upgrade the schema, and then starts the API
alongside PostgreSQL:

- UI — <http://localhost:8080>
- API — <http://localhost:8000> (also reachable on the UI origin at `/api`,
  which nginx reverse-proxies to the API container)

The API container never creates schema at startup: it verifies that the latest
`migrations/*.sql` version is applied. Compose runs `migrate` first (idempotent)
and waits for it to complete.

To run against hosted Supabase instead of the local database, see
[Hosted Supabase](#hosted-supabase).

The images are the same ones used in production, so there is no source mount and
no hot reload: re-run `docker compose up --build` after changing code.

For a faster edit/refresh loop, run the API on the host with `uvicorn --reload`
(see [Run without containers](#run-without-containers-optional)) and serve
`frontend/` with any static file server, pointing `window.__API_BASE_URL__` at
<http://localhost:8000> and setting `CORS_ORIGINS=http://localhost:8080` on the
API (cross-origin calls are denied by default).

### Production

```bash
cp .env.example .env   # once, on the deploy host; set real credentials
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

This pulls the published `ghcr.io/...:web` and `ghcr.io/...:latest` images and
runs them non-root with no source mounts. Run
`docker compose -f docker-compose.yml -f docker-compose.prod.yml pull` (or add
`--no-build`) first, so Compose cannot fall back to building the base file's
`build:` contexts. The `api`, `web`, and `postgres` images are pinned by digest
for reproducibility, so a new release is adopted only when its digest is
updated in `docker-compose.prod.yml` (resolve one with
`docker buildx imagetools inspect <image>:<tag>`).

> The first feed refresh runs in the background on startup (single-flight) and
> never blocks a request: every request is answered from the configured store,
> which is seeded with sample rows until live data arrives. The cache refreshes
> every 10 minutes; the browser updates via SSE (`/api/events`) and falls back
> to polling every 5 minutes.

When `DATABASE_URL` is unset, the app uses SQLite (`./data/feed.db` locally, or
the `feed-data` volume in containers).

### Frontend configuration

The frontend is a dependency-free static app in `frontend/`. It reads the API
origin from `window.__API_BASE_URL__` (set in `frontend/config.js`):

- Leave it empty (`""`) to call the API on the same origin (the default when
  served behind a reverse proxy).
- Set it to an absolute URL (e.g. `"https://feed.example.com"`) to host the
  frontend separately from the API. That deployment also needs the API's
  `CORS_ORIGINS` set and the frontend's CSP `connect-src` extended to include
  that origin (`frontend/security-headers.conf`).

The nginx image sends `Content-Security-Policy`, `Permissions-Policy`,
`X-Content-Type-Options`, `X-Frame-Options`, and `Referrer-Policy` on every
response.

### Run without containers (optional)

Install [uv](https://docs.astral.sh/uv/) 0.13.1 or newer, then:

```bash
uv sync --frozen
uv run --frozen uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

This starts the API only (no UI); serve `frontend/` with any static file server.

### Dependency management

Direct dependencies live in `pyproject.toml`; the full resolved graph is
committed in `uv.lock` with hashes. Docker and CI install only from that lock.

```bash
uv lock                 # re-resolve after editing pyproject.toml
uv lock --upgrade       # refresh transitive dependencies
uv lock --check         # verify the lock matches pyproject.toml
uv sync --frozen        # install exactly the locked graph (incl. dev tools)
uv run --frozen pytest -q
```

To audit the runtime graph (CI runs the same check):

```bash
uv sync --frozen --no-dev
uvx --from pip-audit==2.10.1 pip-audit \
  --path .venv/lib/python3.13/site-packages --strict
uv sync --frozen        # restore the dev tools afterwards
```

`uv.lock` is generated and must never be edited by hand. Renovate updates both
`pyproject.toml` and `uv.lock`, and lock-file maintenance refreshes transitives.

### Alerting environment variables

Channels are opt-in; Discord is the primary channel:

| Variable | Channel |
|---|---|
| `DISCORD_WEBHOOK_URL` | Discord incoming webhook (primary) |
| `SLACK_WEBHOOK_URL` | Slack incoming webhook |
| `ALERT_EMAIL_TO` + `SMTP_HOST` | SMTP email |
| none | Log-only fallback |

Without any channel configured, urgent items are logged only.

### HTTP hardening environment variables

| Variable | Default | Purpose |
|---|---|---|
| `CORS_ORIGINS` | unset (deny all) | Comma-separated cross-origin allow-list; required only when the frontend is hosted on another origin |
| `RATE_LIMIT_PER_MINUTE` | `120` | Per-client limit for `/api/search` and `/api/events`; `0` disables |
| `RATE_LIMIT_TRUST_PROXY` | `true` | Key on the last `X-Forwarded-For` hop (set `false` when the API is directly reachable) |
| `MAX_SSE_SUBSCRIBERS` | `100` | Concurrent `/api/events` subscribers before `503`; `0` disables the cap |

### Source tuning environment variables

| Variable | Default | Purpose |
|---|---|---|
| `GITHUB_TOKEN` | unset | Raises the GitHub API limits for the GHSA sources |
| `NVD_WINDOW_DAYS` | `7` | Publication window per NVD query; the newest CVEs inside it enter the feed |
| `KEV_SOURCE_DAYS` | `7` | How recently a CISA KEV addition must be added to enter the feed as an urgent item |
| `EPSS_MAX_CVES` | `200` | Total CVEs scored per refresh (chunked into requests of 100); `0` removes the cap |
| `OSV_MAX_CVES_PER_RUN` | `50` | CVEs fetched from OSV.dev per refresh, urgent/recent first; `0` removes the cap |

### Refresh and retention environment variables

| Variable | Default | Purpose |
|---|---|---|
| `FEED_CACHE_TTL` | `600` | Seconds before `/api/feed` schedules a background refresh; minimum `30` |
| `RETENTION_DAYS` | `180` | Archive retention for non-sample rows; `0` disables pruning |

Sources also carry a per-source minimum fetch interval (for example distro
advisories every 30 minutes and NVD/GHSA hourly). Sources
that send `ETag`/`Last-Modified` are fetched conditionally and an unchanged
body is answered with `304`, reusing the last normalized payload.

### PostgreSQL + OpenSearch via Compose

`docker compose up --build` starts the frontend (`web`), the one-shot `migrate`
job, the API (`api`), and PostgreSQL. The job applies `migrations/*.sql` using
the admin role; the API then starts and verifies the schema version (it never
creates DDL itself). To run without PostgreSQL, use the SQLite fallback by
removing `DATABASE_URL` from the `api` service (or run the API on the host with
`DATABASE_URL` unset).

To add OpenSearch search, run:

```bash
docker compose --profile search up --build
```

Then uncomment `OPENSEARCH_URL=http://opensearch:9200` in the `api` service
environment. Without OpenSearch, `/api/search` falls back to SQL (Postgres
`ILIKE` or SQLite `LIKE`).

When OpenSearch is enabled, the app creates the index with an explicit mapping
on startup and keeps it in sync with the archive automatically (incremental
indexing per refresh plus a throttled full reconcile) — all best-effort, so an
unavailable OpenSearch never breaks the feed. Sample/fallback rows are never
indexed, and any sample document left over from an earlier offline boot is
purged once live rows exist, so search matches the SQL behaviour exactly.

### Hosted Supabase

Supabase is the supported production database. The API connects through the
**shared pooler in session mode** (`aws-N-REGION.pooler.supabase.com:5432`),
which is IPv4 on every plan and supports prepared statements and session state.

There are two database roles:

| Role | DSN variable | Used by | Privileges |
|---|---|---|---|
| `feed_app.PROJECT-REF` | `DATABASE_URL` | API container | `SELECT/INSERT/UPDATE/DELETE` on the three app tables; no DDL, no other schemas |
| `postgres.PROJECT-REF` | `ADMIN_DATABASE_URL` | `migrate` job / one-shot commands only | schema ownership, role creation, migrations |

Put both in `.env` (gitignored; keep it mode `600`):

```bash
DATABASE_URL="postgresql://feed_app.PROJECT-REF:APP_PASSWORD@aws-0-us-west-2.pooler.supabase.com:5432/postgres"
ADMIN_DATABASE_URL="postgresql://postgres.PROJECT-REF:ADMIN_PASSWORD@aws-0-us-west-2.pooler.supabase.com:5432/postgres"
DB_SSLMODE=require
DB_PREPARE_THRESHOLD=5        # session mode only
DB_POOL_MAX_SIZE=4
```

One-time setup for a new project (after `migrations/0001_baseline.sql` exists):

```bash
# 1. Apply schema, grants, RLS and the NOLOGIN feed_app role.
ADMIN_DATABASE_URL=... uv run python -m app.migrate upgrade

# 2. Give feed_app a password (generated, URL-safe; never commit it).
FEED_APP_PASSWORD="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')" \
  ADMIN_DATABASE_URL=... uv run python -m app.migrate bootstrap-role

# 3. Verify the DSN and start the stack.
docker compose -f docker-compose.yml -f docker-compose.supabase.yml up --build
```

`migrate` is a one-shot service: it applies pending migrations, retries while
the database starts, and the API waits for it to complete. Re-running it is a
no-op. After `bootstrap-role` sets a new `feed_app` password, Supavisor may
briefly cache the previous credential; retry the first login after a few
seconds. Check the schema without changing anything:

```bash
ADMIN_DATABASE_URL=... uv run python -m app.migrate check
```

The overlay puts the local `postgres` services behind the `local-db` profile,
so `docker compose -f docker-compose.yml -f docker-compose.supabase.yml up`
does not start a local database.

Connection settings:

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | unset (→ SQLite) | runtime DSN (DML-only role) |
| `ADMIN_DATABASE_URL` | unset | privileged DSN, migrations only |
| `DB_POOL_MIN_SIZE` / `DB_POOL_MAX_SIZE` | `1` / `4` | application pool bounds (budget: `max × workers × replicas` must stay below the Supabase connection limit) |
| `DB_POOL_TIMEOUT` | `30` | seconds to wait for a pooled connection |
| `DB_POOL_MAX_IDLE` / `DB_POOL_MAX_LIFETIME` | `600` / `3600` | recycle idle/stale connections (seconds) |
| `DB_PREPARE_THRESHOLD` | unset (off) | set `5` only on direct/session mode |
| `DB_CONNECT_TIMEOUT` | `10` | libpq connect timeout (seconds) |
| `DB_STATEMENT_TIMEOUT_MS` | `15000` | per-session query timeout |
| `DB_IDLE_TX_TIMEOUT_MS` | `30000` | release leaked idle transactions |
| `DB_LOCK_TIMEOUT_MS` | `5000` | bound lock waits |
| `DB_SSLMODE` | `prefer` | `require` for Supabase; a remote host with `prefer` is rejected at startup |
| `DB_SSLROOTCERT` | unset | CA file for `verify-full` (optional but recommended) |
| `DB_APPLICATION_NAME` | `security-feed` | direct/self-hosted only; Supavisor reports its own name |

**TLS.** `require` encrypts but does not verify the server. For `verify-full`,
download the project CA from the Supabase dashboard (**Database settings → SSL
configuration**), mount it into the API and migrate containers, and set
`DB_SSLMODE=verify-full` plus `DB_SSLROOTCERT=/path/to/prod-supabase.cer`.

**Pooler notes.** Supavisor ignores DSN `options` and overwrites
`application_name`, so the app applies `statement_timeout`, idle-transaction and
lock timeouts with an explicit committed `SET` on every pooled connection.
Transaction mode (`:6543`) does not support prepared statements, session state
or session-level advisory locks; this project targets session mode (or a direct
connection). `DB_PREPARE_THRESHOLD` must be a code setting, not a URL parameter
(libpq rejects it in the connection string).

Free-plan projects pause after about a week of low activity; the `/ready`
probe keeps the project active, and a paid plan removes pausing. Daily
backups/PITR are a plan-level decision — confirm them before relying on the
hosted database as the only copy.

### Kubernetes quickstart

Requires `kubectl` and access to a cluster (Kustomize is built into `kubectl`).

```bash
# Deploy the API, the frontend, the ConfigMap, and the Traefik IngressRoute
kubectl apply -k deploy/k8s

# Watch the pods become ready (frontend `web` and API `api` pods)
kubectl get pods -l app=security-feed-web -w
kubectl get pods -l app=security-feed-api -w
```

Access the app with a port-forward:

```bash
kubectl port-forward svc/security-feed-web 8000:80
```

Then open <http://localhost:8000>.

**What gets deployed by default** (`deploy/k8s/kustomization.yaml`):

- `security-feed-api` — the backend (Deployment + internal ClusterIP Service
  `api` on port 8000). It runs as UID 10001 and persists to **hosted Postgres**
  through `DATABASE_URL` (the DML-only `feed_app` role), so there is no SQLite
  volume and no PVC. It does not set `SECURITY_FEED_DB`.
- `security-feed-web` — the frontend (`nginxinc/nginx-unprivileged` Deployment
  running as UID 101 on port 8080 + ClusterIP Service on port 80). It
  reverse-proxies `/api` to the internal `api` Service, and the pod is
  `runAsNonRoot`.
- `security-feed-api-config` — ConfigMap for `LOG_LEVEL`, `CORS_ORIGINS`,
  rate-limit/SSE tuning, and the `DB_*` connection settings (`DB_SSLMODE`,
  `DB_APPLICATION_NAME`). Put real Discord/Slack/email webhook values in a
  **Secret**, not here — a webhook URL is a credential.
- `security-feed-ingressroute` — a Traefik `IngressRoute` (not a
  `networking.k8s.io` Ingress) that publishes the app on
  `security-feed.sredevops.org`, routing `/api` straight to the `api` Service on
  8000 and everything else to `security-feed-web` on 80, with TLS from the
  `security-feed-sredevops-tls` Secret (provisioned out-of-band; it holds a
  private key and is not templated here).
- `security-feed-api-secrets` — **not applied by kustomize**. This repo ships
  only `secret.example.yaml` (placeholders), so create the real Secret
  out-of-band before deploying. The API needs only the DML-only `DATABASE_URL`;
  the privileged `ADMIN_DATABASE_URL` is used by `migrate-job.yaml`, never by
  the API container:

  ```bash
  kubectl -n security-feed create secret generic security-feed-api-secrets \
    --from-literal=DATABASE_URL="postgresql://feed_app.PROJECT-REF:APP_PASSWORD@HOST:5432/postgres" \
    --from-literal=ADMIN_DATABASE_URL="postgresql://postgres.PROJECT-REF:ADMIN_PASSWORD@HOST:5432/postgres" \
    --from-literal=FEED_APP_PASSWORD="APP_PASSWORD"
  ```

  Then apply the optional migration Job before rolling the API:

  ```bash
  kubectl -n security-feed apply -f deploy/k8s/migrate-job.yaml
  kubectl -n security-feed wait --for=condition=complete job/security-feed-migrate --timeout=5m
  ```

  For GitOps, manage it with Sealed Secrets, the External Secrets Operator, or
  SOPS instead of committing plaintext.

**Optional components are shipped but commented out** of
`deploy/k8s/kustomization.yaml`. Enable them deliberately:

| Component | How to enable | Notes |
|---|---|---|
| PostgreSQL (in-cluster) | Uncomment `- postgres.yaml` in `kustomization.yaml` and point `DATABASE_URL` at `postgresql://USER:PASSWORD@postgres:5432/DB` | Only needed if you do **not** want hosted Supabase, which is the default. Credentials come from `security-feed-api-secrets` (created out-of-band, above); the PVC is `ReadWriteOnce` |
| NetworkPolicies | Uncomment `- networkpolicy.yaml` | Shipped but **not applied** by default. Enforcement needs a CNI that implements NetworkPolicy |
| PodDisruptionBudgets | Uncomment `- pdb.yaml` | `minAvailable: 1` with `replicas: 1` blocks node drains, so raise the API/web replicas to at least 2 first |
| Generic Ingress (non-Traefik) | Uncomment `- ingress.yaml`, drop `- ingressroute.yaml`, and set a real host + TLS | Only for clusters without Traefik. The default is the `IngressRoute`; the sample host in `ingress.yaml` is `security-feed.example.com` |
| OpenSearch | Uncomment `- opensearch.yaml` and `OPENSEARCH_URL` in `configmap.yaml` | Without it, `/api/search` falls back to SQL (Postgres `ILIKE`), so search needs no extra infrastructure. Requires `vm.max_map_count >= 262144` on the node, and runs without auth |

The API no longer uses a `security-feed-api-data` PVC: hosted Postgres is the
store, so `pvc.yaml` was removed with the SQLite path. If you deliberately want
SQLite on a volume, add a PVC back, mount it at `/app/data`, and set
`SECURITY_FEED_DB=/app/data/feed.db` on the container.

## API

| Method | Path | Description |
|---|---|---|
| `GET` | `/api` | API descriptor (name, version, endpoints) |
| `GET` | `/api/feed` | Normalized feed JSON |
| `GET` | `/api/items` | Search/filter the persistent archive |
| `GET` | `/api/search?q=...` | Full-text search (OpenSearch when configured, otherwise SQL — Postgres `ILIKE` or SQLite `LIKE`) |
| `GET` | `/api/stats` | Counts by severity/tag plus enrichment coverage (cached ~30 s; not a live query per request) |
| `GET` | `/api/events` | Server-Sent Events stream |
| `GET` | `/api/sources` | Configured sources |
| `GET` | `/health` | Liveness only: process/cache status and pipeline step outcomes, **no database query** |
| `GET` | `/ready` | Readiness: cheap database ping (`SELECT 1`), `503` when unreachable |

### `/api/feed`

Query parameters:

| Parameter | Type | Default | Description |
|---|---|---|---|
| `tag` | string | — | Filter by one tag, e.g. `kubernetes` |
| `severity` | string | — | Filter by severity, e.g. `critical` |
| `limit` | int | `50` | Max items (1–200) |

Example:

```bash
curl 'http://localhost:8000/api/feed?tag=kubernetes&severity=critical&limit=20'
```

The response carries `source_errors`: one line per source that could not be
reached in the last refresh, shaped `<source-id>: <ExceptionType>: <detail>`.
When the exception has no message of its own — httpx reports a blackholed
connection as a message-less `ConnectTimeout` — the unreachable host is named
instead, e.g. `debian: ConnectTimeout reaching www.debian.org`. The rest of the
feed is unaffected: items from every source that answered are served as usual.
A fetch is retried once when the *connection* fails; HTTP error responses
(4xx/5xx) are never retried, so a source's own rate limiting is respected.

### `/api/items`

Same filters as `/api/feed`, but reads the whole persistent archive instead of
the live cache (default `limit` 100, max 1000).

| Parameter | Type | Default | Description |
|---|---|---|---|
| `tag` | string | — | Filter by one tag |
| `severity` | string | — | Filter by severity |
| `limit` | int | `100` | Max items (1–1000) |

### `/api/search`

| Parameter | Type | Default | Description |
|---|---|---|---|
| `q` | string | `""` | Free-text query over title, summary, source and CVE ids |
| `tag` | string | — | Filter by one tag |
| `severity` | string | — | Filter by severity |
| `limit` | int | `50` | Max items (1–200) |

The response adds `backend` (`opensearch` or `sql`) so callers can tell which
engine answered. A `%` or `_` in `q` is escaped, so it matches literally instead
of acting as a SQL wildcard.

### Rate limiting

`/api/search` and `/api/events` are rate limited per client (default 120
requests/minute; `RATE_LIMIT_PER_MINUTE=0` disables it). Over the limit returns
`429 Too Many Requests` with a `Retry-After` header.

`/api/events` also caps concurrent subscribers (default 100) and returns
`503 Service Unavailable` with `Retry-After: 30` when the cap is reached.

The limiter is in-process, so with N API replicas the effective limit is N ×
`RATE_LIMIT_PER_MINUTE`. The client key is the last `X-Forwarded-For` hop by
default, which the bundled nginx appends and a client cannot forge; set
`RATE_LIMIT_TRUST_PROXY=false` when the API is reachable directly (for example
through Compose's published port 8000) so the socket peer is used instead.

### Feed item schema

```json
{
  "id": "a1b2c3d4e5f6a7b8",
  "title": "CVE-2024-21626: runc container escape",
  "summary": "runc before 1.1.12 contains a container escape…",
  "url": "https://example.com/advisory",
  "source": "Ubuntu Security Notices",
  "source_url": "https://ubuntu.com/security/notices/rss.xml",
  "published": "2025-01-01T12:00:00+00:00",
  "time_ago": "6 hours",
  "tags": ["linux", "kubernetes", "cve", "exploit", "patch"],
  "cves": ["CVE-2024-21626"],
  "severity": "critical",
  "urgent": true,
  "kev": true,
  "epss_score": 0.97,
  "osv_affected": ["Go:runc"],
  "osv_fixed": ["1.1.12"],
  "osv_severity": "high",
  "patch_status": "fixed",
  "is_sample": false
}
```

`epss_score` is `null` when EPSS is unavailable or has no score for the item's
CVEs, and `is_sample` is `true` only for the fallback rows the server serves
while no live source is reachable. `published` and `time_ago` are `null` when
the source carries no parseable publication date — the feed never invents one.
Items are ordered by publication time, with urgency as a badge and tiebreaker.

## Tagging and prioritization

- **Tags** are inferred from source scope plus title/summary keywords. The
  core set is `linux`, `cloud`, `kubernetes`, `cve`, `exploit`, `patch`,
  `threat`; enrichment and the KEV source add `kev` for known-exploited CVEs.
  Historical items may still carry the `zeroday` tag from the retired ZDI
  sources; it is no longer added to new items.
- **Severity** comes from CVSS when available, otherwise from textual heuristics.
- **Urgent** items are critical/high-severity and exploitation-related, plus
  every KEV-source item (CISA has confirmed exploitation); they render the red
  dot in the UI.
- **KEV** items are in CISA's Known Exploited Vulnerabilities catalog.
- **EPSS** is fetched from FIRST when CVEs are present (best-effort, first
  100 unique CVEs per refresh). `epss_score` is `null` when the score is
  unknown; `0.0` always means a real, known zero.
- **OSV.dev** adds affected packages, fixed versions, and severity for CVEs
  (best-effort, capped per refresh).
- **Patch status** (`fixed` | `affected` | `not-affected` | `deferred` |
  `unknown`) is normalized from distro advisories: Ubuntu/Debian notices map
  to `fixed`, and Red Hat's `package_state`/`affected_release` are reduced to
  a single canonical status.
- The feed is sorted by `urgent` first, then `published` descending.
- Sample/fallback rows are only shown while no live rows are available.

## Tests

```bash
uv sync --frozen
uv run --frozen pytest -q
```

CI runs on Python 3.13 (`.github/workflows/ci.yaml`): it verifies the lock with
`uv lock --check`, installs the frozen lock, runs `uv pip check`, runs the
tests, and audits the runtime graph with `pip-audit`. The frontend has no build
step or test runner; `node --check frontend/app.js` is the syntax check used
when editing it.

