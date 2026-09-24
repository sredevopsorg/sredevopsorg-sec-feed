# Security Intelligence Live Feed

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
found afterwards; those changes are listed under [Audit fixes](#audit-fixes-2025-09-one-pr-per-item).

## Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.13, FastAPI, httpx, feedparser |
| Frontend | Static HTML/CSS/JS in `frontend/`, served by non-root nginx (UID 101, port 8080) — no build step, no CDN |
| Storage | PostgreSQL primary store, SQLite fallback, in-memory cache |
| Live updates | Server-Sent Events (`/api/events`) with polling fallback |
| Enrichment | CISA Known Exploited Vulnerabilities + FIRST EPSS + OSV.dev |
| Malware | OpenSSF Malicious Packages (recent OSV reports) |
| Search | `/api/search` with SQL fallback (Postgres/SQLite) or optional OpenSearch |
| Alerting | Discord webhook (primary) / Slack webhook / SMTP email / log for urgent items |
| Deployment | Docker/Podman compose + Kubernetes manifests |

All roadmap items are complete for this release candidate (0.2.0-rc.1).

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
| Kubernetes Blog (security-filtered) | RSS | Kubernetes |
| AWS Security Bulletins | RSS | Cloud |
| CISA Cybersecurity Advisories (topic-filtered) | RSS | Threats |
| NVD CVE 2.0 (`linux kernel`, `kubernetes`, `cloud`) | JSON API | CVE |
| OpenSSF Malicious Packages (recent commits) | GitHub API | Supply-chain malware |

### Notes on source handling

- The NVD keyword API returns oldest matches first, so the fetcher reads
  `totalResults` and requests the last page to obtain the newest CVEs.
- CISA and the Kubernetes blog are broad feeds, so items are filtered for
  Linux/cloud/Kubernetes relevance before entering the feed.
- OpenSSF Malicious Packages uses the GitHub API and only processes new
  commits (no 1 GB clone). Set `GITHUB_TOKEN` to avoid unauthenticated rate
  limits. By default only Go/git ecosystems or packages mentioning
  Linux/cloud/Kubernetes tooling are included.
- If a source fails, the rest of the feed continues. If **all** live sources
  fail, the server serves realistic sample items so the UI is always usable.

## Project layout

```text
.
├── app/
│   ├── __init__.py       # Package marker
│   ├── config.py         # Centralized Settings (ADR-0002)
│   ├── models.py         # Domain model (FeedItem) + serialization (ADR-0004)
│   ├── main.py           # FastAPI API routes (pure JSON API)
│   ├── sources.py        # Source definitions
│   ├── fetcher.py        # Fetching + normalization of upstream sources
│   ├── pipeline.py       # Refresh orchestration: fetch → enrich → persist → index → publish → alert
│   ├── enrich.py         # CISA KEV + EPSS enrichment
│   ├── osv.py            # OSV.dev enrichment (affected/fixed/severity)
│   ├── search.py         # Search backend (OpenSearch + SQL fallback)
│   ├── ossf.py           # OpenSSF Malicious Packages GitHub-API source
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
│   ├── test_ossf.py      # OpenSSF source
│   ├── test_alerts.py    # Alert formatting
│   ├── test_store.py     # SQLite persistence
│   ├── test_postgres_store.py # PostgreSQL adapter (needs TEST_DATABASE_URL)
│   ├── test_search.py    # Search document mapping
│   ├── test_config.py    # Settings
│   ├── test_models.py    # Domain model + storage selection
│   ├── test_http.py      # Outbound HTTP policy (user agent + timeouts)
│   ├── test_api.py       # API surface (routes, CORS, rate limiting)
│   ├── test_events.py    # SSE broker subscriber cap
│   ├── test_ratelimit.py # Rate limiter
│   └── test_pipeline.py  # Refresh pipeline
├── docs/
│   ├── architecture.md   # Architecture review (C4) + delivery record
│   └── adr/              # Architecture Decision Records
├── deploy/
│   └── k8s/              # Kubernetes manifests (api, frontend, NetworkPolicy,
│                         #   postgres/PDB/Ingress/OpenSearch optional;
│                         #   secret.example.yaml is a template, not applied)
├── Dockerfile            # API image (non-root, production)
├── docker-compose.yml    # Base services (local build; reads .env)
├── docker-compose.prod.yml # Production overrides (digest-pinned images)
├── .env.example          # Template for the gitignored .env
├── requirements.txt      # Runtime dependencies (pinned)
├── requirements-dev.txt  # Test/dev dependencies (pinned)
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

This builds the `web` (nginx) and `api` (FastAPI) images from source and starts
them alongside PostgreSQL:

- UI — <http://localhost:8080>
- API — <http://localhost:8000> (also reachable on the UI origin at `/api`,
  which nginx reverse-proxies to the API container)

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

```bash
pip install -r requirements-dev.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

This starts the API only (no UI); serve `frontend/` with any static file server.

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

### PostgreSQL + OpenSearch via Compose

`docker compose up --build` starts the frontend (`web`), the API (`api`), and
PostgreSQL, and the API connects to PostgreSQL using the credentials from
`.env`. To run without PostgreSQL instead, comment out `DATABASE_URL` in the
`api` service; the app then falls back to SQLite (`./data/feed.db` locally, or
the `feed-data` volume in containers).

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

### PostgreSQL / Supabase configuration

Setting `DATABASE_URL` switches the store from SQLite to PostgreSQL (self-hosted
or hosted Supabase). On startup the app creates the schema idempotently —
tables, indexes, the `pg_trgm` extension, and row-level security — and connects
through an application-side connection pool.

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | unset (→ SQLite) | `postgresql://…` connection string |
| `DB_POOL_MIN_SIZE` | `1` | pool min size |
| `DB_POOL_MAX_SIZE` | `4` | pool max size (Supabase Nano/Micro allows 60 DB connections) |
| `DB_PREPARE_THRESHOLD` | unset (prepared statements off) | set `5` only on direct/session mode |
| `DB_CONNECT_TIMEOUT` | `10` | libpq connect timeout, seconds |
| `DB_SSLMODE` | `prefer` | set `require` for Supabase |
| `DB_APPLICATION_NAME` | `security-feed` | `application_name` in `pg_stat_activity` |

**Supabase.** Use the *session-mode* pooler (`:5432`) or a direct connection —
both support prepared statements and session state. Transaction mode (`:6543`)
also works because prepared statements are disabled by default. Copy the exact
host from the dashboard **Connect** dialog: the direct host is
`db.PROJECT-REF.supabase.co`, the pooler host is
`aws-INDEX-REGION.pooler.supabase.com`, and the pooler username is
`postgres.PROJECT-REF`.

```bash
DATABASE_URL="postgresql://postgres.PROJECT-REF:PASSWORD@aws-0-us-west-2.pooler.supabase.com:5432/postgres"
DB_SSLMODE=require
```

Notes: `DB_PREPARE_THRESHOLD` must stay a code setting, not a URL parameter
(libpq rejects it in the connection string). Free-plan projects pause after
about a week of low database activity; a deployed feed with background refresh
plus `/health` traffic keeps it active, and a paid plan removes pausing
altogether.

### Kubernetes quickstart

Requires `kubectl` and access to a cluster (Kustomize is built into `kubectl`).

```bash
# Deploy the API, the frontend, the ConfigMap, the NetworkPolicies, and the SQLite PVC
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
  `api` on port 8000). It runs as UID 10001 with a read-only root filesystem
  (`emptyDir` at `/tmp`) and sets `SECURITY_FEED_DB` (`/app/data/feed.db`), so
  **the default store is SQLite** on the `security-feed-api-data` PVC. The image
  is pinned by digest.
- `security-feed-web` — the frontend (`nginxinc/nginx-unprivileged` Deployment
  running as UID 101 on port 8080 + ClusterIP Service on port 80). It
  reverse-proxies `/api` to the internal `api` Service, and the pod is
  `runAsNonRoot` with all capabilities dropped and a read-only root filesystem
  (`emptyDir` mounts for the nginx cache/pid/tmp), like the API pod.
- `security-feed-api-config` — ConfigMap for `LOG_LEVEL`, optional
  `CORS_ORIGINS`, optional rate-limit/SSE tuning, and optional alerting env
  vars. Put real Discord/Slack/email webhook values in a Secret in production
  rather than the ConfigMap.
- `security-feed-*-ingress` — ingress-only NetworkPolicies restricting the API
  to the frontend pod, PostgreSQL to the API pod, and OpenSearch to the API
  pod. Egress is untouched. Enforcement needs a CNI that supports
  NetworkPolicy; remove `- networkpolicy.yaml` to disable them.
- `security-feed-api-secrets` — **not applied by kustomize**. This repo ships
  only `secret.example.yaml` (placeholders), so create the real Secret
  out-of-band before enabling PostgreSQL:

  ```bash
  kubectl -n security-feed create secret generic security-feed-api-secrets \
    --from-literal=POSTGRES_USER=feed \
    --from-literal=POSTGRES_PASSWORD="$(openssl rand -base64 24)" \
    --from-literal=POSTGRES_DB=feed \
    --from-literal=DATABASE_URL="postgresql://feed:PASSWORD@postgres:5432/feed"
  ```

  For GitOps, manage it with Sealed Secrets, the External Secrets Operator, or
  SOPS instead of committing plaintext.

**Optional components are shipped but commented out** of
`deploy/k8s/kustomization.yaml`. Enable them deliberately:

| Component | How to enable | Notes |
|---|---|---|
| PostgreSQL | Uncomment `- postgres.yaml` in `kustomization.yaml`, uncomment the `DATABASE_URL` env in `deployment.yaml`, and uncomment the `wait-for-postgres` init container next to it | Credentials come from `security-feed-api-secrets` (created out-of-band, above); the PVC is `ReadWriteOnce` |
| PodDisruptionBudgets | Uncomment `- pdb.yaml` | `minAvailable: 1` with `replicas: 1` blocks node drains, so raise the API/web replicas to at least 2 first |
| Ingress | Uncomment `- ingress.yaml` and set a real host + TLS | Needs an Ingress controller; the sample host is `security-feed.example.com` |
| OpenSearch | Uncomment `- opensearch.yaml` and `OPENSEARCH_URL` in `configmap.yaml` | Without it, `/api/search` falls back to SQL (Postgres `ILIKE`), so search needs no extra infrastructure. Requires `vm.max_map_count >= 262144` on the node, and runs without auth (ingress is restricted to the API pod by the NetworkPolicy) |

The `security-feed-api-data` PVC uses the cluster's default StorageClass.
Set `storageClassName` in `deploy/k8s/pvc.yaml` if your cluster requires an
explicit class (the manifests were previously hardcoded to `longhorn-rwx`).

## API

| Method | Path | Description |
|---|---|---|
| `GET` | `/api` | API descriptor (name, version, endpoints) |
| `GET` | `/api/feed` | Normalized feed JSON |
| `GET` | `/api/items` | Search/filter the persistent archive |
| `GET` | `/api/search?q=...` | Full-text search (OpenSearch when configured, otherwise SQL — Postgres `ILIKE` or SQLite `LIKE`) |
| `GET` | `/api/stats` | Counts by severity/tag |
| `GET` | `/api/events` | Server-Sent Events stream |
| `GET` | `/api/sources` | Configured sources |
| `GET` | `/health` | Cache + DB health |

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
while no live source is reachable.

## Tagging and prioritization

- **Tags** are inferred from source scope plus title/summary keywords. The
  core set is `linux`, `cloud`, `kubernetes`, `cve`, `exploit`, `patch`,
  `threat`; enrichment adds `kev` for CISA KEV hits, and the OpenSSF source adds
  `malware`, `supply-chain`, `malicious-packages` plus the affected ecosystem
  (`go`, `npm`, …, lowercased).
- **Severity** comes from CVSS when available, otherwise from textual heuristics.
- **Urgent** items are critical/high-severity and exploitation-related; they
  render the red dot in the UI.
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
pip install -r requirements-dev.txt
pytest -q
```

CI runs the same command on Python 3.13 (`.github/workflows/ci.yaml`). The
frontend has no build step or test runner; `node --check frontend/app.js` is the
syntax check used when editing it.

## Roadmap

- [x] Persistent store (SQLite) and search/filter endpoints
- [x] Enrichment: EPSS, CISA KEV, OSV.dev
- [x] SSE live updates
- [x] Slack / email / log alerts for `urgent` items
- [x] Discord webhook alerting as first alert option
- [x] Docker/Podman compose + Kubernetes manifests
- [x] OpenSearch search backend (optional) with SQL fallback
- [x] OpenSSF Malicious Packages source
- [x] PostgreSQL primary store (SQLite fallback when `DATABASE_URL` unset)
- [x] Distro patch-status normalization
- [x] OpenSearch auto-sync improvements

### Architecture (2025-09)

- [x] Frontend/backend separated into `web` (nginx) + `api` (FastAPI) deployables
- [x] Centralized configuration (`app/config.py` Settings)
- [x] `Storage` port with SQLite + PostgreSQL adapters
- [x] Extracted domain model (`app/models.py`)
- [x] Refresh pipeline decomposed into an explicit orchestrator (`app/pipeline.py`)

### Audit fixes (2025-09, one PR per item)

- [x] EPSS "unknown" reported as `null` instead of `0.0` (#15)
- [x] OSSF CVE ids normalized to uppercase via the shared extractor (#16)
- [x] All timestamps normalized to UTC so text-ordered queries are correct (#17)
- [x] `/api/feed` never blocks on a refresh; refresh is single-flight (#18)
- [x] `is_sample` exposed in the item contract (#19)
- [x] OpenSearch purges sample documents once live rows exist (#20)
- [x] Frontend: real footer archive toggle, source/sample notices, LIVE/OFFLINE pill, legible chips (#21)
- [x] nginx keeps security headers and stops caching `config.js` (#22)
- [x] One outbound HTTP policy (shared user agent + bounded timeouts) (#23)
- [x] Dead code, redundant guards and unused imports removed (#24)
- [x] Frontend image is genuinely non-root on port 8080; compose/k8s aligned (#25)
- [x] Documentation synced with the code (this PR)

Still deferred (not blocking): typed API response models (Pydantic), a shared
row-mapping/sample-hiding helper for the two storage adapters instead of
mirrored implementations, and a linter/formatter.

## Security To-Do

Reviewed: app code, Dockerfiles, docker-compose, Kubernetes manifests, GitHub Actions workflows.

Legend: 🔴 Critical · 🟠 High · 🟡 Medium · 🟢 Low / hardening

> **Status:** the code, container, Compose, and Kubernetes items below are
> resolved in this change. The four GitHub Actions items remain open — workflow
> files were deliberately out of scope here, so no `.github/workflows/` file was
> modified.

---

### Sprint 1 — Critical / High

- [x] 🔴 **Remove hardcoded Postgres credentials from `deploy/k8s/secret.yaml`**
  `stringData` shipped real values `feed`/`feed`/`feed` and a matching
  `DATABASE_URL`. **Resolved:** the manifest is now
  `deploy/k8s/secret.example.yaml`, holds only `REPLACE_ME` placeholders, and is
  excluded from `kustomization.yaml` so `kubectl apply -k` neither applies
  placeholders nor clobbers a real Secret. The file header, README, and
  AGENTS.md document creating it with `kubectl create secret`, or adopting
  Sealed Secrets / External Secrets Operator / SOPS so real credentials never
  live in git.

- [x] 🔴 **Stop shipping default Postgres credentials in `docker-compose.yml` / `docker-compose.prod.yml`**
  **Resolved:** `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` come from a
  gitignored `.env` (shipped as `.env.example`) and Compose fails closed
  (`${VAR:?…}`) when they are missing. The `postgres`, `postgres-init`, and
  `api` services interpolate them; both quickstarts start with
  `cp .env.example .env`, and the sample values carry a rotate-before-prod note.

- [x] 🟠 **Add rate limiting to `/api/events` and `/api/search`**
  **Resolved:** `app/ratelimit.py` adds a dependency-free in-process fixed-window
  limiter (default 120/min per client, `RATE_LIMIT_PER_MINUTE=0` disables it)
  applied to `/api/search` and `/api/events`, returning `429` with a
  `Retry-After` header. `app/events.py::Broker` now caps concurrent SSE
  subscribers (`MAX_SSE_SUBSCRIBERS`, default 100) and `/api/events` returns
  `503` when full. The limiter is per process, so N replicas allow N × the
  limit; the README documents that and the proxy-keying tradeoff.

- [x] 🟠 **Fail closed on CORS instead of defaulting to `"*"`**
  **Resolved:** `CORS_ORIGINS` now defaults to empty, so `CORSMiddleware` denies
  every cross-origin caller, and a clear startup warning is logged when `"*"` is
  set explicitly. The separately-hosted-frontend path documents setting
  `CORS_ORIGINS` (and extending CSP `connect-src`).

- [ ] 🟠 **Trim GitHub Actions job permissions to least privilege** — *deferred (workflow changes excluded)*
  `.github/workflows/multi-build.yaml` and `multi-build-front.yaml` grant
  `contents: write`, `issues: read`, `discussions: read`,
  `pull-requests: read`, `repository-projects: read`, `checks: write`,
  `statuses: read`, `security-events: read` to build/push jobs. Reduce to
  `contents: read`, `packages: write`, `id-token: write`, and
  `attestations: write` only if attestation is actually generated.

---

### Sprint 2 — Medium

- [ ] 🟡 **Add container image vulnerability scanning to CI** — *deferred (workflow changes excluded)*
  No Trivy/Grype step scans the built `api`/`web` images before pushing to
  GHCR. Add one to `multi-build.yaml` / `multi-build-front.yaml`, failing (or
  at least reporting) on critical/high CVEs.

- [ ] 🟡 **Extend CodeQL to cover the frontend** — *deferred (workflow changes excluded)*
  `.github/workflows/codeql.yml` only analyzes `python`. Add
  `javascript-typescript` to the language matrix so `frontend/app.js` gets
  static analysis coverage too.

- [x] 🟡 **Pin production images to digests, not mutable tags**
  **Resolved:** `docker-compose.prod.yml`, the k8s Deployments, and both
  Dockerfiles now reference `tag@sha256:…` digests (PostgreSQL and OpenSearch
  included) with `imagePullPolicy: IfNotPresent`. The README documents the bump
  procedure. `frontend/Dockerfile` pins `nginx-unprivileged:1.31.5-alpine` to its
  digest, so its comment and `FROM` line now agree.

- [x] 🟡 **Harden OpenSearch when enabled**
  **Resolved:** Compose publishes the unauthenticated port on `127.0.0.1` only;
  Kubernetes restricts ingress to the API pod via NetworkPolicy; and the
  `privileged: true` init container was replaced by a documented node-level
  `vm.max_map_count >= 262144` prerequisite. The security plugin stays disabled
  for this optional local setup, which is stated in the manifests and README.

- [x] 🟡 **Add Kubernetes NetworkPolicies**
  **Resolved:** `deploy/k8s/networkpolicy.yaml` (enabled by default) restricts
  PostgreSQL and OpenSearch ingress to the API pod and the API to the frontend
  pod; egress and unselected pods are untouched.

- [x] 🟡 **Set `readOnlyRootFilesystem: true`**
  **Resolved:** the API and web containers set `readOnlyRootFilesystem: true`,
  with explicit `emptyDir` mounts for `/tmp` (API) and `/var/cache/nginx`,
  `/var/run`, `/tmp` (web).

---

### Sprint 3 — Low / hardening

- [x] 🟢 **Add `Content-Security-Policy` and `Permissions-Policy` headers**
  **Resolved:** `frontend/security-headers.conf` (included by `nginx.conf` at the
  server level and in every location that sets its own `add_header`) sends a
  strict CSP (`default-src 'self'`, `frame-ancestors 'none'`, …) plus a
  `Permissions-Policy`, and the frontend Dockerfile copies the snippet into the
  image.

- [x] 🟢 **Escape `%` / `_` in search wildcards**
  **Resolved:** both adapters escape `\`, `%`, and `_` before wrapping the query
  in `%...%` (`search_feed`, plus the SQLite tag filter), with `ESCAPE '\'` on
  the SQLite clauses and PostgreSQL's default backslash escape otherwise. Tests
  cover both adapters.

- [ ] 🟢 **Pin `ci.yaml` actions to commit SHAs** — *deferred (workflow changes excluded)*
  `.github/workflows/ci.yaml` pins actions by tag (`@v7`, `@v5`), while the
  build workflows pin by commit SHA. Align `ci.yaml` with the same SHA-pinning
  practice for consistency and supply-chain safety.

---

## Already in good shape (no action needed)

- All SQL access is parameterized (SQLite and Postgres adapters) — no
  injection risk found.
- Frontend (`app.js`) escapes all feed-derived HTML and validates URLs
  before turning them into links — no XSS found.
- API and web containers already run non-root with dropped capabilities and
  `seccompProfile: RuntimeDefault`.
- Dependencies are exactly pinned in `requirements.txt`, and Renovate is
  configured for automatic updates.
- CodeQL and a `SECURITY.md` disclosure policy are already in place.
