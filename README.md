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

## Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.13, FastAPI, httpx, feedparser |
| Frontend | Static HTML/CSS/JS in `frontend/`, served by nginx (no build step, no CDN) |
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
backend's `CORS_ORIGINS` setting.

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
│   └── alerts.py         # Discord / Slack / email / log alerting
├── frontend/
│   ├── index.html        # Single-page frontend (markup)
│   ├── styles.css        # Styles
│   ├── app.js            # Frontend logic (consumes the JSON API)
│   ├── config.js         # Runtime config (API base URL)
│   ├── nginx.conf        # nginx config (serves the SPA, proxies /api)
│   └── Dockerfile        # Frontend (nginx) image
├── tests/
│   ├── test_feed.py      # Feed normalization / dedup logic
│   ├── test_osv.py       # OSV enrichment
│   ├── test_ossf.py      # OpenSSF source
│   ├── test_alerts.py    # Alert formatting
│   ├── test_store.py     # SQLite persistence
│   ├── test_search.py    # Search document mapping
│   ├── test_config.py    # Settings
│   ├── test_models.py    # Domain model + storage selection
│   ├── test_api.py       # API surface (routes, CORS)
│   └── test_pipeline.py  # Refresh pipeline
├── docs/
│   ├── architecture.md   # Architecture review (C4) + delivery record
│   └── adr/              # Architecture Decision Records
├── deploy/
│   └── k8s/              # Kubernetes manifests (api, frontend, postgres, PDB, …)
├── .devcontainer/        # Dev Container (VS Code / Codespaces)
├── Dockerfile            # API image (non-root, production)
├── docker-compose.yml    # Base services
├── docker-compose.override.yml  # Dev overrides (hot reload, source mounts)
├── docker-compose.prod.yml      # Production overrides (pinned images)
├── requirements.txt      # Runtime dependencies (pinned)
├── requirements-dev.txt  # Test/dev dependencies (pinned)
├── README.md
└── AGENTS.md
```

## Quickstart (container-first)

Only Docker (or Podman) is required — no host Python setup.

### Development

```bash
docker compose up --build
```

`docker compose` auto-applies `docker-compose.override.yml`, which mounts the
source and runs `uvicorn --reload`, so code changes hot-reload. The UI is served
at <http://localhost:8000>.

Alternatively, open this repo in a **Dev Container** (VS Code or GitHub
Codespaces) — see `.devcontainer/`.

### Production

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

This runs the pinned, non-root images (`ghcr.io/...:web` and
`ghcr.io/...:latest`) with no source mounts. (When `-f` is used, the dev
override is not loaded.)

> The first feed refresh runs in the background on startup. Subsequent requests
> are served from the configured store and refresh every 10 minutes; the
> browser updates via SSE (`/api/events`) and falls back to polling every 5
> minutes.

When `DATABASE_URL` is unset, the app uses SQLite (`./data/feed.db` locally, or
the `feed-data` volume in containers).

### Frontend configuration

The frontend is a dependency-free static app in `frontend/`. It reads the API
origin from `window.__API_BASE_URL__` (set in `frontend/config.js`):

- Leave it empty (`""`) to call the API on the same origin (the default when
  served behind a reverse proxy).
- Set it to an absolute URL (e.g. `"https://feed.example.com"`) to host the
  frontend separately from the API.

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

### PostgreSQL + OpenSearch via Compose

`docker compose up --build` starts the frontend (`web`), the API (`api`), and
PostgreSQL. By default the API uses SQLite; to use PostgreSQL, uncomment
`DATABASE_URL=postgresql://feed:feed@postgres:5432/feed` in the `api` service.

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
unavailable OpenSearch never breaks the feed.

### Kubernetes quickstart

Requires `kubectl` and access to a cluster (Kustomize is built into `kubectl`).

```bash
# Deploy the app, PostgreSQL (primary store), ConfigMap, Secret, and PVCs
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

**What gets deployed** by `kubectl apply -k deploy/k8s`:

- `security-feed-web` — the frontend (nginx Deployment + ClusterIP Service on
  port 80). It reverse-proxies `/api` to the internal `api` Service.
- `security-feed-api` — the backend API (Deployment + internal ClusterIP
  Service `api` on port 8000). An init container waits for PostgreSQL before
  startup, and the API reads `DATABASE_URL` from the
  `security-feed-api-secrets` Secret.
- `postgres` — PostgreSQL primary store (Deployment + PVC + ClusterIP Service).
  Credentials live in `security-feed-api-secrets`.
- `security-feed-api-data` — PVC kept as the SQLite fallback when `DATABASE_URL`
  is unset.
- `security-feed-api-config` — ConfigMap for `LOG_LEVEL`, optional `CORS_ORIGINS`,
  and optional alerting env vars. Put real Discord/Slack/email webhook values
  in a Secret in production rather than the ConfigMap.
- PodDisruptionBudgets for the API, frontend, and PostgreSQL workloads.

The API and frontend run as non-root and drop all Linux capabilities.

**OpenSearch is optional and off by default.** To enable it, uncomment
`opensearch.yaml` in `deploy/k8s/kustomization.yaml` and `OPENSEARCH_URL` in
`deploy/k8s/configmap.yaml`. Without it, `/api/search` falls back to SQL
(Postgres `ILIKE`), so search works without any extra infrastructure.

## API

| Method | Path | Description |
|---|---|---|
| `GET` | `/api` | API descriptor (name, version, endpoints) |
| `GET` | `/api/feed` | Normalized feed JSON |
| `GET` | `/api/items` | Search/filter the persistent archive |
| `GET` | `/api/search?q=...` | Full-text search (OpenSearch or SQLite) |
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
  "patch_status": "fixed"
}
```

## Tagging and prioritization

- **Tags** are inferred from source scope plus title/summary keywords:
  `linux`, `cloud`, `kubernetes`, `cve`, `exploit`, `patch`, `threat`.
- **Severity** comes from CVSS when available, otherwise from textual heuristics.
- **Urgent** items are critical/high-severity and exploitation-related; they
  render the red dot in the UI.
- **KEV** items are in CISA's Known Exploited Vulnerabilities catalog.
- **EPSS** is fetched from FIRST when CVEs are present (best-effort).
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
cd sredevopsorg-sec-feed
PYTHONPATH=./.pip-packages python3 -m pytest -q
```

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
