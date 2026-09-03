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

## Status

Iteration 6. The feed works end-to-end: live sources are fetched, normalized
(including distro patch status), enriched (CISA KEV + EPSS + OSV.dev),
deduplicated, prioritized, persisted to PostgreSQL (or SQLite locally),
searchable (`/api/search`), pushed to the browser over SSE, rendered in a
single-page frontend, and urgent items trigger alerts via
Discord/Slack/email/log channels.

## Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.13, FastAPI, httpx, feedparser |
| Frontend | Single-file HTML/CSS/JS (no build step, no CDN) |
| Storage | PostgreSQL primary store, SQLite fallback, in-memory cache |
| Live updates | Server-Sent Events (`/api/events`) with polling fallback |
| Enrichment | CISA Known Exploited Vulnerabilities + FIRST EPSS + OSV.dev |
| Malware | OpenSSF Malicious Packages (recent OSV reports) |
| Search | `/api/search` with SQLite fallback or optional OpenSearch |
| Alerting | Discord webhook (primary) / Slack webhook / SMTP email / log for urgent items |
| Deployment | Docker/Podman compose + Kubernetes manifests |

All roadmap items are complete for this release candidate (0.2.0-rc.1).

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
│   ├── main.py           # FastAPI application and API routes
│   ├── sources.py        # Source definitions
│   ├── fetcher.py        # Fetching, normalization, caching
│   ├── enrich.py         # CISA KEV + EPSS enrichment
│   ├── osv.py            # OSV.dev enrichment (affected/fixed/severity)
│   ├── search.py         # Search backend (OpenSearch + SQLite fallback)
│   ├── ossf.py           # OpenSSF Malicious Packages GitHub-API source
│   ├── store.py          # Storage facade (Postgres or SQLite)
│   ├── postgres_store.py # PostgreSQL storage implementation
│   ├── events.py         # SSE pub/sub broker
│   └── alerts.py         # Discord / Slack / email / log alerting
├── static/
│   └── index.html        # Single-page frontend
├── tests/
│   ├── test_feed.py      # Unit tests for feed logic
│   ├── test_osv.py       # Unit tests for OSV enrichment
│   ├── test_ossf.py      # Unit tests for OpenSSF source
│   ├── test_alerts.py    # Unit tests for alert formatting
│   └── test_store.py     # Unit tests for persistence
├── deploy/
│   └── k8s/              # Kubernetes manifests (Deployment, Service, PVC, ConfigMap)
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── README.md
└── AGENTS.md
```

## Quickstart

```bash
cd /home/ngeorger/feeder

# Install dependencies into ./.pip-packages
python3 -m pip install --target ./.pip-packages -r requirements.txt

# Run the server
PYTHONPATH=./.pip-packages python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Open <http://localhost:8000>.

> The first feed refresh runs in the background on startup. Subsequent requests
> are served from the configured store and refresh every 10 minutes; the
> browser updates via SSE (`/api/events`) and falls back to polling every 5
> minutes.

### Local PostgreSQL

```bash
# Without Docker, point the app at any PostgreSQL database:
export DATABASE_URL=postgresql://feed:feed@localhost:5432/feed
PYTHONPATH=./.pip-packages python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

When `DATABASE_URL` is unset, the app uses SQLite in `./data/feed.db`.

### Docker / Podman

```bash
docker compose up --build
# or, with rootless containers available:
podman-compose up --build
```

The SQLite database is stored in the `feed-data` volume.

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

`docker compose up --build` starts the app plus PostgreSQL. The feed service
uses `DATABASE_URL=postgresql://feed:feed@postgres:5432/feed`.

To add OpenSearch search, run:

```bash
docker compose --profile search up --build
```

Then uncomment `OPENSEARCH_URL=http://opensearch:9200` in the `feed` service
environment. Without OpenSearch, `/api/search` falls back to SQL (Postgres
`ILIKE` or SQLite `LIKE`).

When OpenSearch is enabled, the app creates the index with an explicit mapping
on startup and keeps it in sync with the archive automatically (incremental
indexing per refresh plus a throttled full reconcile) — all best-effort, so an
unavailable OpenSearch never breaks the feed.

### Kubernetes

```bash
kubectl apply -k deploy/k8s
```

The manifests deploy the feed app plus its PostgreSQL dependency:

- **PostgreSQL** primary store (Deployment + `ReadWriteOnce` PVC + `postgres`
  ClusterIP service). Credentials and the `DATABASE_URL` connection string
  live in the `security-feed-web-secrets` Secret.
- The feed app itself (ClusterIP service on port 80), with a `ReadWriteOnce`
  PVC retained as the SQLite fallback when `DATABASE_URL` is unset.

**OpenSearch is optional and off by default.** `opensearch.yaml` is included
in the tree but not applied unless you uncomment it in `kustomization.yaml`
and uncomment `OPENSEARCH_URL` in `configmap.yaml`. Without it, `/api/search`
falls back to SQL (Postgres `ILIKE`), so search works without any extra
infrastructure.

## API

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Single-page frontend |
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
cd /home/ngeorger/feeder
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
