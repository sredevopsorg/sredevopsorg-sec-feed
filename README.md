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

Iteration 3. The feed works end-to-end: live sources are fetched, normalized,
enriched (CISA KEV + EPSS), deduplicated, prioritized, persisted to SQLite,
pushed to the browser over SSE, rendered in a single-page frontend, and urgent
items trigger alerts via Slack/email/log channels.

## Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.13, FastAPI, httpx, feedparser |
| Frontend | Single-file HTML/CSS/JS (no build step, no CDN) |
| Storage | SQLite archive + in-memory cache with background refresh |
| Live updates | Server-Sent Events (`/api/events`) with polling fallback |
| Enrichment | CISA Known Exploited Vulnerabilities + FIRST EPSS |
| Alerting | Slack webhook / SMTP email / log for urgent items |
| Deployment | Docker/Podman compose + Kubernetes manifests |

Planned next: PostgreSQL/OpenSearch search backend, and OSV.dev +
distro patch-status enrichment.

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

### Notes on source handling

- The NVD keyword API returns oldest matches first, so the fetcher reads
  `totalResults` and requests the last page to obtain the newest CVEs.
- CISA and the Kubernetes blog are broad feeds, so items are filtered for
  Linux/cloud/Kubernetes relevance before entering the feed.
- If a source fails, the rest of the feed continues. If **all** live sources
  fail, the server serves realistic sample items so the UI is always usable.

## Project layout

```text
.
├── app/
│   ├── main.py        # FastAPI application and API routes
│   ├── sources.py     # Source definitions
│   ├── fetcher.py     # Fetching, normalization, caching
│   ├── enrich.py      # CISA KEV + EPSS enrichment
│   ├── store.py       # SQLite persistence
│   ├── events.py      # SSE pub/sub broker
│   └── alerts.py      # Slack / email / log alerting
├── static/
│   └── index.html     # Single-page frontend
├── tests/
│   ├── test_feed.py   # Unit tests for feed logic
│   └── test_store.py  # Unit tests for persistence
├── deploy/
│   └── k8s/           # Kubernetes manifests (Deployment, Service, PVC, ConfigMap)
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
> are served from SQLite and refresh every 10 minutes; the browser updates via
> SSE (`/api/events`) and falls back to polling every 5 minutes.

### Docker / Podman

```bash
docker compose up --build
# or, with rootless containers available:
podman-compose up --build
```

The SQLite database is stored in the `feed-data` volume.

### Kubernetes

```bash
kubectl apply -k deploy/k8s
```

The deployment uses a `ReadWriteOnce` PVC for the SQLite archive and exposes
the app as a `ClusterIP` service on port 80.

## API

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Single-page frontend |
| `GET` | `/api/feed` | Normalized feed JSON |
| `GET` | `/api/items` | Search/filter the persistent archive |
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
  "epss_score": 0.97
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
- The feed is sorted by `urgent` first, then `published` descending.
- Sample/fallback rows are only shown while no live rows are available.

## Tests

```bash
cd /home/ngeorger/feeder
PYTHONPATH=./.pip-packages python3 -m pytest -q
```

## Roadmap

- [x] Persistent store (SQLite) and search/filter endpoints
- [x] Enrichment: EPSS, CISA KEV
- [x] SSE live updates
- [x] Dockerize the stack
- [x] Slack / email / log alerts for `urgent` items
- [x] Kubernetes deployment manifests
- [ ] PostgreSQL/OpenSearch search backend
- [ ] OSV.dev and distro patch-status enrichment
