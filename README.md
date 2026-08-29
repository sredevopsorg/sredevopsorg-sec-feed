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

MVP. The feed works end-to-end: live sources are fetched, normalized,
deduplicated, prioritized, and served to a single-page frontend.

## Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.13, FastAPI, httpx, feedparser |
| Frontend | Single-file HTML/CSS/JS (no build step, no CDN) |
| Storage | In-memory cache with background refresh |

Planned post-MVP: PostgreSQL/OpenSearch, SSE live updates, enrichment
(EPSS, CISA KEV, OSV.dev), and alerting.

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
│   └── fetcher.py     # Fetching, normalization, enrichment, caching
├── static/
│   └── index.html     # Single-page frontend
├── tests/
│   └── test_feed.py   # Unit tests for feed logic
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

> The first feed refresh runs in the background on startup and can take a few
> seconds while all sources are fetched concurrently. Subsequent requests are
> served from cache and refresh every 10 minutes.

## API

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Single-page frontend |
| `GET` | `/api/feed` | Normalized feed JSON |
| `GET` | `/api/sources` | Configured sources |
| `GET` | `/health` | Cache health |

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
  "urgent": true
}
```

## Tagging and prioritization

- **Tags** are inferred from source scope plus title/summary keywords:
  `linux`, `cloud`, `kubernetes`, `cve`, `exploit`, `patch`, `threat`.
- **Severity** comes from CVSS when available, otherwise from textual heuristics.
- **Urgent** items are critical/high-severity and exploitation-related; they
  render the red dot in the UI.
- The feed is sorted by `urgent` first, then `published` descending.

## Tests

```bash
cd /home/ngeorger/feeder
PYTHONPATH=./.pip-packages python3 -m pytest -q
```

## Roadmap

- [ ] Persistent store (Postgres + OpenSearch) and search/facet endpoints
- [ ] Enrichment: EPSS, CISA KEV, OSV.dev, distro patch status
- [ ] SSE/WebSocket live updates instead of 60s polling
- [ ] Slack / email alerts for `urgent` items
- [ ] Dockerize and deploy on Kubernetes
