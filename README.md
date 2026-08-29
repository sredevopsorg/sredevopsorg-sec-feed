# Security Intelligence Live Feed — MVP

A minimal live-feed MVP that mirrors the attached dark "Live Intelligence Feed"
design, but focuses on **Linux**, **cloud**, **Kubernetes** and related
security content: advisories, CVEs, threats and patches.

## Stack

- **Backend:** Python 3.13, FastAPI, httpx, feedparser
- **Frontend:** Single-file HTML/CSS/JS SPA (no build step, no CDN)
- **Storage:** In-memory cache (PostgreSQL/OpenSearch planned post-MVP)

## Sources

| Source | Kind | Focus |
|---|---|---|
| Ubuntu Security Notices | RSS | Linux |
| Debian Security Advisories | RSS | Linux |
| Red Hat CVE Database | JSON API | Linux / cloud |
| Kubernetes Blog (security-filtered) | RSS | Kubernetes |
| AWS Security Bulletins | RSS | Cloud |
| CISA Cybersecurity Advisories (filtered) | RSS | Threats |
| NVD CVE 2.0 (`linux kernel`, `kubernetes`, `cloud`) | JSON API | CVE |

The NVD keyword API returns oldest-first, so the fetcher asks for `totalResults`
first and then requests the last page to get the most recent matching CVEs.

If a source fails, the feed keeps going. If **all** live sources fail, the
server falls back to realistic sample items so the UI remains demonstrable.

## Run

```bash
cd /home/ngeorger/feeder

# Install dependencies (pip is available; packages go into ./.pip-packages)
python3 -m pip install --target ./.pip-packages -r requirements.txt

# Run the server
PYTHONPATH=./.pip-packages python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Open <http://localhost:8000>.

## API

- `GET /` — the single-page frontend
- `GET /api/feed?tag=kubernetes&severity=critical&limit=50` — feed JSON
- `GET /api/sources` — configured sources
- `GET /health` — cache health

## Tests

```bash
PYTHONPATH=./.pip-packages pytest -q
```

## Next steps after MVP

- Add a real store (Postgres + OpenSearch) and search/facet endpoints
- Add enrichment: EPSS, CISA KEV, OSV.dev, distro patch status
- Add SSE/WebSocket live updates instead of 60s polling
- Add Slack / email alerts for `urgent` items
- Dockerise the stack and deploy on Kubernetes
