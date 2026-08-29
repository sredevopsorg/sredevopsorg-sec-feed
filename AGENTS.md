# AGENTS.md

Guidelines for AI coding agents (and human contributors) working in this
repository.

## Project in one sentence

A FastAPI-backed single-page feed that aggregates, normalizes, enriches,
persists, and displays security advisories, CVEs, and threats for Linux,
cloud, and Kubernetes.

## Commands

Run these from the repository root.

```bash
# Install dependencies (vendored into ./.pip-packages)
python3 -m pip install --target ./.pip-packages -r requirements.txt

# Run the server
PYTHONPATH=./.pip-packages python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000

# Run tests
PYTHONPATH=./.pip-packages python3 -m pytest -q

# Run with Docker/Podman
docker compose up --build
# or
podman-compose up --build

# Deploy to Kubernetes
kubectl apply -k deploy/k8s
```

There is no linter or formatter configured yet. Keep code PEP 8-ish and
readable.

## Repository layout

```text
app/main.py        FastAPI routes and app startup
app/sources.py     Source definitions (add new feeds here)
app/fetcher.py     Fetching, parsing, normalization, caching
app/enrich.py      CISA KEV + FIRST EPSS enrichment (best-effort)
app/store.py       SQLite persistence and queries
app/events.py      SSE pub/sub broker
app/alerts.py      Slack / email / log alerts for urgent items
static/index.html  Single-page frontend (HTML + CSS + vanilla JS)
tests/             Unit tests for feed and store logic
```

## Critical invariants

1. **The frontend must stay dependency-free.** It is a single `static/index.html`
   file with inline CSS/JS. Do not introduce npm, bundlers, or CDN scripts.
2. **The feed must never render empty.** `fetcher.py` provides sample fallback
   data when all live sources fail. Preserve that behavior.
3. **Never block the API on a slow source.** `get_feed()` returns the cached
   feed immediately and refreshes in the background.
4. **Sample rows must stay hidden once live rows exist.** `store.query_feed()`
   excludes `is_sample=1` when `is_sample=0` rows are present.
4. **Respect source rate limits and terms.** All HTTP calls must keep the
   current `USER_AGENT` and `HTTP_TIMEOUT`.
5. **Keep tests passing.** Every change to parsing/enrichment should add or
   update a test in `tests/test_feed.py`.

## Adding a source

1. Add a `Source` entry to `app/sources.py`.
2. If it is RSS/Atom, no new fetcher code is needed. If it is a new API shape,
   add a `_fetch_<kind>` function in `app/fetcher.py` and a branch in
   `_fetch_source()`.
3. Add relevance filtering if the feed is broader than Linux/cloud/Kubernetes
   (see `_is_relevant()`).
4. Add a unit test for the normalization/filtering logic with fixture data.
5. Update the Sources table in `README.md`.
6. Enrichment (KEV/EPSS) is optional and best-effort; new enrichment goes in
   `app/enrich.py` and must never fail the whole refresh.
7. Alerting is opt-in. Without `SLACK_WEBHOOK_URL` or SMTP settings, urgent
   items are logged only. Alert delivery must never break the refresh loop.

## Feed item contract

Every item must be normalized to the `FeedItem` dataclass in
`app/fetcher.py`:

- `id` — stable hash of URL + title
- `title`, `summary`, `url`, `source`, `source_url`
- `published` — timezone-aware UTC datetime or `None`
- `tags` — subset of `linux`, `cloud`, `kubernetes`, `cve`, `exploit`,
  `patch`, `threat`
- `cves` — list of uppercase CVE IDs, e.g. `["CVE-2024-21626"]`
- `severity` — `critical` | `high` | `medium` | `low` | `unknown`
- `urgent` — boolean, drives the red dot in the UI
- `kev` — true when a CVE is in CISA's Known Exploited Vulnerabilities catalog
- `epss_score` — FIRST EPSS score when available
- `is_sample` — true for fallback/sample rows

The API returns these via `item_to_dict()`, which also computes `time_ago`.

## When changing the UI

- Mirror the existing dark "Live Intelligence Feed" aesthetic: dark panels,
  orange accent, uppercase header, left time column, tag chips, red urgent dot,
  `VIEW FULL LIVE FEED →` footer.
- Keep it responsive (the current layout collapses on narrow screens).
- Prefer server-provided `time_ago`; do not duplicate relative-time logic in
  JS unless there is a clear reason.

## Common pitfalls

- **Timezone-naive datetimes** break sorting. Always use
  `_ensure_aware()` before comparing `published`.
- **HTML summaries** must be stripped/truncated with `_strip_html()` and
  `_truncate()` before rendering.
- **NVD keyword queries** return oldest-first. Use the `totalResults` +
  `startIndex` approach already implemented in `_fetch_nvd()`.
- **CISA feed noise.** CISA publishes ICS/OT advisories too; keep the
  topic filter in `_is_relevant()` when touching that source.

## Definition of done

- [ ] Tests pass
- [ ] Server starts and `/health` returns `{"status":"ok"}`
- [ ] `/api/feed` returns valid items (or sample fallback)
- [ ] README/source table updated if sources changed
