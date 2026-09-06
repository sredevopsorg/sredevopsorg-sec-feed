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
# Development (hot reload via the auto-applied dev override)
docker compose up --build

# Run tests (host, or inside the dev container)
pip install -r requirements-dev.txt
pytest -q

# Production (pinned, non-root images; dev override is not loaded with -f)
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# Deploy to Kubernetes
kubectl apply -k deploy/k8s
```

There is no linter or formatter configured yet. Keep code PEP 8-ish and
readable.

## Repository layout

```text
app/config.py      Centralized Settings (environment-driven; ADR-0002)
app/models.py      Domain model (FeedItem) + serialization (ADR-0004)
app/main.py        FastAPI API routes and app startup (pure JSON API)
app/sources.py     Source definitions (add new feeds here)
app/fetcher.py     Fetching + normalization of upstream sources
app/pipeline.py    Refresh orchestration: fetch → enrich → persist → index → publish → alert
app/enrich.py      CISA KEV + FIRST EPSS enrichment (best-effort)
app/osv.py         OSV.dev enrichment (affected/fixed/severity, best-effort)
app/search.py      Search backend (OpenSearch if configured, SQL fallback)
app/ossf.py         OpenSSF Malicious Packages source (GitHub API + cursor)
app/store.py       Storage facade/port (selects sqlite or postgres backend)
app/sqlite_store.py    SQLite storage adapter
app/postgres_store.py  PostgreSQL storage adapter
app/events.py      SSE pub/sub broker
app/alerts.py      Discord / Slack / email / log alerts for urgent items
frontend/          Single-page frontend (HTML + CSS + vanilla JS, no build step)
tests/             Unit tests for feed, store, search, config, API, and pipeline
docs/              Architecture review (docs/architecture.md) + ADRs (docs/adr/)
deploy/k8s/        Kubernetes manifests (api, frontend, postgres, PDB, optional OpenSearch/Ingress)
.devcontainer/     Dev Container (VS Code / Codespaces)
docker-compose.override.yml  Dev overrides (hot reload, source mounts)
docker-compose.prod.yml      Production overrides (pinned images)
requirements-dev.txt         Test/dev dependencies
```

## Critical invariants

1. **The frontend must stay dependency-free.** It is a static app in
   `frontend/` (`index.html`, `styles.css`, `app.js`, `config.js`) with no
   build step. Do not introduce npm, bundlers, or CDN scripts. Resolve API
   calls through the configured base URL rather than hardcoding `/api/...`.
2. **The feed must never render empty.** `fetcher.py` provides sample fallback
   data when all live sources fail. Preserve that behavior.
3. **Never block the API on a slow source.** `pipeline.get_feed()` returns the
   cached feed immediately and refreshes in the background.
4. **Sample rows must stay hidden once live rows exist.** `store.query_feed()`
   excludes `is_sample=1` when `is_sample=0` rows are present.
5. **Respect source rate limits and terms.** All HTTP calls must keep the
   current `USER_AGENT` and `HTTP_TIMEOUT`.
6. **Keep tests passing.** Every change to parsing/enrichment should add or
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
    user (UID 10001) and the frontend uses `nginxinc/nginx-unprivileged`
    (listens on 8080). Do not add `USER root` to production images; dev
    containers may run as root.

## Feed item contract

Every item must be normalized to the `FeedItem` dataclass in
`app/models.py` (re-exported by `app/fetcher.py`):

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
- `patch_status` — `fixed` | `affected` | `not-affected` | `deferred` | `unknown`
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
