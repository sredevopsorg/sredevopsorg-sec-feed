# Architecture Review — Security Intelligence Live Feed

Status: Implemented + audited (living document)
Date: 2025-09-05 (audit follow-ups added 2025-09)

This document records the original-state analysis, the target architecture, and
the delivery of the refactor for the `sredevopsorg-sec-feed` repository. It is
intentionally short: each material decision links to an Architecture Decision
Record under [`docs/adr/`](./adr/).

The refactor is **complete** — see the [delivery record](#5-delivery-record).

## 1. Original state (pre-refactor, C4 — Context and Container)

```text
┌──────────┐   HTTP (same origin)    ┌─────────────────────────────────────┐
│ Browser  │ ───────────────────────▶│  FastAPI process  (single container)│
└──────────┘                         │  ┌───────────────┐  ┌─────────────┐ │
                                     │  │  API  /api/*  │  │  UI  /,/static│ │
                                     │  └──────┬────────┘  └─────────────┘ │
                                     │         │ fetcher → store/search/… │
                                     └─────────┼───────────────────────────┘
                              ┌───────────────┼───────────────┐
                              ▼               ▼               ▼
                     Upstream RSS/JSON   PostgreSQL / SQLite  OpenSearch (opt)
                     (NVD, CISA, …)     (runtime-selected)   Discord/Slack/SMTP
```

One deployable served both the JSON API and the single-page frontend. Storage
was a runtime switch between two parallel implementations (`store.py` for
SQLite, `postgres_store.py` for PostgreSQL) selected by the presence of
`DATABASE_URL`. The fetch → normalize → enrich → persist → index → publish →
alert pipeline was a single coroutine, `refresh_feed()`, living in a 778-line
`app/fetcher.py`.

## 2. Observations and resolution

| # | Observation | Resolution |
|---|---|---|
| 1 | Frontend and backend are the same deployable; hardcoded same-origin `/api/*`; no CORS/configurable origin. | ✅ Resolved — ADR-0001 |
| 2 | Configuration captured at import time via scattered `os.environ.get`. | ✅ Resolved — ADR-0002 |
| 3 | Storage backend duplication with per-function `if _use_postgres()` branching. | ✅ Resolved — ADR-0003 |
| 4 | Tangled dependency direction / god module (`fetcher.py`); domain model inside the I/O module. | ✅ Resolved — ADR-0004 |
| 5 | Global mutable state (`CACHE`, `broker`, `_kev_cache`, `_last_sync_at`). | ⏸ Partially resolved — `CACHE` relocated to `pipeline.py`; the remaining module globals are acceptable for a single-process app. |
| 6 | Duplicated domain rule ("hide sample rows once live rows exist") across both backends. | ⏸ Deferred — the two adapters still each implement it. |
| 7 | No API contract schemas (raw dicts); no route/SSE integration tests. | ⏸ Deferred — surface tests were added (`test_api.py`, `test_pipeline.py`); typed response models remain future work. |
| 8 | A cold `/api/feed` awaited a full refresh (and started a second one); the refresh task was unmanaged and could be garbage-collected. | ✅ Resolved — single-flight `pipeline.schedule_refresh()`; `get_feed()` returns the cache immediately (PR #18). |
| 9 | Enrichment reported an unknown EPSS score as `0.0`, and OSSF carried lowercase CVE ids that defeated KEV/OSV lookups. | ✅ Resolved — unknown stays `None` (PR #15) and one canonical uppercase extractor is used everywhere (PR #16). |
| 10 | Non-UTC offsets broke the SQLite adapter's text ordering of `published`. | ✅ Resolved — `_ensure_aware()` converts aware values to UTC (PR #17). |
| 11 | Only the fetcher identified itself to upstreams; `ossf` sent a different agent version, and the other modules sent none. | ✅ Resolved — `app/http_client.py` owns the user agent and timeouts; a test forbids other clients (PR #23). |
| 12 | The frontend image ran root nginx on port 80 while the invariant and docs claimed non-root on 8080; the README described PostgreSQL and PDBs as part of the default Kubernetes deployment. | ✅ Resolved — unprivileged nginx as UID 101 on 8080, and the manifests/docs now separate default from opt-in components (PR #25 and this PR). |

## 3. Current architecture (implemented, C4 — Container)

```text
┌──────────┐   HTTP(S)   ┌────────────────────┐      ┌──────────────────────────┐
│ Browser  │ ───────────▶│  web (nginx)       │ ───▶ │  api (FastAPI)  /api/*   │
└──────────┘             │  serves frontend/  │      │  /health                 │
                         │  static assets     │      └────────┬─────────────────┘
                         └────────────────────┘               │
                                          (configurable API_BASE_URL + CORS)
                                                              ▼
                                   PostgreSQL / SQLite · OpenSearch (opt) · webhooks
```

- **`web`** — a static frontend (plain HTML/CSS/JS, no build step, no CDN
  dependency) served by nginx. It consumes the API over HTTP using a
  configurable base URL and supports same-origin (reverse-proxied) or
  cross-origin (CORS) operation.
- **`api`** — FastAPI serving only `/api/*` and `/health`. No UI assets.
- **`postgres` / `opensearch`** — optional backing services.

Component-level (backend), all implemented:

- `app/config.py` — a single `Settings` object centralizes environment-driven
  configuration (ADR-0002).
- `app/models.py` — the `FeedItem` domain model and serialization, breaking the
  `fetcher ↔ store` cycle (ADR-0004).
- `app/store.py` — a `Storage` port/facade that selects one backend
  (`sqlite_store.py` or `postgres_store.py`) once (ADR-0003).
- `app/pipeline.py` — the refresh orchestrator with one-way dependencies:
  `fetch → enrich → persist → index → publish → alert` (ADR-0004). `fetcher.py`
  now only fetches and normalizes (`fetch_all()`).

## 4. Decision log

| ADR | Decision | Status |
|---|---|---|
| [0001](./adr/0001-separate-frontend-and-backend.md) | Split frontend and backend into separate deployables; dependency-free frontend; configurable API origin + CORS. | Implemented |
| [0002](./adr/0002-centralize-configuration.md) | Centralize configuration in a `Settings` object. | Implemented |
| [0003](./adr/0003-storage-port-and-adapters.md) | Define a single `Storage` port with SQLite + PostgreSQL adapters. | Implemented |
| [0004](./adr/0004-domain-models-and-refresh-pipeline.md) | Extract a domain `models` module and decompose the refresh pipeline. | Implemented |

## 5. Delivery record

Each improvement was delivered as its own pull request, reviewed, and merged:

1. **`docs/architecture-review`** — this review and the ADRs (docs only).
2. **`refactor/frontend-extraction`** — extract the UI into `frontend/` with a
   configurable API base URL.
3. **`refactor/backend-pure-api`** — pure API (CORS + `Settings`), split into
   `web` (nginx) and `api` containers; Compose/Kubernetes/CI updated.
4. **`refactor/storage-port`** — `Storage` port + adapters, extract the domain
   model, remove per-call backend branching.
5. **`refactor/config-centralization`** — route the remaining env reads
   (search/alerts/ossf) through `Settings`.
6. **`refactor/refresh-pipeline`** — decompose `refresh_feed()` into the
   explicit `fetch → enrich → persist → index → publish → alert` pipeline.

All branches were consolidated onto `main`.

### Follow-up audit (2025-09)

A second pass over the backend, frontend, deployment layer and docs produced
one PR per finding, each with its own tests and verification notes:

7. **`fix/enrich-epss-unknown-not-zero`** — an unknown EPSS score stays `null`
   instead of `0.0` (#15).
8. **`fix/ossf-cve-uppercase`** — one canonical CVE extractor, so OSSF items
   enrich like every other source (#16).
9. **`fix/utc-timestamps`** — every serialized timestamp normalized to UTC
   (#17).
10. **`fix/pipeline-nonblocking-refresh`** — single-flight refresh, no request
    ever waits for it (#18).
11. **`fix/contract-is-sample`** — `is_sample` exposed in the item contract
    (#19).
12. **`fix/search-sample-index-consistency`** — sample documents purged from
    the OpenSearch index once live rows exist (#20).
13. **`fix/frontend-footer-state-chips`** — the footer archive toggle, honest
    LIVE/OFFLINE and sample-data state, legible chips, http(s)-only links (#21).
14. **`fix/nginx-headers-cache`** — security headers no longer dropped, and
    `config.js` is never cached (#22).
15. **`refactor/outbound-http-policy`** — one module owns the outbound user
    agent and timeouts (#23).
16. **`chore/dead-code-cleanup`** — dead code, redundant guards and unused
    imports removed; both storage adapters migrate the same columns (#24).
17. **`fix/frontend-image-nonroot-8080`** — the frontend image is genuinely
    non-root on 8080, and Compose/Kubernetes follow (#25).
18. **`docs/sync-readme-agents-architecture`** — README, AGENTS.md and this
    document resynced with the code (this PR).

## 6. Remaining follow-ups (deferred, not blocking)

- Type the API responses with Pydantic models (observation #7).
- Share the "hide sample rows" rule and row-mapping across the two storage
  adapters, or move to an ORM (observation #6).
- Consider dependency injection for the remaining module-level globals
  (`CACHE`, `broker`, `_kev_cache`, `_osv_cache`, `_last_sync_at`) if the app
  ever grows beyond a single process (observation #5).
- Add a linter/formatter (e.g. ruff) to CI; the repository still documents
  "none configured", so style is enforced by review only.
