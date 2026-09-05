# Architecture Review — Security Intelligence Live Feed

Status: Accepted (living document)
Date: 2025-09-05

This document records the current-state analysis and the target architecture
for the `sredevopsorg-sec-feed` repository. It is intentionally short: each
material decision links to an Architecture Decision Record under
[`docs/adr/`](./adr/).

## 1. Current state (C4 — Context and Container)

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

One deployable serves both the JSON API and the single-page frontend. Storage
is a runtime switch between two parallel implementations (`store.py` for
SQLite, `postgres_store.py` for PostgreSQL) selected by the presence of
`DATABASE_URL`. The fetch → normalize → enrich → persist → index → publish →
alert pipeline is a single coroutine, `refresh_feed()`, living in a 778-line
`app/fetcher.py`.

## 2. Observations (ranked by impact on simplicity and separation)

1. **Frontend and backend are the same deployable.** `app/main.py` mounts
   `static/` and serves `index.html`; the JavaScript hardcodes same-origin
   `/api/*` paths. There is no CORS and no configurable API origin, so the UI
   cannot be hosted, versioned, or scaled independently of the API.

2. **Configuration is captured at import time.** `DATABASE_URL`,
   `OPENSEARCH_URL`, webhook URLs, and SMTP settings are read with
   `os.environ.get(...)` at module scope. This freezes settings at process
   start, makes injection/testing awkward, and scatters configuration across
   many modules.

3. **Storage backend duplication.** `store.py` and `postgres_store.py`
   duplicate the entire schema and every query, with an `if _use_postgres()`
   branch in each public function. There is no single interface (port) that
   the two adapters implement, so the two implementations can drift.

4. **Tangled dependency direction / god module.** `app/fetcher.py` performs
   fetching, parsing, normalization, enrichment, persistence, indexing,
   event publishing, and alerting, and it lazily imports `store`, `events`,
   `search`, `alerts`, `enrich`, and `osv` to dodge circular imports. The
   domain model (`FeedItem`) lives inside the I/O module, and `store.py`
   imports it back from `fetcher.py` — a circular dependency at the model
   layer.

5. **Global mutable state.** `CACHE`, `broker`, `_kev_cache`, and
   `_last_sync_at` are module-level globals, making behaviour harder to test
   and reason about.

6. **Duplicated domain rule.** The "hide sample rows once live rows exist"
   rule is re-implemented in `query_feed`, `search_feed`, and
   `unalerted_urgent_items`, in both storage backends.

7. **No API contract schemas.** Routes return hand-built dictionaries; the
   feed-item shape is documented only in prose. Test coverage is helper-level
   only — there are no route/API integration tests and no SSE test.

## 3. Target architecture (C4 — Container)

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
- **`postgres` / `opensearch`** — unchanged optional backing services.

Component-level target (backend):

- A `Settings` object centralises environment-driven configuration.
- A `Storage` port (interface) with SQLite and PostgreSQL adapters replaces the
  duplicated facades and removes per-call branching.
- A `models` (domain) module owns `FeedItem` and serialization, breaking the
  `fetcher ↔ store` cycle.
- The refresh pipeline is a small orchestrator with one-way dependencies
  (`fetch → enrich → persist → index → publish → alert`) rather than one god
  coroutine.

## 4. Decision log

| ADR | Decision |
|---|---|
| [0001](./adr/0001-separate-frontend-and-backend.md) | Split frontend and backend into separate deployables; dependency-free frontend; configurable API origin + CORS. |
| [0002](./adr/0002-centralize-configuration.md) | Centralise configuration in a `Settings` object. |
| [0003](./adr/0003-storage-port-and-adapters.md) | Define a single `Storage` port with SQLite + PostgreSQL adapters. |
| [0004](./adr/0004-domain-models-and-refresh-pipeline.md) | Extract a domain `models` module and decompose the refresh pipeline. |

## 5. Delivery plan

Each improvement is delivered as its own pull request so it can be reviewed and
merged independently:

1. **PR `docs/architecture-review`** — this review and the ADRs (docs only).
2. **PR `refactor/frontend-extraction`** — extract the UI into a self-contained
   `frontend/` directory with a configurable API base URL (still served by the
   backend to keep the app runnable in the interim).
3. **PR `refactor/backend-pure-api`** — turn the backend into a pure API
   (CORS + `Settings`), split the deployment into `web` (nginx) and `api`
   containers, and update Compose/Kubernetes/CI.
4. **PR `refactor/storage-port`** — introduce the `Storage` port, extract the
   domain model, and remove the SQLite/PostgreSQL duplication.
