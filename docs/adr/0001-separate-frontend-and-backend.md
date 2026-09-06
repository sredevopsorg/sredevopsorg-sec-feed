# ADR-0001: Separate the frontend from the backend

- Status: Accepted (implemented)
- Date: 2025-09-05

## Context

The application ships as a single FastAPI process that serves both the JSON
API (`/api/*`, `/health`) and the single-page frontend (`/`, `/static`). The
frontend JavaScript hardcodes same-origin `/api/*` paths, so:

- the UI cannot be hosted, versioned, or scaled independently of the API;
- there is no CORS policy and no configurable API origin;
- every frontend-only change requires rebuilding/redeploying the backend.

The repository's own guidance requires the frontend to remain dependency-free
(a single static HTML/CSS/JS asset, no npm/bundler/CDN), which the author wants
to preserve while still achieving a clean frontend/backend separation.

## Decision

1. Extract the UI into a self-contained `frontend/` directory: separate
   `index.html`, `styles.css`, `app.js`, and a tiny `config.js` that exposes a
   configurable API base URL (`window.__API_BASE_URL__`, defaulting to the
   same origin).
2. Make every frontend request resolve against the configured base URL rather
   than a hardcoded absolute path.
3. Turn the backend into a pure API: remove `FileResponse`/`StaticFiles`/`/`
   and `/static`; keep `/api/*` and `/health`.
4. Add CORS middleware (configurable allowed origins) so the frontend can call
   the API cross-origin when it is served from a different host/CDN.
5. Deploy the two as separate containers: an nginx container serving
   `frontend/` and the FastAPI container serving the API. In the default
   Compose/Kubernetes topology, nginx reverse-proxies `/api` to the API so the
   browser keeps a single origin; a non-empty `API_BASE_URL` enables the
   fully-separated (CDN + API) topology.

## Consequences

- The frontend and backend can be built, versioned, and deployed independently.
- The frontend remains dependency-free; no build step or CDN is introduced.
- Same-origin deployments need no CORS; cross-origin deployments require
  configuring `CORS_ORIGINS`.
- The backend no longer carries UI assets, shrinking its image and its attack
  surface.

## Alternatives considered

- **Introduce a JS framework + bundler (e.g. Vite/React).** Rejected: violates
  the dependency-free requirement and adds complexity without a matching need.
- **Serve static assets from a CDN only.** Rejected as a default; nginx is the
  simplest self-contained option, and a CDN remains possible via
  `API_BASE_URL`.
