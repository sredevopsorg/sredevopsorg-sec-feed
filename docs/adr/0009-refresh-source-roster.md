# ADR-0009: Refresh the source roster — retire ZDI and Helm advisories, stagger NVD, add Envoy/Moby/CRI-O GHSA

- Status: Accepted (implemented 2026-10-21)
- Relates to: ADR-0008 (retiring a source), ADR-0002 (configuration), ADR-0007 (versioned migrations)

## Context

A 2026-10-21 probe of every configured source (one plain HTTP GET plus the
real `_fetch_source()` path per source) found all 19 sources reachable and
producing normalized items. Two findings drove this decision:

- **ZDI (Zero Day Initiative) is off-scope by content.** Both feeds answered
  200 with fresh entries, but the published feed carries desktop/vendor
  advisories (FreeBSD kernel, LibreOffice, Adobe Photoshop, X.Org, Sparx EA)
  and the upcoming feed is bare vendor names with no CVE IDs, severity, or
  advisory links. Neither maps to the Linux/cloud/Kubernetes scope the
  relevance filter enforces everywhere else; ZDI is also the only source ever
  ingested *without* that filter. Confirmed-exploitation signal is already
  covered better by CISA KEV (catalog entries carry CVE IDs and are urgent by
  definition) and GHSA covers the upstream advisory layer.
- **NVD is intermittently unreliable, not broken.** A single sequential probe
  of the three keyword queries hit a `ReadTimeout`; NVD rate-limits
  unauthenticated clients to 5 requests per rolling 30 s and the three keyword
  sources fire concurrently on every refresh (each with one transport-level
  retry). Removing them would gut CVSS/severity coverage for plain CVEs, so
  the fix is to spread the requests instead.

While reshaping the roster, the GHSA curated list was rebalanced: `helm`
has returned exactly one advisory since 2021 (zero recent yield), while three
uncovered packages at the same layer — `envoyproxy/envoy`, `moby/moby`
(Docker Engine), `cri-o/cri-o` — each have live advisory feeds verified the
same day.

## Decision

1. **Retire** the `zeroday`, `zeroday-upcoming` and `ghsa-helm` sources:
   entries in `app/sources.py` and their `_MIN_INTERVALS` cadence rows.
2. **Add** three curated GHSA sources — Envoy, Moby, CRI-O — reusing the
   existing `ghsa` fetch kind, tags and 5-item cap. The curated list stays at
   7 packages; each costs one GitHub API request per hourly fetch
   (`min_interval_seconds=3600`), ≈7 requests/hour against the
   unauthenticated 60/hour budget, so `GITHUB_TOKEN` stays optional headroom.
3. **Stagger NVD**: every NVD request reserves a start slot at least
   `NVD_STAGGER_SECONDS` (2 s) after the previous one, via a loop-scoped
   `asyncio.Lock` plus a monotonic next-slot timestamp. Reservation is
   atomic; the sleep happens outside the lock so callers overlap their
   waits. With three keyword sources the requests spread over ~4 s, inside
   the rate-limit window even when a transport retry re-enters the queue.
   The stagger runs inside the background refresh only — no request path
   ever awaits it (invariant 3).
4. **Clean stale fetch state** with `migrations/0004_remove_stale_zdi_helm_source_state.sql`:
   delete the three sources' rows from `source_state`. SQLite deployments
   have no migration runner; stale rows there are harmless because no active
   source id reads them.
5. **Keep historical `feed_items` rows** ingested from the retired sources
   (real advisories; `RETENTION_DAYS` prunes them on the normal schedule).
   No `zeroday` chip style is needed in the frontend — unknown tags already
   fall back to the generic `.chip` class. The `zeroday` tag is no longer
   added to new items.

## Consequences

- The feed carries one fewer out-of-scope vendor stream and two fewer
  exploit-tagged noise streams; zero-day *in-the-wild* signal is unchanged
  because KEV already flags confirmed exploitation with CVE IDs.
- NVD fetches take up to ~4 s longer end-to-end per refresh but stop tripping
  the unauthenticated rate limit; the added latency is invisible to API
  consumers (invariant 3).
- The GHSA curated list covers the container/agent layer more completely
  (containerd, runc, CRI-O, Moby, Envoy, Istio, Argo CD) at the same request
  budget as before.
- Reintroducing ZDI, or any per-30-seconds-limited API, needs an explicit
  cadence/stagger design of its own; the NVD stagger is deliberately private
  to the NVD fetcher, not a generic per-host throttle.
- Deploying the code before `0004` is harmless (stale rows are only written
  by the retired fetchers); applying `0004` before the code is equally safe.

## Alternatives considered

- **Replace ZDI with a like-for-like zero-day feed.** No freely accessible,
  CVE-annotated zero-day feed matched the scope; vendor blogs (AWS Security
  Blog, Microsoft Security Blog, Kubernetes blog) were probed and rejected as
  noisy general-purpose streams.
- **Drop the NVD keyword sources.** Rejected: they are the only source of
  CVSS-derived severity for CVEs that no distro/vendor feed mentions.
- **Fix Helm instead of removing it.** Nothing to fix — the GitHub Advisory
  Database simply has one Helm advisory in the list endpoint's window.
