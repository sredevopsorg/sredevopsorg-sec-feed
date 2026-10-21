# ADR-0008: Retire the OpenSSF Malicious Packages source

- Status: Accepted (implemented 2026-10-21)
- Relates to: ADR-0003 (storage port and adapters), ADR-0007 (versioned migrations)

## Context

`app/ossf.py` read recent OSV reports from the GitHub-hosted
`ossf/malicious-packages` repository without cloning it. It was the only source
that stored a **commit cursor** (`source_cursors`, one row per source, holding
the last processed commit SHA) and the only reason
`Storage.get_source_cursor()` / `set_source_cursor()` existed.

The source carried a meaningful operational cost for its signal:

- It cost several GitHub API requests per refresh (one commit-list page plus
  one commit detail and one raw-file fetch per report), competing for the same
  unauthenticated 60-requests/hour GitHub budget as the five curated GHSA
  sources. `GITHUB_TOKEN` raised the ceiling but did not remove the budget.
- Its reports were largely package-ecosystem entries filtered down to
  Go/git or Linux/cloud/Kubernetes keywords. The feed already covers the same
  operational risk through OSV enrichment (affected/fixed versions for CVEs)
  and the CISA KEV source (confirmed exploitation).
- It was the only user of a second, parallel state table. Fetch cadence,
  conditional-GET validators and the last normalized payload — the concerns
  that actually keep refreshes cheap — live in `source_state` (ADR-0007),
  not in a SHA cursor.

## Decision

1. Remove the `ossf-malicious` source: entry in `app/sources.py`, fetch branch
   in `app/fetcher.py`, module `app/ossf.py`, and its tests.
2. Remove the now-unused cursor API from the storage port and both adapters
   (`store.py`, `sqlite_store.py`, `postgres_store.py`).
3. Drop `source_cursors` in `migrations/0003_drop_source_cursors.sql` and delete
   the stale `ossf-malicious` row from `source_state`. Fresh databases still
   replay `0001` (which creates the table) and then `0003`; existing databases
   converge without a manual step.
4. Keep historical `feed_items` rows ingested from the source. They are real
   advisories; `RETENTION_DAYS` prunes them on the normal schedule. The
   frontend keeps its `malware` / `supply-chain` chip styles so those rows do
   not render unstyled.
5. Keep `GITHUB_TOKEN`: the curated GHSA sources are the remaining GitHub API
   consumer.

## Consequences

- One fewer upstream dependency and GitHub-API budget line; one fewer state
  table and two fewer storage-port functions to maintain in both adapters.
- Reintroducing the source (or any commit-cursor source) needs a new state
  mechanism plus a new migration — the old cursor table is gone by design.
- Search can still return historical malicious-package items until retention
  removes them; that is intentional and not a data-loss bug.
- Deploying the code before `0003` makes `postgres_store.init_db()` fail fast
  with the migration command, which is the intended safety behaviour. Applying
  `0003` before the code is harmless because no remaining source reads the
  cursor.
