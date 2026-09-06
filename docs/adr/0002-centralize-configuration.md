# ADR-0002: Centralize configuration in a Settings object

- Status: Accepted (implemented)
- Date: 2025-09-05

## Context

Configuration is currently read at import time via `os.environ.get(...)`
scattered across `store.py`, `postgres_store.py`, `search.py`, `alerts.py`,
`ossf.py`, and `fetcher.py`. This:

- freezes values at process start;
- makes tests awkward (values are captured before test fixtures run);
- scatters knowledge of environment variable names across the codebase;
- has an inconsistent default (`postgres_store.py` silently defaults
  `DATABASE_URL` to a localhost URL while `store.py` treats an unset variable
  as SQLite).

## Decision

Introduce a single `app/config.py` with a `Settings` class that reads the
environment once, documents every variable, and applies defaults in one place.
Modules consume `Settings` (injected where practical) instead of calling
`os.environ.get` directly.

## Consequences

- One place to see every configuration knob and its default.
- Easier to inject configuration in tests and to validate at startup.
- Removes the misleading localhost default for `DATABASE_URL`.

## Alternatives considered

- **Keep per-module `os.environ.get`.** Rejected: it is the source of the
  current drift and hard-to-test behaviour.
- **A full config library (pydantic-settings).** Deferred: pydantic is already
  a dependency, but a plain dataclass is sufficient and avoids an extra
  dependency until validation needs grow.
