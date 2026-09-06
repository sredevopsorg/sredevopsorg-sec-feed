# ADR-0003: Single Storage port with SQLite and PostgreSQL adapters

- Status: Accepted (implemented)
- Date: 2025-09-05

## Context

Persistence is implemented twice: `app/store.py` (SQLite) and
`app/postgres_store.py` (PostgreSQL) duplicate the entire schema and every
query. Each public function in `store.py` branches with `if _use_postgres():`
to delegate. The two implementations:

- duplicate SQL and row-mapping logic that can drift;
- repeat the same domain rules (e.g. "hide sample rows once live rows exist");
- present no interface a caller can depend on or a test can fake.

## Decision

Define a single `Storage` port — a `typing.Protocol` (or an ABC) describing
`init_db`, `seed_if_empty`, `upsert_items`, `query_feed`, `search_feed`,
`stats`, `unalerted_urgent_items`, `mark_alerted`, `get_source_cursor`, and
`set_source_cursor`. Implement two adapters against that port and select one at
startup from `Settings`. Callers depend only on the port, not on a concrete
backend.

## Consequences

- Removes per-call backend branching; a single backend instance is used.
- Enables a fake/in-memory adapter for tests and for the API layer.
- Keeps the SQLite path working for local development and tests.

## Alternatives considered

- **A single ORM (SQLAlchemy) with two dialects.** Rejected for now: it adds a
  significant dependency and rewrite for a small schema; the port can hide an
  ORM later if needs grow.
- **Drop SQLite and require PostgreSQL.** Rejected: the local, zero-setup
  path is a deliberate feature of the project.
