# ADR-0004: Extract a domain model and decompose the refresh pipeline

- Status: Accepted
- Date: 2025-09-05

## Context

`app/fetcher.py` is a 778-line module that fetches, parses, normalizes,
enriches, persists, indexes, publishes events, and sends alerts. It lazily
imports `store`, `events`, `search`, `alerts`, `enrich`, and `osv` to avoid
circular imports, while `store.py` imports `FeedItem` back from `fetcher.py`.
The domain model (`FeedItem`) therefore lives inside the I/O module, and the
pipeline is a single god coroutine (`refresh_feed`).

## Decision

1. Move `FeedItem` and its serialization helpers (`item_to_dict`,
   `_time_ago`, `_ensure_aware`, sample data, deduplication/sort) into a
   dedicated `models` module so persistence and fetching depend on the model
   one-way, breaking the `fetcher ↔ store` cycle.
2. Extract the refresh orchestration from `fetcher.py` into a small
   pipeline/orchestrator with one-way dependencies:
   `fetch → enrich → persist → index → publish → alert`. Each step stays
   best-effort as today.

## Consequences

- Clear, acyclic module dependency direction: `models ← store ← pipeline`.
- The fetch module focuses on sources and normalization; enrichment,
  persistence, indexing, and alerting are called by the orchestrator, not
  hidden inside a single coroutine.
- Smaller units are easier to test in isolation.

## Alternatives considered

- **Leave the god module as-is.** Rejected: it is the main obstacle to
  maintainability and to testing the pipeline end to end.
- **Introduce a task queue (Celery) now.** Rejected: single-process
  background refresh is sufficient; the pipeline extraction keeps that option
  available without paying for it today.
