"""PostgreSQL-backed store implementation.

Activated when ``DATABASE_URL`` is set. The API is intentionally the same as
the SQLite store in ``app/sqlite_store.py``, so the rest of the app is
backend-agnostic (ADR-0003).

Connections come from a lazy ``psycopg_pool.ConnectionPool`` rather than a new
connection per call: against a remote provider (Supabase) every call would
otherwise pay a full TLS handshake. The pool is created on first use and closed
by ``close()`` (called from the FastAPI lifespan shutdown hook).
"""

from __future__ import annotations

import json
import logging
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from . import config
from .models import FeedItem, _ensure_aware, _sample_items, item_to_dict

logger = logging.getLogger(__name__)

# The pool is built lazily from ``config.settings`` so tests can monkeypatch the
# settings object and reset the pool. ``prepare_threshold`` is a psycopg kwarg
# only — it cannot be expressed in the connection string (libpq rejects it), and
# the default of ``None`` disables prepared statements, which keeps the adapter
# safe through transaction-mode poolers and avoids ``executemany`` preparing
# ``_pg3_0`` on its first row.
_POOL: ConnectionPool | None = None


def _ensure_pool() -> ConnectionPool:
    global _POOL
    if _POOL is None:
        s = config.settings
        dsn = s.database_url or ""
        if not dsn:
            raise RuntimeError("DATABASE_URL is not set; cannot use the PostgreSQL backend")
        _POOL = ConnectionPool(
            dsn,
            kwargs={
                "row_factory": dict_row,
                "prepare_threshold": s.db_prepare_threshold,
                "connect_timeout": s.db_connect_timeout,
                "sslmode": s.db_sslmode,
                "application_name": s.db_application_name,
            },
            min_size=s.db_pool_min_size,
            max_size=s.db_pool_max_size,
            # `open=True` fills min_size connections in the background without
            # blocking; the pool itself is only built lazily, on first use.
            open=True,
        )
    return _POOL


@contextmanager
def _connection() -> Iterator[psycopg.Connection]:
    with _ensure_pool().connection() as conn:
        yield conn


def close() -> None:
    """Close the pool (called from the application shutdown hook)."""
    global _POOL
    if _POOL is not None:
        _POOL.close()
        _POOL = None


def _reset_pool() -> None:
    """Test hook: drop the pool so the next call rebuilds it from settings."""
    close()


# Schema is a list of single statements. Executing each individually (rather
# than one multi-statement string) removes the reliance on the simple-query
# protocol fallback and stays correct under any ``prepare_threshold``.
_SCHEMA_STATEMENTS = (
    """
    CREATE TABLE IF NOT EXISTS feed_items (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        summary TEXT NOT NULL DEFAULT '',
        url TEXT NOT NULL DEFAULT '',
        source TEXT NOT NULL DEFAULT '',
        source_url TEXT NOT NULL DEFAULT '',
        published TIMESTAMPTZ,
        tags JSONB NOT NULL DEFAULT '[]',
        cves JSONB NOT NULL DEFAULT '[]',
        severity TEXT NOT NULL DEFAULT 'unknown',
        urgent BOOLEAN NOT NULL DEFAULT FALSE,
        kev BOOLEAN NOT NULL DEFAULT FALSE,
        epss_score DOUBLE PRECISION,
        is_sample BOOLEAN NOT NULL DEFAULT FALSE,
        osv_affected JSONB NOT NULL DEFAULT '[]',
        osv_fixed JSONB NOT NULL DEFAULT '[]',
        osv_severity TEXT,
        patch_status TEXT NOT NULL DEFAULT 'unknown',
        first_seen TIMESTAMPTZ NOT NULL,
        last_seen TIMESTAMPTZ NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_feed_items_published ON feed_items(published DESC)",
    "CREATE INDEX IF NOT EXISTS idx_feed_items_urgent ON feed_items(urgent DESC)",
    """
    CREATE TABLE IF NOT EXISTS alerted_items (
        item_id TEXT PRIMARY KEY,
        created_at TIMESTAMPTZ NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS source_cursors (
        source_id TEXT PRIMARY KEY,
        cursor TEXT NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL
    )
    """,
)

# Lightweight migrations for databases created before these columns existed
# (kept in step with app/sqlite_store.py).
_COLUMN_MIGRATIONS = (
    "ALTER TABLE feed_items ADD COLUMN IF NOT EXISTS is_sample BOOLEAN NOT NULL DEFAULT FALSE",
    "ALTER TABLE feed_items ADD COLUMN IF NOT EXISTS kev BOOLEAN NOT NULL DEFAULT FALSE",
    "ALTER TABLE feed_items ADD COLUMN IF NOT EXISTS epss_score DOUBLE PRECISION",
    "ALTER TABLE feed_items ADD COLUMN IF NOT EXISTS osv_affected JSONB NOT NULL DEFAULT '[]'",
    "ALTER TABLE feed_items ADD COLUMN IF NOT EXISTS osv_fixed JSONB NOT NULL DEFAULT '[]'",
    "ALTER TABLE feed_items ADD COLUMN IF NOT EXISTS osv_severity TEXT",
    "ALTER TABLE feed_items ADD COLUMN IF NOT EXISTS patch_status TEXT NOT NULL DEFAULT 'unknown'",
)

# pg_trgm powers the trigram GIN indexes used by the ILIKE search path
# (CVE-substring matching in particular, which to_tsvector tokenizes poorly).
_EXTENSION_STATEMENTS = (
    "CREATE SCHEMA IF NOT EXISTS extensions",
    "CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA extensions",
)

# Indexes for the queries this adapter actually runs (see the
# supabase-postgres-best-practices rules for jsonb GIN and trigram indexing).
_INDEX_STATEMENTS = (
    "CREATE INDEX IF NOT EXISTS idx_feed_items_tags ON feed_items USING gin (tags jsonb_path_ops)",
    "CREATE INDEX IF NOT EXISTS idx_feed_items_title_trgm ON feed_items USING gin (title gin_trgm_ops)",
    "CREATE INDEX IF NOT EXISTS idx_feed_items_summary_trgm ON feed_items USING gin (summary gin_trgm_ops)",
    "CREATE INDEX IF NOT EXISTS idx_feed_items_cves_trgm ON feed_items USING gin ((cves::text) gin_trgm_ops)",
    "CREATE INDEX IF NOT EXISTS idx_feed_items_severity ON feed_items (severity)",
)

# RLS is defence in depth: the app connects as the table owner (which bypasses
# RLS), and the tables are never exposed to the Supabase Data API. Enabling RLS
# with no policies denies every non-owner role by default.
_RLS_STATEMENTS = (
    "ALTER TABLE feed_items ENABLE ROW LEVEL SECURITY",
    "ALTER TABLE alerted_items ENABLE ROW LEVEL SECURITY",
    "ALTER TABLE source_cursors ENABLE ROW LEVEL SECURITY",
)


def _jsonb(value: Any) -> str:
    return json.dumps(value or [])


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return _ensure_aware(dt).isoformat()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db(db_path: str = "") -> None:
    with _connection() as conn:
        for statement in (
            *_SCHEMA_STATEMENTS,
            *_COLUMN_MIGRATIONS,
            *_EXTENSION_STATEMENTS,
            *_INDEX_STATEMENTS,
            *_RLS_STATEMENTS,
        ):
            conn.execute(statement)


def seed_if_empty(db_path: str = "") -> int:
    with _connection() as conn:
        count = conn.execute("SELECT COUNT(*) FROM feed_items").fetchone()["count"]
    if count > 0:
        return 0
    return upsert_items(_sample_items())


def upsert_items(items: list[FeedItem], db_path: str = "") -> int:
    if not items:
        return 0
    now = _now_iso()
    rows: list[tuple[Any, ...]] = []
    for item in items:
        rows.append(
            (
                item.id,
                item.title,
                item.summary or "",
                item.url or "",
                item.source or "",
                item.source_url or "",
                _iso(item.published),
                _jsonb(sorted(item.tags)),
                _jsonb(item.cves),
                item.severity,
                bool(item.urgent),
                bool(item.kev),
                item.epss_score,
                bool(item.is_sample),
                _jsonb(item.osv_affected),
                _jsonb(item.osv_fixed),
                item.osv_severity,
                item.patch_status,
                now,
                now,
            )
        )
    with _connection() as conn:
        # The transaction block must be the first statement on the connection so
        # it becomes a real BEGIN/COMMIT rather than a SAVEPOINT inside an
        # implicit transaction left open by a prior query.
        with conn.transaction():
            conn.executemany(
                """
                INSERT INTO feed_items (
                    id, title, summary, url, source, source_url, published,
                    tags, cves, severity, urgent, kev, epss_score,
                    is_sample, osv_affected, osv_fixed, osv_severity,
                    patch_status, first_seen, last_seen
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s,
                        %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s, %s, %s, %s)
                ON CONFLICT(id) DO UPDATE SET
                    title = EXCLUDED.title,
                    summary = EXCLUDED.summary,
                    url = EXCLUDED.url,
                    source = EXCLUDED.source,
                    source_url = EXCLUDED.source_url,
                    published = EXCLUDED.published,
                    tags = EXCLUDED.tags,
                    cves = EXCLUDED.cves,
                    severity = EXCLUDED.severity,
                    urgent = EXCLUDED.urgent,
                    kev = EXCLUDED.kev,
                    epss_score = EXCLUDED.epss_score,
                    is_sample = EXCLUDED.is_sample,
                    osv_affected = EXCLUDED.osv_affected,
                    osv_fixed = EXCLUDED.osv_fixed,
                    osv_severity = EXCLUDED.osv_severity,
                    patch_status = EXCLUDED.patch_status,
                    last_seen = EXCLUDED.last_seen
                """,
                rows,
            )
    return len(rows)


def _row_to_item(row: dict[str, Any], now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    published = row.get("published")
    if isinstance(published, str):
        try:
            published = datetime.fromisoformat(published)
        except Exception:
            published = None
    item = FeedItem(
        id=row["id"],
        title=row["title"],
        summary=row["summary"] or "",
        url=row["url"] or "",
        source=row["source"] or "",
        source_url=row["source_url"] or "",
        published=published,
        tags=set(row.get("tags") or []),
        cves=list(row.get("cves") or []),
        severity=row.get("severity") or "unknown",
        urgent=bool(row.get("urgent")),
    )
    item.kev = bool(row.get("kev"))
    item.epss_score = row.get("epss_score")
    item.is_sample = bool(row.get("is_sample"))
    item.osv_affected = list(row.get("osv_affected") or [])
    item.osv_fixed = list(row.get("osv_fixed") or [])
    item.osv_severity = row.get("osv_severity")
    item.patch_status = row.get("patch_status") or "unknown"
    return item_to_dict(item, now=now)


# Sample rows must stay hidden once live rows exist (invariant 4). This single
# predicate replaces the old two-query `_live_count` round trip on every read.
_HIDE_SAMPLE = "(is_sample = FALSE OR NOT EXISTS (SELECT 1 FROM feed_items WHERE is_sample = FALSE))"


def query_feed(tag: str | None = None, severity: str | None = None, limit: int = 50, db_path: str = "") -> list[dict[str, Any]]:
    clauses: list[str] = [_HIDE_SAMPLE]
    params: list[Any] = []
    if tag:
        clauses.append("tags @> %s::jsonb")
        params.append(_jsonb([tag]))
    if severity:
        clauses.append("severity = %s")
        params.append(severity)
    sql = "SELECT * FROM feed_items WHERE " + " AND ".join(clauses)
    sql += " ORDER BY urgent DESC, published DESC NULLS LAST, last_seen DESC NULLS LAST LIMIT %s"
    params.append(int(limit))
    with _connection() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [_row_to_item(row) for row in rows]


def search_feed(q: str, tag: str | None = None, severity: str | None = None, limit: int = 50, db_path: str = "") -> list[dict[str, Any]]:
    if not q:
        return query_feed(tag=tag, severity=severity, limit=limit)
    clauses: list[str] = [_HIDE_SAMPLE]
    params: list[Any] = []
    like = f"%{q}%"
    clauses.append("(title ILIKE %s OR summary ILIKE %s OR source ILIKE %s OR cves::text ILIKE %s)")
    params.extend([like, like, like, like])
    if tag:
        clauses.append("tags @> %s::jsonb")
        params.append(_jsonb([tag]))
    if severity:
        clauses.append("severity = %s")
        params.append(severity)
    sql = "SELECT * FROM feed_items WHERE " + " AND ".join(clauses)
    sql += " ORDER BY urgent DESC, published DESC NULLS LAST, last_seen DESC NULLS LAST LIMIT %s"
    params.append(int(limit))
    with _connection() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [_row_to_item(row) for row in rows]


def stats(db_path: str = "") -> dict[str, Any]:
    sql = """
    SELECT
        COUNT(*) AS total,
        COUNT(*) FILTER (WHERE NOT is_sample) AS live,
        COUNT(*) FILTER (WHERE urgent) AS urgent,
        MAX(last_seen) AS latest_seen,
        COALESCE(
            (SELECT jsonb_object_agg(severity, cnt) FROM (
                SELECT severity, COUNT(*) AS cnt FROM feed_items GROUP BY severity
            ) s),
            '{}'::jsonb
        ) AS by_severity,
        COALESCE(
            (SELECT jsonb_object_agg(tag, cnt) FROM (
                SELECT tag, COUNT(*) AS cnt
                FROM feed_items, jsonb_array_elements_text(tags) AS tag
                GROUP BY tag
            ) t),
            '{}'::jsonb
        ) AS by_tag
    FROM feed_items
    """
    with _connection() as conn:
        row = conn.execute(sql).fetchone()
    return {
        "total": row["total"],
        "live": row["live"],
        "sample": row["total"] - row["live"],
        "urgent": row["urgent"],
        "by_severity": {k: int(v) for k, v in (row["by_severity"] or {}).items()},
        "by_tag": {k: int(v) for k, v in (row["by_tag"] or {}).items()},
        "latest_seen": row["latest_seen"].isoformat() if row["latest_seen"] else None,
    }


def unalerted_urgent_items(limit: int = 20, db_path: str = "") -> list[dict[str, Any]]:
    sql = """
    SELECT f.* FROM feed_items f
    LEFT JOIN alerted_items a ON a.item_id = f.id
    WHERE f.urgent = TRUE AND a.item_id IS NULL
      AND (f.is_sample = FALSE OR NOT EXISTS (SELECT 1 FROM feed_items WHERE is_sample = FALSE))
    ORDER BY f.published DESC NULLS LAST
    LIMIT %s
    """
    with _connection() as conn:
        rows = conn.execute(sql, (int(limit),)).fetchall()
    return [_row_to_item(row) for row in rows]


def mark_alerted(item_ids: list[str], db_path: str = "") -> None:
    if not item_ids:
        return
    now = _now_iso()
    with _connection() as conn:
        conn.executemany(
            "INSERT INTO alerted_items (item_id, created_at) VALUES (%s, %s) ON CONFLICT DO NOTHING",
            [(item_id, now) for item_id in item_ids],
        )


def get_source_cursor(source_id: str, db_path: str = "") -> str | None:
    with _connection() as conn:
        row = conn.execute("SELECT cursor FROM source_cursors WHERE source_id = %s", (source_id,)).fetchone()
    return row["cursor"] if row else None


def set_source_cursor(source_id: str, cursor: str, db_path: str = "") -> None:
    with _connection() as conn:
        conn.execute(
            "INSERT INTO source_cursors (source_id, cursor, updated_at) VALUES (%s, %s, %s) "
            "ON CONFLICT(source_id) DO UPDATE SET cursor = EXCLUDED.cursor, updated_at = EXCLUDED.updated_at",
            (source_id, cursor, _now_iso()),
        )
