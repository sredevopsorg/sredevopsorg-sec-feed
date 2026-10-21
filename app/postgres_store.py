"""PostgreSQL-backed store implementation.

Activated when ``DATABASE_URL`` is set. The API is intentionally the same as
the SQLite store in ``app/sqlite_store.py``, so the rest of the app is
backend-agnostic (ADR-0003).

Connections come from a lazy ``psycopg_pool.ConnectionPool`` rather than a new
connection per call: against a remote provider (Supabase) every call would
otherwise pay a full TLS handshake. The pool is created on first use and closed
by ``close()`` (called from the FastAPI lifespan shutdown hook).

Schema management is deliberately absent here: ``init_db()`` only verifies that
the checked-in migrations have been applied. Apply them with
``python -m app.migrate upgrade`` (compose runs it as a one-shot job).
"""

from __future__ import annotations

import json
import logging
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool, PoolTimeout

from . import config
from .errors import SchemaNotMigrated, StoreUnavailable
from .migrate import latest_version
from .models import FeedItem, _ensure_aware, _sample_items, item_to_dict

logger = logging.getLogger(__name__)

# The pool is built lazily from ``config.settings`` so tests can monkeypatch the
# settings object and reset the pool. ``prepare_threshold`` is a psycopg kwarg
# only — it cannot be expressed in the connection string (libpq rejects it), and
# the default of ``None`` disables prepared statements, which keeps the adapter
# safe through transaction-mode poolers and avoids ``executemany`` preparing
# ``_pg3_0`` on its first row. Session-mode connections may safely enable it
# via ``DB_PREPARE_THRESHOLD=5``.
_POOL: ConnectionPool | None = None


def _configure_connection(conn: psycopg.Connection) -> None:
    """Apply per-session guards that a pooler will not deliver via DSN options.

    Supavisor ignores libpq's ``options`` startup parameter (verified: the
    session reports ``application_name=Supavisor`` and the server default
    ``statement_timeout=2min``). A committed ``SET`` does survive the pooled
    session, so set and commit it here. Do not add a pool ``reset`` callback:
    that would discard these session settings on every check-in.
    """
    s = config.settings
    for name, value in (
        ("statement_timeout", s.db_statement_timeout_ms),
        ("idle_in_transaction_session_timeout", s.db_idle_tx_timeout_ms),
        ("lock_timeout", s.db_lock_timeout_ms),
    ):
        conn.execute(f"SET {name} = {int(value)}")
    conn.commit()


def _ensure_pool() -> ConnectionPool:
    global _POOL
    if _POOL is None:
        s = config.settings
        dsn = s.database_url or ""
        if not dsn:
            raise RuntimeError("DATABASE_URL is not set; cannot use the PostgreSQL backend")
        kwargs: dict[str, Any] = {
            "row_factory": dict_row,
            "prepare_threshold": s.db_prepare_threshold,
            "connect_timeout": s.db_connect_timeout,
            "sslmode": s.db_sslmode,
            "application_name": s.db_application_name,
        }
        if s.db_sslrootcert:
            kwargs["sslrootcert"] = s.db_sslrootcert
        _POOL = ConnectionPool(
            dsn,
            kwargs=kwargs,
            min_size=s.db_pool_min_size,
            max_size=s.db_pool_max_size,
            timeout=s.db_pool_timeout,
            max_idle=s.db_pool_max_idle,
            max_lifetime=s.db_pool_max_lifetime,
            configure=_configure_connection,
            # `open=True` fills min_size connections in the background without
            # blocking; the pool itself is only built lazily, on first use.
            open=True,
        )
    return _POOL


@contextmanager
def _connection() -> Iterator[psycopg.Connection]:
    try:
        with _ensure_pool().connection() as conn:
            yield conn
    except (psycopg.OperationalError, PoolTimeout) as exc:
        # Translate driver-level connection failures into a stable API contract
        # (503) instead of leaking a psycopg exception from a route.
        raise StoreUnavailable("database unavailable") from exc


def close() -> None:
    """Close the pool (called from the application shutdown hook)."""
    global _POOL
    if _POOL is not None:
        _POOL.close()
        _POOL = None


def _reset_pool() -> None:
    """Test hook: drop the pool so the next call rebuilds it from settings."""
    close()


# ``init_db`` verifies the schema produced by ``migrations/0001_baseline.sql``.
_REQUIRED_TABLES = ("feed_items", "alerted_items", "source_cursors", "source_state")



def _jsonb(value: Any) -> str:
    return json.dumps(value or [])


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return _ensure_aware(dt).isoformat()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _escape_like(value: str) -> str:
    """Escape LIKE/ILIKE wildcards so user input matches literally.

    The query is still parameterized (no injection risk); this only stops a
    ``%`` or ``_`` in the search box from broadening the match. PostgreSQL's
    default LIKE/ILIKE escape character is the backslash, and the pattern is a
    bound parameter (so ``standard_conforming_strings`` is irrelevant), which
    is why the SQL below needs no explicit ``ESCAPE`` clause.
    """
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def init_db(db_path: str = "") -> None:
    """Verify that the checked-in migrations have been applied.

    This function intentionally performs no DDL: schema creation at API startup
    races across replicas and requires the runtime role to own the schema. Run
    ``python -m app.migrate upgrade`` (compose runs it as a one-shot job) before
    starting the API.
    """
    expected = latest_version()
    with _connection() as conn:
        tracking = conn.execute("SELECT to_regclass(%s) AS t", ("public.feed_schema_migrations",)).fetchone()
        if not tracking or not tracking["t"]:
            raise SchemaNotMigrated(
                "feed_schema_migrations is missing; run `python -m app.migrate upgrade`"
            )
        row = conn.execute("SELECT max(version) AS version FROM feed_schema_migrations").fetchone()
        applied = row["version"] if row else None
        missing = [
            table
            for table in _REQUIRED_TABLES
            if conn.execute("SELECT to_regclass(%s) AS t", (f"public.{table}",)).fetchone()["t"] is None
        ]
    if applied != expected or missing:
        detail = f"applied={applied!r}, expected={expected!r}"
        if missing:
            detail += f", missing tables={missing}"
        raise SchemaNotMigrated(
            f"database schema is not current ({detail}); run `python -m app.migrate upgrade`"
        )


def get_source_state(source_id: str, db_path: str = "") -> dict[str, Any] | None:
    with _connection() as conn:
        row = conn.execute("SELECT * FROM source_state WHERE source_id = %s", (source_id,)).fetchone()
    if row is None:
        return None

    def _ts(value: Any) -> Any:
        return value.isoformat() if isinstance(value, datetime) else value

    return {
        "source_id": row["source_id"],
        "etag": row["etag"],
        "last_modified": row["last_modified"],
        "last_fetched_at": _ts(row["last_fetched_at"]),
        "last_ok_at": _ts(row["last_ok_at"]),
        "last_error": row["last_error"],
        "last_payload": row["last_payload"],
    }


def set_source_state(
    source_id: str,
    *,
    etag: str | None,
    last_modified: str | None,
    fetched_at: datetime | None,
    ok: bool,
    error: str | None,
    payload: list[dict[str, Any]] | None,
    db_path: str = "",
) -> None:
    """Record one fetch attempt, preserving validators/payload when not supplied."""
    now = datetime.now(timezone.utc)
    with _connection() as conn:
        conn.execute(
            """
            INSERT INTO source_state
                (source_id, etag, last_modified, last_fetched_at, last_ok_at, last_error, last_payload)
            VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb)
            ON CONFLICT(source_id) DO UPDATE SET
                etag = COALESCE(EXCLUDED.etag, source_state.etag),
                last_modified = COALESCE(EXCLUDED.last_modified, source_state.last_modified),
                last_fetched_at = EXCLUDED.last_fetched_at,
                last_ok_at = COALESCE(EXCLUDED.last_ok_at, source_state.last_ok_at),
                last_error = EXCLUDED.last_error,
                last_payload = COALESCE(EXCLUDED.last_payload, source_state.last_payload)
            """,
            (
                source_id,
                etag,
                last_modified,
                fetched_at or now,
                now if ok else None,
                error,
                json.dumps(payload) if payload is not None else None,
            ),
        )


def ping(db_path: str = "") -> bool:
    """Cheap readiness probe: prove a pooled connection answers a query."""
    with _connection() as conn:
        conn.execute("SELECT 1").fetchone()
    return True


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
            cur = conn.cursor()
            cur.executemany(
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
    like = f"%{_escape_like(q)}%"
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
        cur = conn.cursor()
        cur.executemany(
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
