"""PostgreSQL-backed store implementation.

Activated when DATABASE_URL is set. The API is intentionally the same as the
SQLite store in app/store.py, so the rest of the app is backend-agnostic.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

import psycopg
from psycopg.rows import dict_row

from .fetcher import FeedItem, _ensure_aware, _sample_items, item_to_dict

logger = logging.getLogger(__name__)

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://feed:feed@localhost:5432/feed")

SCHEMA = """
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
);
CREATE INDEX IF NOT EXISTS idx_feed_items_published ON feed_items(published DESC);
CREATE INDEX IF NOT EXISTS idx_feed_items_urgent ON feed_items(urgent DESC);
CREATE TABLE IF NOT EXISTS alerted_items (
    item_id TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS source_cursors (
    source_id TEXT PRIMARY KEY,
    cursor TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
"""


def _connect() -> psycopg.Connection:
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def _jsonb(value: Any) -> str:
    return json.dumps(value or [])


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return _ensure_aware(dt).isoformat()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db() -> None:
    with _connect() as conn:
        conn.execute(SCHEMA)
        # Lightweight migration for databases created before patch_status.
        conn.execute(
            "ALTER TABLE feed_items ADD COLUMN IF NOT EXISTS patch_status TEXT NOT NULL DEFAULT 'unknown'"
        )


def seed_if_empty() -> int:
    with _connect() as conn:
        count = conn.execute("SELECT COUNT(*) FROM feed_items").fetchone()["count"]
    if count > 0:
        return 0
    return upsert_items(_sample_items())


def upsert_items(items: list[FeedItem]) -> int:
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
                bool(getattr(item, "kev", False)),
                getattr(item, "epss_score", None),
                bool(getattr(item, "is_sample", False)),
                _jsonb(getattr(item, "osv_affected", [])),
                _jsonb(getattr(item, "osv_fixed", [])),
                getattr(item, "osv_severity", None),
                getattr(item, "patch_status", "unknown"),
                now,
                now,
            )
        )
    with _connect() as conn:
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
    item.kev = bool(row.get("kev"))  # type: ignore[attr-defined]
    item.epss_score = row.get("epss_score")  # type: ignore[attr-defined]
    item.is_sample = bool(row.get("is_sample"))  # type: ignore[attr-defined]
    item.osv_affected = list(row.get("osv_affected") or [])
    item.osv_fixed = list(row.get("osv_fixed") or [])
    item.osv_severity = row.get("osv_severity")
    item.patch_status = row.get("patch_status") or "unknown"
    return item_to_dict(item, now=now)


def _live_count(conn: psycopg.Connection) -> int:
    return conn.execute("SELECT COUNT(*) FROM feed_items WHERE is_sample = FALSE").fetchone()["count"]


def query_feed(tag: str | None = None, severity: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    with _connect() as conn:
        if _live_count(conn) > 0:
            clauses.append("is_sample = FALSE")
        if tag:
            clauses.append("tags @> %s::jsonb")
            params.append(_jsonb([tag]))
        if severity:
            clauses.append("severity = %s")
            params.append(severity)
        sql = "SELECT * FROM feed_items"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY urgent DESC, published DESC NULLS LAST, last_seen DESC NULLS LAST LIMIT %s"
        params.append(int(limit))
        rows = conn.execute(sql, params).fetchall()
    return [_row_to_item(row) for row in rows]


def search_feed(q: str, tag: str | None = None, severity: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    if not q:
        return query_feed(tag=tag, severity=severity, limit=limit)
    clauses: list[str] = []
    params: list[Any] = []
    with _connect() as conn:
        if _live_count(conn) > 0:
            clauses.append("is_sample = FALSE")
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
        rows = conn.execute(sql, params).fetchall()
    return [_row_to_item(row) for row in rows]


def stats() -> dict[str, Any]:
    with _connect() as conn:
        total = conn.execute("SELECT COUNT(*) FROM feed_items").fetchone()["count"]
        live = conn.execute("SELECT COUNT(*) FROM feed_items WHERE is_sample = FALSE").fetchone()["count"]
        by_severity = {
            r["severity"]: r["count"]
            for r in conn.execute("SELECT severity, COUNT(*) AS count FROM feed_items GROUP BY severity")
        }
        tag_rows = conn.execute("SELECT tags FROM feed_items").fetchall()
        by_tag: dict[str, int] = {}
        for row in tag_rows:
            for tag in row["tags"] or []:
                by_tag[tag] = by_tag.get(tag, 0) + 1
        urgent = conn.execute("SELECT COUNT(*) FROM feed_items WHERE urgent = TRUE").fetchone()["count"]
        latest = conn.execute("SELECT MAX(last_seen) FROM feed_items").fetchone()["max"]
    return {
        "total": total,
        "live": live,
        "sample": total - live,
        "urgent": urgent,
        "by_severity": by_severity,
        "by_tag": by_tag,
        "latest_seen": latest.isoformat() if latest else None,
    }


def unalerted_urgent_items(limit: int = 20) -> list[dict[str, Any]]:
    with _connect() as conn:
        if _live_count(conn) > 0:
            rows = conn.execute(
                """
                SELECT f.* FROM feed_items f
                LEFT JOIN alerted_items a ON a.item_id = f.id
                WHERE f.urgent = TRUE AND a.item_id IS NULL AND f.is_sample = FALSE
                ORDER BY f.published DESC NULLS LAST
                LIMIT %s
                """,
                (int(limit),),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT f.* FROM feed_items f
                LEFT JOIN alerted_items a ON a.item_id = f.id
                WHERE f.urgent = TRUE AND a.item_id IS NULL
                ORDER BY f.published DESC NULLS LAST
                LIMIT %s
                """,
                (int(limit),),
            ).fetchall()
    return [_row_to_item(row) for row in rows]


def mark_alerted(item_ids: list[str]) -> None:
    if not item_ids:
        return
    now = _now_iso()
    with _connect() as conn:
        conn.executemany(
            "INSERT INTO alerted_items (item_id, created_at) VALUES (%s, %s) ON CONFLICT DO NOTHING",
            [(item_id, now) for item_id in item_ids],
        )


def get_source_cursor(source_id: str) -> str | None:
    with _connect() as conn:
        row = conn.execute("SELECT cursor FROM source_cursors WHERE source_id = %s", (source_id,)).fetchone()
    return row["cursor"] if row else None


def set_source_cursor(source_id: str, cursor: str) -> None:
    with _connect() as conn:
        conn.execute(
            "INSERT INTO source_cursors (source_id, cursor, updated_at) VALUES (%s, %s, %s) "
            "ON CONFLICT(source_id) DO UPDATE SET cursor = EXCLUDED.cursor, updated_at = EXCLUDED.updated_at",
            (source_id, cursor, _now_iso()),
        )
