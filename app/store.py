"""SQLite-backed persistence for the security feed.

Post-MVP this can be swapped for PostgreSQL/OpenSearch, but SQLite keeps the
current iteration self-contained while still surviving restarts.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .fetcher import FeedItem, _ensure_aware, _sample_items, item_to_dict

logger = logging.getLogger(__name__)

DB_PATH = os.environ.get("SECURITY_FEED_DB", str(Path(__file__).resolve().parent.parent / "data" / "feed.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS feed_items (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    summary TEXT NOT NULL DEFAULT '',
    url TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT '',
    source_url TEXT NOT NULL DEFAULT '',
    published TEXT,
    tags TEXT NOT NULL DEFAULT '[]',
    cves TEXT NOT NULL DEFAULT '[]',
    severity TEXT NOT NULL DEFAULT 'unknown',
    urgent INTEGER NOT NULL DEFAULT 0,
    kev INTEGER NOT NULL DEFAULT 0,
    epss_score REAL,
    is_sample INTEGER NOT NULL DEFAULT 0,
    osv_affected TEXT NOT NULL DEFAULT '[]',
    osv_fixed TEXT NOT NULL DEFAULT '[]',
    osv_severity TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_feed_items_published ON feed_items(published DESC);
CREATE INDEX IF NOT EXISTS idx_feed_items_urgent ON feed_items(urgent DESC);
CREATE TABLE IF NOT EXISTS alerted_items (
    item_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL
);
"""


def _connect(db_path: str = DB_PATH) -> sqlite3.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_db(db_path: str = DB_PATH) -> None:
    with _connect(db_path) as conn:
        conn.executescript(SCHEMA)
        # Lightweight migration for databases created before is_sample existed.
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(feed_items)")}
        if "is_sample" not in columns:
            conn.execute("ALTER TABLE feed_items ADD COLUMN is_sample INTEGER NOT NULL DEFAULT 0")
        if "osv_affected" not in columns:
            conn.execute("ALTER TABLE feed_items ADD COLUMN osv_affected TEXT NOT NULL DEFAULT '[]'")
        if "osv_fixed" not in columns:
            conn.execute("ALTER TABLE feed_items ADD COLUMN osv_fixed TEXT NOT NULL DEFAULT '[]'")
        if "osv_severity" not in columns:
            conn.execute("ALTER TABLE feed_items ADD COLUMN osv_severity TEXT")


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return _ensure_aware(dt).isoformat()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def upsert_items(items: list[FeedItem], db_path: str = DB_PATH) -> int:
    """Insert or update feed items. Returns the number of rows touched."""
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
                json.dumps(sorted(item.tags)),
                json.dumps(item.cves),
                item.severity,
                1 if item.urgent else 0,
                1 if getattr(item, "kev", False) else 0,
                getattr(item, "epss_score", None),
                1 if getattr(item, "is_sample", False) else 0,
                json.dumps(getattr(item, "osv_affected", []) or []),
                json.dumps(getattr(item, "osv_fixed", []) or []),
                getattr(item, "osv_severity", None),
                now,
                now,
            )
        )
    with _connect(db_path) as conn:
        conn.executemany(
            """
            INSERT INTO feed_items (id, title, summary, url, source, source_url, published,
                                    tags, cves, severity, urgent, kev, epss_score,
                                    is_sample, osv_affected, osv_fixed, osv_severity,
                                    first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                title = excluded.title,
                summary = excluded.summary,
                url = excluded.url,
                source = excluded.source,
                source_url = excluded.source_url,
                published = excluded.published,
                tags = excluded.tags,
                cves = excluded.cves,
                severity = excluded.severity,
                urgent = excluded.urgent,
                kev = excluded.kev,
                epss_score = excluded.epss_score,
                is_sample = excluded.is_sample,
                osv_affected = excluded.osv_affected,
                osv_fixed = excluded.osv_fixed,
                osv_severity = excluded.osv_severity,
                last_seen = excluded.last_seen
            """,
            rows,
        )
    return len(rows)


def row_to_item(row: sqlite3.Row, now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    published = None
    if row["published"]:
        try:
            published = datetime.fromisoformat(row["published"])
        except Exception:
            published = None
    item = FeedItem(
        id=row["id"],
        title=row["title"],
        summary=row["summary"],
        url=row["url"],
        source=row["source"],
        source_url=row["source_url"],
        published=published,
        tags=set(json.loads(row["tags"] or "[]")),
        cves=json.loads(row["cves"] or "[]"),
        severity=row["severity"] or "unknown",
        urgent=bool(row["urgent"]),
    )
    if row["kev"]:
        item.kev = True  # type: ignore[attr-defined]
    if row["epss_score"] is not None:
        item.epss_score = row["epss_score"]  # type: ignore[attr-defined]
    item.is_sample = bool(row["is_sample"])
    item.osv_affected = json.loads(row["osv_affected"] or "[]")
    item.osv_fixed = json.loads(row["osv_fixed"] or "[]")
    item.osv_severity = row["osv_severity"]
    return item_to_dict(item, now=now)


def query_feed(tag: str | None = None, severity: str | None = None, limit: int = 50, db_path: str = DB_PATH) -> list[dict[str, Any]]:
    """Return feed items from SQLite, newest urgent items first.

    Sample/fallback rows are only returned while no live rows exist.
    """
    sql = "SELECT * FROM feed_items"
    clauses: list[str] = []
    params: list[Any] = []
    with _connect(db_path) as conn:
        live_count = conn.execute("SELECT COUNT(*) FROM feed_items WHERE is_sample=0").fetchone()[0]
    if live_count > 0:
        clauses.append("is_sample = 0")
    if tag:
        clauses.append("tags LIKE ?")
        params.append(f'%"{tag}"%')
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY urgent DESC, published DESC, last_seen DESC LIMIT ?"
    params.append(int(limit))

    with _connect(db_path) as conn:
        rows = conn.execute(sql, params).fetchall()
    return [row_to_item(row) for row in rows]


def stats(db_path: str = DB_PATH) -> dict[str, Any]:
    with _connect(db_path) as conn:
        total = conn.execute("SELECT COUNT(*) FROM feed_items").fetchone()[0]
        live = conn.execute("SELECT COUNT(*) FROM feed_items WHERE is_sample=0").fetchone()[0]
        by_severity = {r["severity"]: r["n"] for r in conn.execute("SELECT severity, COUNT(*) AS n FROM feed_items GROUP BY severity")}
        tag_rows = conn.execute("SELECT tags FROM feed_items").fetchall()
        by_tag: dict[str, int] = {}
        for (tags_json,) in tag_rows:
            for tag in json.loads(tags_json or "[]"):
                by_tag[tag] = by_tag.get(tag, 0) + 1
        urgent = conn.execute("SELECT COUNT(*) FROM feed_items WHERE urgent=1").fetchone()[0]
        latest = conn.execute("SELECT MAX(last_seen) FROM feed_items").fetchone()[0]
    return {
        "total": total,
        "live": live,
        "sample": total - live,
        "urgent": urgent,
        "by_severity": by_severity,
        "by_tag": by_tag,
        "latest_seen": latest,
    }


def seed_if_empty(db_path: str = DB_PATH) -> int:
    """Insert sample items when the database has no rows (e.g. first boot offline)."""
    with _connect(db_path) as conn:
        count = conn.execute("SELECT COUNT(*) FROM feed_items").fetchone()[0]
    if count > 0:
        return 0
    return upsert_items(_sample_items(), db_path=db_path)


def unalerted_urgent_items(limit: int = 20, db_path: str = DB_PATH) -> list[dict[str, Any]]:
    """Return urgent items that have not been alerted yet.

    Sample/fallback rows are excluded once live rows exist.
    """
    with _connect(db_path) as conn:
        live_count = conn.execute("SELECT COUNT(*) FROM feed_items WHERE is_sample=0").fetchone()[0]
        sample_clause = "AND f.is_sample = 0" if live_count > 0 else ""
        rows = conn.execute(
            f"""
            SELECT f.* FROM feed_items f
            LEFT JOIN alerted_items a ON a.item_id = f.id
            WHERE f.urgent = 1 AND a.item_id IS NULL {sample_clause}
            ORDER BY f.published DESC
            LIMIT ?
            """,
            (int(limit),),
        ).fetchall()
    return [row_to_item(row) for row in rows]


def mark_alerted(item_ids: list[str], db_path: str = DB_PATH) -> None:
    if not item_ids:
        return
    now = _now_iso()
    with _connect(db_path) as conn:
        conn.executemany(
            "INSERT OR IGNORE INTO alerted_items (item_id, created_at) VALUES (?, ?)",
            [(item_id, now) for item_id in item_ids],
        )


def search_feed(q: str, tag: str | None = None, severity: str | None = None, limit: int = 50, db_path: str = DB_PATH) -> list[dict[str, Any]]:
    """Fallback search over title, summary, source, and CVE ids."""
    if not q:
        return query_feed(tag=tag, severity=severity, limit=limit, db_path=db_path)
    like = f"%{q}%"
    clauses: list[str] = []
    params: list[Any] = []
    with _connect(db_path) as conn:
        live_count = conn.execute("SELECT COUNT(*) FROM feed_items WHERE is_sample=0").fetchone()[0]
    if live_count > 0:
        clauses.append("is_sample = 0")
    clauses.append("(title LIKE ? OR summary LIKE ? OR source LIKE ? OR cves LIKE ?)")
    params.extend([like, like, like, like])
    if tag:
        clauses.append("tags LIKE ?")
        params.append(f'%"{tag}"%')
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    sql = "SELECT * FROM feed_items WHERE " + " AND ".join(clauses)
    sql += " ORDER BY urgent DESC, published DESC, last_seen DESC LIMIT ?"
    params.append(int(limit))
    with _connect(db_path) as conn:
        rows = conn.execute(sql, params).fetchall()
    return [row_to_item(row) for row in rows]
