import json
from datetime import datetime, timedelta, timezone

from app.fetcher import FeedItem
from app.store import init_db, query_feed, seed_if_empty, stats, upsert_items


def make_item(id: str = "a", title: str = "Test advisory", tags: set[str] = frozenset({"linux"}), cves: list[str] | None = None, severity: str = "high", urgent: bool = False) -> FeedItem:
    return FeedItem(
        id=id,
        title=title,
        summary="summary",
        url="https://example.com/" + id,
        source="test",
        source_url="https://example.com/feed",
        published=datetime.now(timezone.utc) - timedelta(hours=1),
        tags=set(tags),
        cves=cves or ["CVE-2024-0001"],
        severity=severity,
        urgent=urgent,
    )


def test_persist_and_query(tmp_path):
    db = str(tmp_path / "feed.db")
    init_db(db)
    assert seed_if_empty(db) > 0
    assert query_feed(limit=10, db_path=db)

    upsert_items([make_item("b", "Threat advisory", {"threat"}, ["CVE-2024-0002"], "critical", True)], db)
    rows = query_feed(tag="threat", severity="critical", limit=10, db_path=db)
    assert len(rows) == 1
    assert rows[0]["id"] == "b"
    assert rows[0]["tags"] == ["threat"]
    assert rows[0]["urgent"] is True


def test_stats(tmp_path):
    db = str(tmp_path / "feed.db")
    init_db(db)
    seed_if_empty(db)
    s = stats(db)
    assert s["total"] > 0
    assert "by_tag" in s
    assert "by_severity" in s
