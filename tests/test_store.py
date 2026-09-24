from datetime import datetime, timedelta, timezone

from app.fetcher import FeedItem
from app.store import init_db, mark_alerted, query_feed, search_feed, seed_if_empty, stats, unalerted_urgent_items, upsert_items


def make_item(id: str = "a", title: str = "Test advisory", tags: set[str] = frozenset({"linux"}), cves: list[str] | None = None, severity: str = "high", urgent: bool = False, patch_status: str = "unknown", published: datetime | None = None) -> FeedItem:
    return FeedItem(
        id=id,
        title=title,
        summary="summary",
        url="https://example.com/" + id,
        source="test",
        source_url="https://example.com/feed",
        published=published or datetime.now(timezone.utc) - timedelta(hours=1),
        tags=set(tags),
        cves=cves or ["CVE-2024-0001"],
        severity=severity,
        urgent=urgent,
        patch_status=patch_status,
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


def test_search_feed(tmp_path):
    db = str(tmp_path / "feed.db")
    init_db(db)
    seed_if_empty(db)
    rows = search_feed("runc", limit=10, db_path=db)
    assert rows, "expected at least one runc match"
    assert any("runc" in r["title"].lower() or "runc" in r["summary"].lower() for r in rows)


def test_search_feed_escapes_like_wildcards(tmp_path):
    """A bare % or _ must not broaden the match to every row."""
    db = str(tmp_path / "feed.db")
    init_db(db)
    upsert_items([make_item("x", "Runaway advisory"), make_item("y", "Discount 50% off")], db)
    assert search_feed("_", limit=10, db_path=db) == []
    # ...but a literal '%' still matches the row that contains it.
    assert [r["id"] for r in search_feed("%", limit=10, db_path=db)] == ["y"]
    assert [r["id"] for r in search_feed("runaway", limit=10, db_path=db)] == ["x"]


def test_alerted_items(tmp_path):
    db = str(tmp_path / "feed.db")
    init_db(db)
    seed_if_empty(db)
    urgent = unalerted_urgent_items(limit=10, db_path=db)
    assert len(urgent) >= 1
    mark_alerted([urgent[0]["id"]], db)
    remaining = unalerted_urgent_items(limit=10, db_path=db)
    assert all(item["id"] != urgent[0]["id"] for item in remaining)


def test_stats(tmp_path):
    db = str(tmp_path / "feed.db")
    init_db(db)
    seed_if_empty(db)
    s = stats(db)
    assert s["total"] > 0
    assert "by_tag" in s
    assert "by_severity" in s


def test_query_feed_orders_mixed_offsets_by_real_time(tmp_path):
    """Timestamps are normalized to UTC before they are stored as text."""
    db = str(tmp_path / "feed.db")
    init_db(db)
    older_utc = datetime(2025, 1, 1, 12, 0, tzinfo=timezone.utc)
    newer_shifted = datetime(2025, 1, 1, 10, 0, tzinfo=timezone(timedelta(hours=-4)))  # 14:00 UTC
    upsert_items(
        [
            make_item("old", "Older advisory", published=older_utc),
            make_item("new", "Newer advisory", published=newer_shifted),
        ],
        db,
    )
    rows = query_feed(limit=10, db_path=db)
    assert [row["id"] for row in rows] == ["new", "old"]
    assert rows[0]["published"].endswith("+00:00")


def test_patch_status_roundtrip(tmp_path):
    db = str(tmp_path / "feed.db")
    init_db(db)
    seed_if_empty(db)
    upsert_items([make_item("p", "Patched advisory", {"linux"}, ["CVE-2024-0003"], "high", False, "fixed")], db)
    rows = query_feed(limit=50, db_path=db)
    row = next(r for r in rows if r["id"] == "p")
    assert row["patch_status"] == "fixed"
