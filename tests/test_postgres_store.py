"""Integration tests for the PostgreSQL storage adapter.

These run only when ``TEST_DATABASE_URL`` points at a real Postgres (CI provides
a ``postgres:16-alpine`` service). They exercise the adapter directly, bypassing
the ``store`` facade so the backend selection there is not affected.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

from app import config, postgres_store
from app.config import Settings
from app.fetcher import FeedItem

POSTGRES_DSN = os.environ.get("TEST_DATABASE_URL")

pytestmark = pytest.mark.skipif(not POSTGRES_DSN, reason="TEST_DATABASE_URL not set")


def make_item(
    id: str = "a",
    title: str = "Test advisory",
    tags: set[str] = frozenset({"linux"}),
    cves: list[str] | None = None,
    severity: str = "high",
    urgent: bool = False,
    published: datetime | None = None,
) -> FeedItem:
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
    )


@pytest.fixture()
def pg(monkeypatch):
    monkeypatch.setattr(config, "settings", Settings.from_env({"DATABASE_URL": POSTGRES_DSN}))
    postgres_store._reset_pool()
    postgres_store.init_db()
    with postgres_store._connection() as conn:
        conn.execute("TRUNCATE TABLE feed_items, alerted_items, source_cursors")
    yield
    postgres_store._reset_pool()


def test_init_db_is_idempotent(pg):
    # The fixture already called init_db once; a second call must not raise.
    postgres_store.init_db()


def test_seed_then_hide_samples_once_live_exists(pg):
    assert postgres_store.seed_if_empty() > 0
    rows = postgres_store.query_feed(limit=50)
    assert rows
    assert all(r["is_sample"] for r in rows)

    postgres_store.upsert_items([make_item("live", "Live advisory")])
    rows = postgres_store.query_feed(limit=50)
    assert all(not r["is_sample"] for r in rows)
    assert {r["id"] for r in rows} == {"live"}


def test_upsert_is_idempotent(pg):
    item = make_item("u", "First title")
    assert postgres_store.upsert_items([item]) == 1
    updated = make_item("u", "Second title")
    assert postgres_store.upsert_items([updated]) == 1
    rows = postgres_store.query_feed(limit=10)
    assert [r["title"] for r in rows] == ["Second title"]


def test_query_feed_filters(pg):
    postgres_store.upsert_items([
        make_item("k", "K8s advisory", {"kubernetes"}, severity="critical", urgent=True),
        make_item("l", "Linux advisory", {"linux"}, severity="medium"),
    ])
    rows = postgres_store.query_feed(tag="kubernetes", severity="critical", limit=10)
    assert [r["id"] for r in rows] == ["k"]


def test_search_feed(pg):
    postgres_store.seed_if_empty()
    rows = postgres_store.search_feed("runc", limit=10)
    assert rows, "expected at least one runc match in the sample data"


def test_stats_shape(pg):
    postgres_store.seed_if_empty()
    s = postgres_store.stats()
    assert s["total"] > 0
    assert s["live"] == 0  # only samples seeded
    assert s["sample"] == s["total"]
    assert isinstance(s["by_tag"], dict)
    assert isinstance(s["by_severity"], dict)
    assert "latest_seen" in s


def test_alerted_roundtrip(pg):
    postgres_store.seed_if_empty()
    urgent = postgres_store.unalerted_urgent_items(limit=10)
    assert urgent
    postgres_store.mark_alerted([u["id"] for u in urgent])
    assert postgres_store.unalerted_urgent_items(limit=10) == []


def test_source_cursor_roundtrip(pg):
    assert postgres_store.get_source_cursor("ossf") is None
    postgres_store.set_source_cursor("ossf", "cursor-123")
    assert postgres_store.get_source_cursor("ossf") == "cursor-123"


def test_pool_kwargs(pg):
    pool = postgres_store._ensure_pool()
    assert pool.kwargs["prepare_threshold"] is None
    assert pool.kwargs["connect_timeout"] == 10
    assert pool.kwargs["application_name"] == "security-feed"
