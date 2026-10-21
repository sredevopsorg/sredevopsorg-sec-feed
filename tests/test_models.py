from datetime import datetime, timezone

import app.fetcher as fetcher
import app.models as models
import app.store as store
from app import sqlite_store


def test_feeditem_lives_in_models():
    """FeedItem and serialization moved to models (fetcher re-exports them)."""
    assert models.FeedItem is fetcher.FeedItem
    assert models.item_to_dict is fetcher.item_to_dict
    assert models._sample_items is fetcher._sample_items
    assert models._time_ago is fetcher._time_ago


def _item(published):
    return models.FeedItem(
        id="a",
        title="t",
        summary="",
        url="https://example.com/a",
        source="s",
        source_url="https://example.com/feed",
        published=published,
    )


def test_item_to_dict_keeps_unknown_publication_time_unknown():
    """A dateless item must not be reported as published 'now'."""
    data = models.item_to_dict(_item(None), now=datetime(2025, 1, 1, 12, tzinfo=timezone.utc))
    assert data["published"] is None
    assert data["time_ago"] is None


def test_item_to_dict_serializes_a_known_publication_time():
    data = models.item_to_dict(
        _item(datetime(2025, 1, 1, 11, tzinfo=timezone.utc)),
        now=datetime(2025, 1, 1, 12, tzinfo=timezone.utc),
    )
    assert data["published"] == "2025-01-01T11:00:00+00:00"
    assert data["time_ago"] == "1 hour"


def test_store_selects_sqlite_without_database_url():
    """Without DATABASE_URL the facade selects the SQLite adapter."""
    assert store._backend is sqlite_store


def test_store_exposes_full_interface():
    for name in (
        "init_db",
        "seed_if_empty",
        "upsert_items",
        "query_feed",
        "search_feed",
        "stats",
        "unalerted_urgent_items",
        "mark_alerted",
        "get_source_cursor",
        "set_source_cursor",
        "get_source_state",
        "set_source_state",
        "prune_items",
        "close",
    ):
        assert callable(getattr(store, name)), name
