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
    ):
        assert callable(getattr(store, name)), name
