"""Storage facade.

Selects a single backend once (PostgreSQL when ``DATABASE_URL`` is set,
SQLite otherwise) and exposes a stable API to the rest of the app. Callers
depend only on this module — never on a concrete backend (ADR-0003).
"""

from __future__ import annotations

from typing import Any, Protocol

from .config import settings
from .models import FeedItem

DB_PATH = settings.sqlite_db_path


class Storage(Protocol):
    """The storage port implemented by ``sqlite_store`` and ``postgres_store``."""

    def init_db(self, db_path: str = DB_PATH) -> None: ...

    def seed_if_empty(self, db_path: str = DB_PATH) -> int: ...

    def upsert_items(self, items: list[FeedItem], db_path: str = DB_PATH) -> int: ...

    def query_feed(self, tag: str | None = None, severity: str | None = None, limit: int = 50, db_path: str = DB_PATH) -> list[dict[str, Any]]: ...

    def search_feed(self, q: str, tag: str | None = None, severity: str | None = None, limit: int = 50, db_path: str = DB_PATH) -> list[dict[str, Any]]: ...

    def stats(self, db_path: str = DB_PATH) -> dict[str, Any]: ...

    def unalerted_urgent_items(self, limit: int = 20, db_path: str = DB_PATH) -> list[dict[str, Any]]: ...

    def mark_alerted(self, item_ids: list[str], db_path: str = DB_PATH) -> None: ...

    def get_source_cursor(self, source_id: str, db_path: str = DB_PATH) -> str | None: ...

    def set_source_cursor(self, source_id: str, cursor: str, db_path: str = DB_PATH) -> None: ...


if settings.database_url:
    from . import postgres_store as _backend  # noqa: E402
else:
    from . import sqlite_store as _backend  # noqa: E402


def init_db(db_path: str = DB_PATH) -> None:
    return _backend.init_db(db_path)


def seed_if_empty(db_path: str = DB_PATH) -> int:
    return _backend.seed_if_empty(db_path)


def upsert_items(items: list[FeedItem], db_path: str = DB_PATH) -> int:
    return _backend.upsert_items(items, db_path)


def query_feed(tag: str | None = None, severity: str | None = None, limit: int = 50, db_path: str = DB_PATH) -> list[dict[str, Any]]:
    return _backend.query_feed(tag, severity, limit, db_path)


def search_feed(q: str, tag: str | None = None, severity: str | None = None, limit: int = 50, db_path: str = DB_PATH) -> list[dict[str, Any]]:
    return _backend.search_feed(q, tag, severity, limit, db_path)


def stats(db_path: str = DB_PATH) -> dict[str, Any]:
    return _backend.stats(db_path)


def unalerted_urgent_items(limit: int = 20, db_path: str = DB_PATH) -> list[dict[str, Any]]:
    return _backend.unalerted_urgent_items(limit, db_path)


def mark_alerted(item_ids: list[str], db_path: str = DB_PATH) -> None:
    return _backend.mark_alerted(item_ids, db_path)


def get_source_cursor(source_id: str, db_path: str = DB_PATH) -> str | None:
    return _backend.get_source_cursor(source_id, db_path)


def set_source_cursor(source_id: str, cursor: str, db_path: str = DB_PATH) -> None:
    return _backend.set_source_cursor(source_id, cursor, db_path)
