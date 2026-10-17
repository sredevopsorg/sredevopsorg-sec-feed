"""Storage-layer exceptions shared by the adapters and the API.

Kept in a tiny module (rather than in ``store.py``) so adapters can import them
without importing the storage facade that selects a backend.
"""

from __future__ import annotations


class StoreUnavailable(RuntimeError):
    """The database cannot be reached right now; the API should answer 503."""


class SchemaNotMigrated(RuntimeError):
    """The database schema is missing or behind the checked-in migrations."""
