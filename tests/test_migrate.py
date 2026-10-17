"""Integration tests for versioned migrations and the DML-only runtime role.

Like ``test_postgres_store.py``, these require ``TEST_DATABASE_URL`` pointing at
a **local** Postgres (CI provides one). A remote DSN is refused because the
migration creates roles and applies grants.
"""

from __future__ import annotations

import os
import secrets
from urllib.parse import quote, urlsplit

import psycopg
import pytest
from psycopg.rows import dict_row

from app import config, migrate
from app.config import Settings

PG_DSN = os.environ.get("TEST_DATABASE_URL")
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "postgres", "db", "database"}


def _is_local_dsn(dsn: str | None) -> bool:
    if not dsn:
        return False
    host = (urlsplit(dsn).hostname or "").lower()
    return host in _LOCAL_HOSTS or "." not in host


pytestmark = pytest.mark.skipif(
    not PG_DSN or not _is_local_dsn(PG_DSN),
    reason="TEST_DATABASE_URL must point at a local database",
)


@pytest.fixture()
def migrated(monkeypatch):
    monkeypatch.setattr(
        config,
        "settings",
        Settings.from_env({"DATABASE_URL": PG_DSN, "DB_SSLMODE": "prefer"}),
    )
    migrate.apply_pending(PG_DSN, wait_seconds=30)
    yield


def test_upgrade_is_idempotent(migrated):
    assert migrate.apply_pending(PG_DSN, wait_seconds=10) == []
    assert migrate.check(PG_DSN, wait_seconds=10) == []


def test_schema_and_least_privilege_grants(migrated):
    with psycopg.connect(
        PG_DSN, sslmode="prefer", connect_timeout=5, row_factory=dict_row
    ) as conn:
        tables = {
            row["tablename"]
            for row in conn.execute("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
        }
        assert {"feed_items", "alerted_items", "source_cursors", "feed_schema_migrations"} <= tables

        # The runtime role can do DML...
        assert conn.execute(
            "SELECT has_table_privilege('feed_app', 'feed_items', 'SELECT') AS ok"
        ).fetchone()["ok"] is True
        assert conn.execute(
            "SELECT has_table_privilege('feed_app', 'feed_items', 'INSERT') AS ok"
        ).fetchone()["ok"] is True
        # ...but not TRUNCATE (not covered by RLS) or DDL.
        assert conn.execute(
            "SELECT has_table_privilege('feed_app', 'feed_items', 'TRUNCATE') AS ok"
        ).fetchone()["ok"] is False
        assert conn.execute(
            "SELECT has_schema_privilege('feed_app', 'public', 'CREATE') AS ok"
        ).fetchone()["ok"] is False

        # Supabase's Data API roles must hold nothing on the app tables.
        for role in ("anon", "authenticated"):
            exists = conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone()
            if exists:
                assert conn.execute(
                    "SELECT has_table_privilege(%s, 'feed_items', 'SELECT') AS ok", (role,)
                ).fetchone()["ok"] is False


def test_bootstrap_role_allows_login_but_not_ddl(migrated):
    password = secrets.token_urlsafe(24)
    migrate.bootstrap_role(PG_DSN, password=password)

    parts = urlsplit(PG_DSN)
    runtime_dsn = (
        f"postgresql://feed_app:{quote(password, safe='')}"
        f"@{parts.hostname}:{parts.port or 5432}{parts.path}"
    )
    conn = psycopg.connect(runtime_dsn, sslmode="prefer", connect_timeout=5, row_factory=dict_row)
    try:
        assert conn.execute("SELECT count(*) AS n FROM feed_items").fetchone()["n"] >= 0
        # DML is allowed; roll it back so the test leaves no row behind.
        conn.execute(
            "INSERT INTO source_cursors (source_id, cursor, updated_at) "
            "VALUES ('migrate-test', 'x', now())"
        )
        conn.rollback()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("CREATE TABLE should_not_exist (id int)")
        conn.rollback()
    finally:
        conn.close()


def test_bootstrap_role_rejects_short_password(migrated):
    with pytest.raises(migrate.MigrationError):
        migrate.bootstrap_role(PG_DSN, password="too-short")
