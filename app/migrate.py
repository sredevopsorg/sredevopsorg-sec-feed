"""Versioned schema migrations for the PostgreSQL backend.

The API never creates schema at runtime: ``postgres_store.init_db()`` only
verifies that the latest checked-in migration has been applied. Schema changes
are applied by a one-shot job before the API starts:

    python -m app.migrate upgrade           # apply pending migrations
    python -m app.migrate check             # exit 1 if the DB is behind
    python -m app.migrate bootstrap-role    # set the feed_app password

The admin connection comes from ``ADMIN_DATABASE_URL`` (or ``--url``). The
runtime ``DATABASE_URL`` is a DML-only role and intentionally not accepted for
DDL.
"""

from __future__ import annotations

import argparse
import logging
import os
import time
from pathlib import Path
from typing import Any
import psycopg
from psycopg import sql
from psycopg.rows import dict_row

from . import config

logger = logging.getLogger(__name__)

MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "migrations"
TRACKING_TABLE = "feed_schema_migrations"
# Session-level advisory lock: one migration runner at a time, across replicas.
ADVISORY_LOCK_KEY = 0x5ECF33D
DEFAULT_WAIT_SECONDS = 60
MIGRATION_STATEMENT_TIMEOUT_MS = 600_000
RUNTIME_ROLE = "feed_app"
MIN_PASSWORD_LENGTH = 16

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "postgres", "db", "database"}


class MigrationError(RuntimeError):
    """A migration or role bootstrap could not be completed."""


def migration_files() -> list[tuple[str, Path]]:
    """Return ``[(version, path)]`` for every migration, sorted by version."""
    files = sorted(MIGRATIONS_DIR.glob("*.sql"))
    if not files:
        raise MigrationError(f"no migrations found in {MIGRATIONS_DIR}")
    result: list[tuple[str, Path]] = []
    for path in files:
        version = path.stem.split("_", 1)[0]
        if not version.isdigit():
            raise MigrationError(f"migration file must start with a numeric version: {path.name}")
        result.append((version, path))
    return result


def latest_version() -> str:
    """The newest checked-in migration version (used by the startup check)."""
    return migration_files()[-1][0]


def _resolve_url(cli_url: str | None) -> str:
    url = cli_url or os.environ.get("ADMIN_DATABASE_URL") or ""
    if not url:
        raise MigrationError(
            "ADMIN_DATABASE_URL is not set (or pass --url); the runtime "
            "DATABASE_URL is DML-only and is intentionally not used for DDL"
        )
    try:
        config._validate_db_endpoint(url, config.settings.db_sslmode)
    except ValueError as exc:
        raise MigrationError(str(exc)) from exc
    return url


def _connect(url: str, wait_seconds: int = DEFAULT_WAIT_SECONDS) -> psycopg.Connection:
    """Connect as the admin role, retrying while the database starts up."""
    deadline = time.monotonic() + max(0, wait_seconds)
    last_error: Exception | None = None
    while True:
        try:
            kwargs: dict[str, Any] = {
                "row_factory": dict_row,
                "prepare_threshold": None,  # migration files contain multiple statements
                "connect_timeout": 10,
                "sslmode": config.settings.db_sslmode,
            }
            if config.settings.db_sslrootcert:
                kwargs["sslrootcert"] = config.settings.db_sslrootcert
            return psycopg.connect(url, **kwargs)
        except psycopg.OperationalError as exc:
            last_error = exc
            if time.monotonic() >= deadline:
                raise MigrationError(f"database is not reachable: {exc}") from exc
            logger.warning("database not ready (%s); retrying", str(exc).splitlines()[0][:160])
            time.sleep(2)
    # Unreachable, kept for type checkers.
    raise MigrationError(str(last_error))


def _ensure_tracking_table(conn: psycopg.Connection) -> None:
    conn.execute(
        sql.SQL(
            "CREATE TABLE IF NOT EXISTS {} ("
            "version TEXT PRIMARY KEY, "
            "applied_at TIMESTAMPTZ NOT NULL DEFAULT now())"
        ).format(sql.Identifier(TRACKING_TABLE))
    )
    conn.commit()


def _applied_versions(conn: psycopg.Connection) -> set[str]:
    exists = conn.execute("SELECT to_regclass(%s) AS t", (f"public.{TRACKING_TABLE}",)).fetchone()
    if not exists or not exists["t"]:
        return set()
    rows = conn.execute(
        sql.SQL("SELECT version FROM {}").format(sql.Identifier(TRACKING_TABLE))
    ).fetchall()
    return {row["version"] for row in rows}


def pending_versions(conn: psycopg.Connection) -> list[str]:
    applied = _applied_versions(conn)
    return [version for version, _ in migration_files() if version not in applied]


def apply_pending(
    url: str,
    wait_seconds: int = DEFAULT_WAIT_SECONDS,
) -> list[str]:
    """Apply every pending migration. Returns the versions applied by this call."""
    try:
        config._validate_db_endpoint(url, config.settings.db_sslmode)
    except ValueError as exc:
        raise MigrationError(str(exc)) from exc
    conn = _connect(url, wait_seconds)
    acquired = False
    try:
        conn.execute(f"SET statement_timeout = {int(MIGRATION_STATEMENT_TIMEOUT_MS)}")
        conn.commit()

        acquired = bool(
            conn.execute("SELECT pg_try_advisory_lock(%s) AS ok", (ADVISORY_LOCK_KEY,)).fetchone()["ok"]
        )
        conn.commit()
        if not acquired:
            raise MigrationError("another migration runner holds the advisory lock; try again")

        _ensure_tracking_table(conn)
        pending = pending_versions(conn)
        # Close the read transaction opened by pending_versions() so the first
        # ``conn.transaction()`` below is the outermost BEGIN (otherwise it
        # silently degrades to a SAVEPOINT and the DDL is rolled back on close).
        conn.commit()
        if not pending:
            logger.info("database schema is up to date (%s)", latest_version())
            return []

        for version, path in migration_files():
            if version not in pending:
                continue
            logger.info("applying %s (%s)", version, path.name)
            text = path.read_text(encoding="utf-8")
            with conn.transaction():
                conn.execute(text)
                conn.execute(
                    sql.SQL("INSERT INTO {} (version) VALUES (%s)").format(sql.Identifier(TRACKING_TABLE)),
                    (version,),
                )
        logger.info("applied %d migration(s)", len(pending))
        return pending
    finally:
        if acquired:
            try:
                conn.execute("SELECT pg_advisory_unlock(%s)", (ADVISORY_LOCK_KEY,))
                conn.commit()
            except Exception:  # pragma: no cover - best effort on a broken connection
                logger.warning("could not release the migration advisory lock")
        conn.close()


def check(url: str | None = None, wait_seconds: int = 10) -> list[str]:
    """Return pending migration versions (empty when the database is current)."""
    conn = _connect(_resolve_url(url), wait_seconds)
    try:
        return pending_versions(conn)
    finally:
        conn.close()


def bootstrap_role(url: str | None = None, password: str | None = None, wait_seconds: int = 10) -> None:
    """Give the runtime role LOGIN and a password (never stored in a migration)."""
    password = password or os.environ.get("FEED_APP_PASSWORD") or ""
    if len(password) < MIN_PASSWORD_LENGTH:
        raise MigrationError(
            f"FEED_APP_PASSWORD must be at least {MIN_PASSWORD_LENGTH} characters "
            "(generate one with `python -c \"import secrets; print(secrets.token_urlsafe(32))\"`)"
        )
    conn = _connect(_resolve_url(url), wait_seconds)
    try:
        exists = conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (RUNTIME_ROLE,)).fetchone()
        if not exists:
            raise MigrationError(
                f"{RUNTIME_ROLE} does not exist; run `python -m app.migrate upgrade` first"
            )
        conn.execute(
            sql.SQL("ALTER ROLE {} WITH LOGIN CONNECTION LIMIT 10 PASSWORD {}").format(
                sql.Identifier(RUNTIME_ROLE),
                sql.Literal(password),
            )
        )
        conn.commit()
    finally:
        conn.close()


def _build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--url", default=None, help="admin DSN (default: ADMIN_DATABASE_URL)")
    common.add_argument("--wait", type=int, default=DEFAULT_WAIT_SECONDS, help="seconds to wait for the database")

    parser = argparse.ArgumentParser(prog="python -m app.migrate", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("upgrade", parents=[common], help="apply pending migrations")
    sub.add_parser("check", parents=[common], help="exit non-zero when the schema is behind")
    bootstrap = sub.add_parser("bootstrap-role", parents=[common], help="set the feed_app password")
    bootstrap.add_argument("--password-env", default="FEED_APP_PASSWORD")
    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "upgrade":
            applied = apply_pending(_resolve_url(args.url), wait_seconds=args.wait)
            print(f"applied: {', '.join(applied) if applied else 'none (already current)'}")
            return 0
        if args.command == "check":
            pending = check(args.url, wait_seconds=args.wait)
            if pending:
                print(f"pending migrations: {', '.join(pending)}")
                return 1
            print(f"schema is current ({latest_version()})")
            return 0
        if args.command == "bootstrap-role":
            password = os.environ.get(args.password_env)
            bootstrap_role(args.url, password=password, wait_seconds=args.wait)
            print(f"{RUNTIME_ROLE} password updated")
            return 0
    except MigrationError as exc:
        print(f"error: {exc}")
        return 1
    return 2


if __name__ == "__main__":  # pragma: no cover - exercised via subprocess in CI
    raise SystemExit(main())
