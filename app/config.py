"""Centralised application configuration.

Every environment variable is read here, documented, and given a single
default. Modules should consume ``Settings`` instead of calling
``os.environ.get`` directly (see ADR-0002).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

_DEFAULT_SQLITE_DB = str(Path(__file__).resolve().parent.parent / "data" / "feed.db")

# Hosts that are unambiguously local (Docker Compose service names, loopback).
# A single-label hostname (no dot) is also treated as local, so an internal
# service such as `postgres` or `db` keeps working with `sslmode=prefer`.
_LOCAL_DB_HOSTS = {"localhost", "127.0.0.1", "::1", "postgres", "db", "database"}


def _csv(value: str | None) -> tuple[str, ...]:
    """Split a comma-separated env value into a tuple of trimmed, non-empty strings."""
    if not value:
        return ()
    return tuple(v.strip() for v in value.split(",") if v.strip())


def _int(value: str | None, default: int) -> int:
    try:
        return int(value) if value is not None else default
    except ValueError:
        return default


def _float(value: str | None, default: float) -> float:
    """Parse a float env value, falling back to the default when invalid."""
    try:
        return float(value) if value not in (None, "") else default
    except ValueError:
        return default


def _is_local_host(host: str | None) -> bool:
    """True for loopback and single-label service names; False for remote hosts."""
    if not host:
        return True
    normalized = host.strip().lower()
    if normalized.startswith("[") and normalized.endswith("]"):
        normalized = normalized[1:-1]
    if normalized in _LOCAL_DB_HOSTS:
        return True
    return "." not in normalized


def _validate_db_endpoint(url: str | None, sslmode: str) -> None:
    """Fail closed when a remote database would be reachable over plaintext.

    libpq defaults to ``prefer``, silently falling back to an unencrypted
    connection if TLS fails. For a hosted database (Supabase) that is a
    downgrade we never want, so a remote host must use at least ``require``
    (``verify-full`` plus ``DB_SSLROOTCERT`` is better). Local service names
    keep working with ``prefer``.
    """
    if not url or sslmode != "prefer":
        return
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return
    if not _is_local_host(host):
        raise ValueError(
            f"DB_SSLMODE=prefer would allow plaintext to remote database host {host!r}; "
            "set DB_SSLMODE=require (or verify-full with DB_SSLROOTCERT)"
        )


def _opt_int(value: str | None) -> int | None:
    """Parse an optional int: empty/None/invalid -> None."""
    if value is None or not value.strip():
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _bool(value: str | None, default: bool = False) -> bool:
    """Parse a boolean env value ("1"/"true"/"yes"/"on" are true)."""
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    # Storage
    database_url: str | None
    # Privileged DSN used only by ``python -m app.migrate`` (never by the API).
    admin_database_url: str | None
    sqlite_db_path: str
    # Postgres connection pool (Postgres/Supabase backend only)
    db_pool_min_size: int
    db_pool_max_size: int
    db_pool_timeout: float
    db_pool_max_idle: float
    db_pool_max_lifetime: float
    db_prepare_threshold: int | None
    db_connect_timeout: int
    db_sslmode: str
    db_sslrootcert: str | None
    db_application_name: str
    db_statement_timeout_ms: int
    db_idle_tx_timeout_ms: int
    db_lock_timeout_ms: int
    # Search
    opensearch_url: str | None
    opensearch_index: str
    # HTTP / CORS
    cors_origins: tuple[str, ...]
    # Rate limiting / SSE fan-out
    rate_limit_per_minute: int
    rate_limit_trust_proxy: bool
    max_sse_subscribers: int
    # Logging
    log_level: str
    # Sources: GitHub token (GHSA) and NVD/KEV recent windows
    github_token: str | None
    nvd_window_days: int
    kev_source_days: int
    # Refresh cadence, retention, and enrichment batch caps
    feed_cache_ttl: int
    retention_days: int
    epss_max_cves: int
    osv_max_cves_per_run: int
    # Alerting (all opt-in)
    discord_webhook_url: str | None
    slack_webhook_url: str | None
    alert_email_to: str | None
    smtp_host: str | None
    smtp_port: int
    smtp_user: str | None
    smtp_password: str | None
    alert_from: str

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None) -> "Settings":
        env = os.environ if environ is None else environ

        database_url = env.get("DATABASE_URL") or None
        admin_database_url = env.get("ADMIN_DATABASE_URL") or None
        db_sslmode = env.get("DB_SSLMODE") or "prefer"
        db_sslrootcert = env.get("DB_SSLROOTCERT") or None
        db_pool_min_size = _int(env.get("DB_POOL_MIN_SIZE"), 1)
        db_pool_max_size = _int(env.get("DB_POOL_MAX_SIZE"), 4)

        if db_pool_min_size < 0 or db_pool_max_size < 1 or db_pool_min_size > db_pool_max_size:
            raise ValueError(
                "DB_POOL_MIN_SIZE/DB_POOL_MAX_SIZE are invalid: require "
                "0 <= min <= max and max >= 1"
            )
        if db_sslrootcert and not Path(db_sslrootcert).is_file():
            raise ValueError(f"DB_SSLROOTCERT does not exist: {db_sslrootcert}")

        # Check both DSNs: the admin DSN is used by migrations and deserves the
        # same encryption floor as the runtime connection.
        _validate_db_endpoint(database_url, db_sslmode)
        _validate_db_endpoint(admin_database_url, db_sslmode)

        return cls(
            database_url=database_url,
            admin_database_url=admin_database_url,
            sqlite_db_path=env.get("SECURITY_FEED_DB", _DEFAULT_SQLITE_DB),
            db_pool_min_size=db_pool_min_size,
            db_pool_max_size=db_pool_max_size,
            db_pool_timeout=max(0.0, _float(env.get("DB_POOL_TIMEOUT"), 30.0)),
            db_pool_max_idle=max(0.0, _float(env.get("DB_POOL_MAX_IDLE"), 600.0)),
            db_pool_max_lifetime=max(0.0, _float(env.get("DB_POOL_MAX_LIFETIME"), 3600.0)),
            db_prepare_threshold=_opt_int(env.get("DB_PREPARE_THRESHOLD")),
            db_connect_timeout=_int(env.get("DB_CONNECT_TIMEOUT"), 10),
            db_sslmode=db_sslmode,
            db_sslrootcert=db_sslrootcert,
            db_application_name=env.get("DB_APPLICATION_NAME") or "security-feed",
            db_statement_timeout_ms=max(0, _int(env.get("DB_STATEMENT_TIMEOUT_MS"), 15000)),
            db_idle_tx_timeout_ms=max(0, _int(env.get("DB_IDLE_TX_TIMEOUT_MS"), 30000)),
            db_lock_timeout_ms=max(0, _int(env.get("DB_LOCK_TIMEOUT_MS"), 5000)),
            opensearch_url=env.get("OPENSEARCH_URL") or None,
            opensearch_index=env.get("OPENSEARCH_INDEX", "security-feed"),
            # Fail closed: deny cross-origin requests unless an allow-list is
            # configured explicitly (the bundled frontend is same-origin).
            cors_origins=_csv(env.get("CORS_ORIGINS")),
            rate_limit_per_minute=_int(env.get("RATE_LIMIT_PER_MINUTE"), 120),
            rate_limit_trust_proxy=_bool(env.get("RATE_LIMIT_TRUST_PROXY"), True),
            max_sse_subscribers=_int(env.get("MAX_SSE_SUBSCRIBERS"), 100),
            log_level=env.get("LOG_LEVEL", "INFO"),
            github_token=env.get("GITHUB_TOKEN") or None,
            nvd_window_days=_int(env.get("NVD_WINDOW_DAYS"), 7),
            kev_source_days=_int(env.get("KEV_SOURCE_DAYS"), 7),
            feed_cache_ttl=max(30, _int(env.get("FEED_CACHE_TTL"), 600)),
            retention_days=max(0, _int(env.get("RETENTION_DAYS"), 180)),
            epss_max_cves=max(0, _int(env.get("EPSS_MAX_CVES"), 200)),
            osv_max_cves_per_run=max(0, _int(env.get("OSV_MAX_CVES_PER_RUN"), 50)),
            discord_webhook_url=env.get("DISCORD_WEBHOOK_URL") or None,
            slack_webhook_url=env.get("SLACK_WEBHOOK_URL") or None,
            alert_email_to=env.get("ALERT_EMAIL_TO") or None,
            smtp_host=env.get("SMTP_HOST") or None,
            smtp_port=_int(env.get("SMTP_PORT"), 587),
            smtp_user=env.get("SMTP_USER") or None,
            smtp_password=env.get("SMTP_PASSWORD") or None,
            alert_from=env.get("ALERT_FROM", "security-feed@example.com"),
        )


settings = Settings.from_env()
