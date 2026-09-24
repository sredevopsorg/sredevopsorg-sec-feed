"""Centralised application configuration.

Every environment variable is read here, documented, and given a single
default. Modules should consume ``Settings`` instead of calling
``os.environ.get`` directly (see ADR-0002).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

_DEFAULT_SQLITE_DB = str(Path(__file__).resolve().parent.parent / "data" / "feed.db")


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
    sqlite_db_path: str
    # Postgres connection pool (Postgres/Supabase backend only)
    db_pool_min_size: int
    db_pool_max_size: int
    db_prepare_threshold: int | None
    db_connect_timeout: int
    db_sslmode: str
    db_application_name: str
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
    # OpenSSF Malicious Packages source
    github_token: str | None
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
        return cls(
            database_url=env.get("DATABASE_URL") or None,
            sqlite_db_path=env.get("SECURITY_FEED_DB", _DEFAULT_SQLITE_DB),
            db_pool_min_size=_int(env.get("DB_POOL_MIN_SIZE"), 1),
            db_pool_max_size=_int(env.get("DB_POOL_MAX_SIZE"), 4),
            db_prepare_threshold=_opt_int(env.get("DB_PREPARE_THRESHOLD")),
            db_connect_timeout=_int(env.get("DB_CONNECT_TIMEOUT"), 10),
            db_sslmode=env.get("DB_SSLMODE") or "prefer",
            db_application_name=env.get("DB_APPLICATION_NAME") or "security-feed",
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
