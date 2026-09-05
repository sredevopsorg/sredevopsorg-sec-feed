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


@dataclass(frozen=True)
class Settings:
    # Storage
    database_url: str | None
    sqlite_db_path: str
    # Search
    opensearch_url: str | None
    opensearch_index: str
    # HTTP / CORS
    cors_origins: tuple[str, ...]
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
            opensearch_url=env.get("OPENSEARCH_URL") or None,
            opensearch_index=env.get("OPENSEARCH_INDEX", "security-feed"),
            cors_origins=_csv(env.get("CORS_ORIGINS", "*")),
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
