"""Alerting for urgent feed items.

Channels are opt-in via environment variables:

- DISCORD_WEBHOOK_URL — send urgent items to Discord (primary channel)
- SLACK_WEBHOOK_URL — send urgent items to Slack
- ALERT_EMAIL_TO, SMTP_HOST — send urgent items via email (SMTP)
- If none are configured, urgent items are logged only.
"""

from __future__ import annotations

import asyncio
import json
import logging
import smtplib
from email.message import EmailMessage

import httpx

from . import store
from .config import settings

logger = logging.getLogger(__name__)

DISCORD_WEBHOOK_URL = settings.discord_webhook_url
SLACK_WEBHOOK_URL = settings.slack_webhook_url
ALERT_EMAIL_TO = settings.alert_email_to
SMTP_HOST = settings.smtp_host
SMTP_PORT = settings.smtp_port
SMTP_USER = settings.smtp_user
SMTP_PASSWORD = settings.smtp_password
ALERT_FROM = settings.alert_from

MAX_ALERTS_PER_RUN = 10


def _format_item(item: dict) -> str:
    tags = " ".join(f"`{t}`" for t in item.get("tags", []))
    cves = " ".join(item.get("cves", []))
    severity = item.get("severity", "unknown").upper()
    return (
        f"*[{severity}] {item.get('title')}*\n"
        f"{item.get('summary', '')[:300]}\n"
        f"Source: {item.get('source')} | {item.get('time_ago')}\n"
        f"Tags: {tags} | CVEs: {cves}\n"
        f"<{item.get('url')}>"
    )


async def _send_slack(webhook_url: str, text: str) -> None:
    async with httpx.AsyncClient(timeout=8.0) as client:
        resp = await client.post(webhook_url, json={"text": text})
        resp.raise_for_status()


_SEVERITY_COLORS = {
    "critical": 0xE53935,
    "high": 0xFB8C00,
    "medium": 0xFDD835,
    "low": 0x1E88E5,
    "unknown": 0x9E9E9E,
}


def _discord_payload(item: dict) -> dict:
    """Build the JSON payload for a Discord webhook (one embed per item)."""
    severity = (item.get("severity") or "unknown").lower()
    cves = ", ".join(item.get("cves") or []) or "—"
    title = f"[{severity.upper()}] {item.get('title') or ''}"[:256]
    return {
        "username": "Security Feed",
        "embeds": [
            {
                "title": title,
                "description": (item.get("summary") or "")[:1800] or "—",
                "url": item.get("url"),
                "color": _SEVERITY_COLORS.get(severity, 0x9E9E9E),
                "fields": [
                    {"name": "Source", "value": f"{item.get('source')} · {item.get('time_ago')}", "inline": True},
                    {"name": "CVEs", "value": cves[:1024], "inline": True},
                ],
                "footer": {"text": "Security Intelligence Live Feed"},
            }
        ],
    }


async def _send_discord(webhook_url: str, item: dict) -> None:
    async with httpx.AsyncClient(timeout=8.0) as client:
        resp = await client.post(webhook_url, json=_discord_payload(item))
        resp.raise_for_status()


def _send_email(to: str, subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["From"] = ALERT_FROM
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=8) as smtp:
        smtp.starttls()
        if SMTP_USER:
            smtp.login(SMTP_USER, SMTP_PASSWORD)
        smtp.send_message(msg)


async def send_urgent_alerts() -> list[str]:
    """Send alerts for new urgent items. Returns the list of alerted item ids."""
    try:
        items = await asyncio.to_thread(store.unalerted_urgent_items, MAX_ALERTS_PER_RUN)
    except Exception:
        logger.exception("Could not query urgent items for alerting")
        return []

    alerted: list[str] = []
    for item in items:
        subject = f"[security-feed] {item.get('severity', 'unknown').upper()} - {item.get('title', '')[:80]}"
        body = _format_item(item)
        try:
            if DISCORD_WEBHOOK_URL:
                await _send_discord(DISCORD_WEBHOOK_URL, item)
            if SLACK_WEBHOOK_URL:
                await _send_slack(SLACK_WEBHOOK_URL, body)
            if ALERT_EMAIL_TO and SMTP_HOST:
                await asyncio.to_thread(_send_email, ALERT_EMAIL_TO, subject, body)
            if not DISCORD_WEBHOOK_URL and not SLACK_WEBHOOK_URL and not (ALERT_EMAIL_TO and SMTP_HOST):
                logger.warning("URGENT ALERT: %s", subject)
            alerted.append(item["id"])
        except Exception:
            logger.exception("Alert delivery failed for item %s", item["id"])

    if alerted:
        try:
            await asyncio.to_thread(store.mark_alerted, alerted)
        except Exception:
            logger.exception("Could not mark items as alerted")
    return alerted
