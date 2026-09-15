"""Outbound HTTP policy tests (AGENTS invariant 5)."""

import asyncio
import pathlib

import httpx

from app import http_client


def _close(client: httpx.AsyncClient) -> None:
    asyncio.run(client.aclose())


def test_client_uses_shared_user_agent_and_timeout():
    client = http_client.client()
    try:
        assert client.headers["User-Agent"] == http_client.USER_AGENT
        assert client.timeout == httpx.Timeout(http_client.HTTP_TIMEOUT)
    finally:
        _close(client)


def test_client_merges_extra_headers():
    client = http_client.client(headers={"Accept": "application/vnd.github+json"})
    try:
        assert client.headers["User-Agent"] == http_client.USER_AGENT
        assert client.headers["Accept"] == "application/vnd.github+json"
    finally:
        _close(client)


def test_client_accepts_a_custom_timeout():
    client = http_client.client(timeout=15.0)
    try:
        assert client.timeout == httpx.Timeout(15.0)
    finally:
        _close(client)


def test_only_http_client_builds_outbound_clients():
    """Every outbound call must go through the shared policy."""
    app_dir = pathlib.Path(__file__).resolve().parent.parent / "app"
    offenders = sorted(
        path.name
        for path in app_dir.glob("*.py")
        if path.name != "http_client.py" and "httpx.AsyncClient(" in path.read_text()
    )
    assert offenders == []


def test_ossf_client_keeps_github_headers_and_shared_agent():
    from app import ossf

    client = ossf._client()
    try:
        assert client.headers["User-Agent"] == http_client.USER_AGENT
        assert client.headers["Accept"] == "application/vnd.github+json"
        assert client.timeout == httpx.Timeout(15.0)
    finally:
        _close(client)