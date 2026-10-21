import asyncio

import app.fetcher as fetcher
import app.ossf as ossf
from app.ossf import _build_item, _is_relevant_ossf


def test_is_relevant_ossf_core_ecosystems():
    assert _is_relevant_ossf("Go", "github.com/foo/bar", "Malicious Go package") is True
    assert _is_relevant_ossf("git", "repo", "malicious git repo") is True


def test_is_relevant_ossf_topic_keywords():
    assert _is_relevant_ossf("npm", "node-kubernetes-client", "malicious npm package") is True
    assert _is_relevant_ossf("npm", "node-net-pool", "generic network pool") is False


def test_build_item_from_go_report():
    data = {
        "id": "MAL-2025-2551",
        "summary": "Malicious code in github.com/vainreboot/layout (Go)",
        "details": "Malicious typosquatting Go packages targeting Linux and macOS systems.",
        "published": "2025-03-19T23:58:41Z",
        "affected": [{"package": {"ecosystem": "Go", "name": "github.com/vainreboot/layout"}}],
    }
    item = _build_item("osv/malicious/go/github.com/vainreboot/layout/MAL-2025-2551.json", data)
    assert item is not None
    assert item.title == "Malicious code in github.com/vainreboot/layout (Go)"
    assert "linux" in item.tags
    assert "malware" in item.tags
    assert "go" in item.tags
    assert item.severity == "high"
    assert item.urgent is True


def test_build_item_skips_placeholders():
    data = {"id": "MAL-0000-ghsa-malware-abc123", "summary": "placeholder"}
    assert _build_item("osv/malicious/npm/foo/MAL-0000-ghsa-malware-abc123.json", data) is None


def test_build_item_uppercases_lowercase_cve_ids():
    """CVE ids are normalized, matching the FeedItem contract."""
    data = {
        "id": "MAL-2025-9001",
        "summary": "Malicious code in github.com/acme/linux-tool (Go)",
        "details": "Drops a payload exploiting cve-2025-0001 on linux hosts.",
        "published": "2025-04-01T00:00:00Z",
        "affected": [{"package": {"ecosystem": "Go", "name": "github.com/acme/linux-tool"}}],
    }
    item = _build_item("osv/malicious/go/github.com/acme/linux-tool/MAL-2025-9001.json", data)
    assert item is not None
    assert item.cves == ["CVE-2025-0001"]


def test_ossf_uses_the_shared_cve_extractor():
    """OSSF must not carry a second, divergent CVE extractor."""
    assert ossf._extract_cves is fetcher._extract_cves


# ---------------------------------------------------------------------------
# Commit-cursor pagination (a busy day must not skip reports)
# ---------------------------------------------------------------------------

def _commit(sha: str) -> dict:
    return {"sha": sha}


class _Response:
    def __init__(self, data):
        self._data = data

    def raise_for_status(self) -> None:
        return None

    def json(self):
        return self._data


class _Pages:
    """Fake client returning one page of commits per page number."""

    def __init__(self, pages: dict, default=None):
        self.pages = pages
        self.default = default
        self.requested: list[int] = []

    async def get(self, url, params=None, headers=None):
        page = (params or {}).get("page", 1)
        self.requested.append(page)
        return _Response(self.pages.get(page, self.default or []))


def test_collect_new_commits_stops_at_the_cursor():
    client = _Pages({1: [_commit("a"), _commit("b"), _commit("cursor"), _commit("z")]})
    new, advance = asyncio.run(ossf._collect_new_commits(client, "cursor", 5))
    assert [c["sha"] for c in new] == ["a", "b"]
    assert advance == "a"
    assert client.requested == [1]


def test_collect_new_commits_pages_back_when_the_cursor_is_older():
    """A full first page without the cursor must not be treated as the end."""
    client = _Pages({1: [_commit("a"), _commit("b")], 2: [_commit("cursor"), _commit("d")]})
    new, advance = asyncio.run(ossf._collect_new_commits(client, "cursor", 2))
    assert [c["sha"] for c in new] == ["a", "b"]
    assert advance == "a"
    assert client.requested == [1, 2]


def test_collect_new_commits_handles_a_stale_cursor_at_history_start():
    client = _Pages({1: [_commit("a")]})  # shorter than per_page => no more history
    new, advance = asyncio.run(ossf._collect_new_commits(client, "gone", 2))
    assert [c["sha"] for c in new] == ["a"]
    assert advance == "a"


def test_collect_new_commits_never_advances_past_unseen_commits():
    """At the page limit with the cursor still missing, the cursor stays put."""
    client = _Pages({}, default=[_commit("x")])  # every page full, cursor never seen
    new, advance = asyncio.run(ossf._collect_new_commits(client, "gone", 1))
    assert advance is None
    assert len(new) == ossf.MAX_PAGES


def test_collect_new_commits_first_run_only_takes_the_newest():
    client = _Pages({1: [_commit("newest"), _commit("old")]})
    new, advance = asyncio.run(ossf._collect_new_commits(client, None, 5))
    assert [c["sha"] for c in new] == ["newest"]
    assert advance == "newest"
