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
