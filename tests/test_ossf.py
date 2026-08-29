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
