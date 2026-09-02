from app.alerts import _discord_payload


def test_discord_payload_structure():
    item = {
        "title": "CVE-2024-21626: runc container escape",
        "summary": "runc before 1.1.12 contains a container escape.",
        "url": "https://example.com/advisory",
        "source": "Ubuntu Security Notices",
        "time_ago": "6 hours",
        "severity": "critical",
        "cves": ["CVE-2024-21626"],
    }
    payload = _discord_payload(item)
    embed = payload["embeds"][0]
    assert payload["username"] == "Security Feed"
    assert embed["title"].startswith("[CRITICAL]")
    assert embed["url"] == "https://example.com/advisory"
    assert embed["color"] == 0xE53935
    fields = {f["name"]: f["value"] for f in embed["fields"]}
    assert fields["CVEs"] == "CVE-2024-21626"


def test_discord_payload_defaults():
    payload = _discord_payload({})
    embed = payload["embeds"][0]
    assert embed["title"] == "[UNKNOWN] "
    assert embed["description"] == "—"
    assert embed["color"] == 0x9E9E9E
    fields = {f["name"]: f["value"] for f in embed["fields"]}
    assert fields["CVEs"] == "—"
