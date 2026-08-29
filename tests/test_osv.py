from app.osv import parse_osv


def test_parse_osv_extracts_affected_fixed_severity():
    data = {
        "summary": "runc container breakout",
        "aliases": ["CVE-2024-21626"],
        "database_specific": {"severity": "HIGH"},
        "affected": [
            {
                "package": {"name": "runc", "ecosystem": "Go"},
                "ranges": [{"events": [{"introduced": "1.1.11"}, {"fixed": "1.1.12"}]}],
            }
        ],
    }
    parsed = parse_osv(data)
    assert parsed["summary"] == "runc container breakout"
    assert "Go:runc" in parsed["affected_packages"]
    assert parsed["fixed_versions"] == ["1.1.12"]
    assert parsed["severity"] == "high"
    assert parsed["patch_available"] is True


def test_parse_osv_no_patch():
    parsed = parse_osv({"affected": [{"package": {"name": "foo", "ecosystem": "bar"}}]})
    assert parsed["patch_available"] is False
    assert parsed["severity"] is None
