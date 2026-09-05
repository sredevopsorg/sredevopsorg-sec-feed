from app.config import Settings


def test_settings_defaults():
    s = Settings.from_env({})
    assert s.database_url is None
    assert s.sqlite_db_path.endswith("/data/feed.db")
    assert s.opensearch_url is None
    assert s.opensearch_index == "security-feed"
    assert s.cors_origins == ("*",)
    assert s.log_level == "INFO"
    assert s.smtp_port == 587
    assert s.alert_from == "security-feed@example.com"


def test_settings_csv_parsing():
    s = Settings.from_env({"CORS_ORIGINS": " https://a.example.com , https://b.example.com ,, "})
    assert s.cors_origins == ("https://a.example.com", "https://b.example.com")


def test_settings_int_parsing():
    assert Settings.from_env({"SMTP_PORT": "2525"}).smtp_port == 2525
    assert Settings.from_env({"SMTP_PORT": "not-a-number"}).smtp_port == 587


def test_settings_optional_values():
    s = Settings.from_env({
        "DATABASE_URL": "postgresql://u:p@host/db",
        "OPENSEARCH_URL": "http://os:9200",
        "GITHUB_TOKEN": "tok",
        "DISCORD_WEBHOOK_URL": "https://discord.example.com",
    })
    assert s.database_url == "postgresql://u:p@host/db"
    assert s.opensearch_url == "http://os:9200"
    assert s.github_token == "tok"
    assert s.discord_webhook_url == "https://discord.example.com"
