from soc_platform.config import AppConfig, load_config


def test_app_config_llm_key_detection():
    cfg = AppConfig(anthropic_api_key="a", openai_api_key="", google_api_key="")
    assert cfg.has_llm_keys is True


def test_load_config_defaults(monkeypatch):
    monkeypatch.delenv("RULEFORGE_ENV", raising=False)
    monkeypatch.delenv("RF_DEFAULT_MODEL", raising=False)
    monkeypatch.delenv("RF_USER_ROLE", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)

    cfg = load_config()
    assert cfg.env == "development"
    assert cfg.default_model
    assert cfg.user_role == "analyst"
