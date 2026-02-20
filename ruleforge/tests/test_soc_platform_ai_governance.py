import sys
import types

import pytest

from soc_platform.ai.providers.base import AIProviderError
from soc_platform.ai.providers.factory import MODEL_REGISTRY, create_provider, model_choices
from soc_platform.governance import RateLimiter, TokenMonitor, can_use_model, policy_for_role


class _DummyOpenAIUsage:
    total_tokens = 42


class _DummyOpenAIMessage:
    content = "openai-response"


class _DummyOpenAIChoice:
    message = _DummyOpenAIMessage()


class _DummyOpenAIResp:
    id = "req-openai-1"
    usage = _DummyOpenAIUsage()
    choices = [_DummyOpenAIChoice()]


class _DummyOpenAIClient:
    class chat:
        class completions:
            @staticmethod
            def create(**kwargs):
                return _DummyOpenAIResp()


class _DummyAnthropicUsage:
    input_tokens = 11
    output_tokens = 31


class _DummyAnthropicText:
    text = "anthropic-response"


class _DummyAnthropicResp:
    id = "req-anthropic-1"
    usage = _DummyAnthropicUsage()
    content = [_DummyAnthropicText()]


class _DummyAnthropicClient:
    def __init__(self, api_key: str):
        self.api_key = api_key

    class messages:
        @staticmethod
        def create(**kwargs):
            return _DummyAnthropicResp()


class _DummyGeminiResp:
    text = "gemini-response"


class _DummyGeminiModel:
    def __init__(self, model: str, system_instruction=None):
        self.model = model
        self.system_instruction = system_instruction

    def generate_content(self, *args, **kwargs):
        return _DummyGeminiResp()


def test_provider_factory_registry_and_local_interface():
    choices = model_choices()
    assert "openai:gpt-4o" in choices
    assert "anthropic:claude-3-5-sonnet" in choices
    assert "google:gemini-1.5-pro" in choices

    provider = create_provider(
        "local:deterministic",
        temperature=0.4,
        streaming=True,
        max_tokens=333,
        system_prompt="sys",
    )
    assert provider.max_tokens == 333
    assert provider.system_prompt == "sys"
    result = provider.generate_intelligence("test prompt")

    assert result.provider == "local"
    assert result.model == MODEL_REGISTRY["local:deterministic"].model
    assert result.estimated_tokens > 0


def test_openai_adapter_with_mocked_sdk(monkeypatch):
    module = types.SimpleNamespace(OpenAI=lambda api_key: _DummyOpenAIClient())
    monkeypatch.setitem(sys.modules, "openai", module)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")

    provider = create_provider("openai:gpt-4o", max_tokens=256, system_prompt="sys")
    result = provider.generate_report("prompt")

    assert result.provider == "openai"
    assert result.content == "openai-response"
    assert result.estimated_tokens == 42
    assert result.request_id == "req-openai-1"


def test_anthropic_adapter_with_mocked_sdk(monkeypatch):
    module = types.SimpleNamespace(Anthropic=_DummyAnthropicClient)
    monkeypatch.setitem(sys.modules, "anthropic", module)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "ant-test")

    provider = create_provider("anthropic:claude-3-5-sonnet", max_tokens=512)
    result = provider.generate_detections("prompt")

    assert result.provider == "anthropic"
    assert result.content == "anthropic-response"
    assert result.estimated_tokens == 42
    assert result.request_id == "req-anthropic-1"


def test_google_adapter_with_mocked_sdk(monkeypatch):
    module = types.SimpleNamespace(
        configure=lambda api_key: None,
        GenerativeModel=_DummyGeminiModel,
    )
    monkeypatch.setitem(sys.modules, "google", types.SimpleNamespace(generativeai=module))
    monkeypatch.setitem(sys.modules, "google.generativeai", module)
    monkeypatch.setenv("GOOGLE_API_KEY", "g-test")

    provider = create_provider("google:gemini-1.5-pro", max_tokens=128)
    result = provider.generate_playbook("prompt")

    assert result.provider == "google"
    assert result.content == "gemini-response"
    assert result.estimated_tokens > 0


def test_provider_error_on_missing_keys(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    provider = create_provider("openai:gpt-4o")
    with pytest.raises(AIProviderError):
        provider.generate_intelligence("x")


def test_rate_limiter_enforces_window():
    limiter = RateLimiter(max_requests=2, window_seconds=60)
    assert limiter.allow("alice") is True
    assert limiter.allow("alice") is True
    assert limiter.allow("alice") is False


def test_token_monitor_accumulates_usage():
    monitor = TokenMonitor()
    monitor.add("alice", 10)
    monitor.add("alice", 5)
    assert monitor.get("alice") == 15


def test_rbac_model_and_role_controls():
    analyst_policy = policy_for_role("analyst")
    admin_policy = policy_for_role("admin")

    assert analyst_policy.allow_model_selection is True
    assert admin_policy.allow_high_cost_models is True

    assert can_use_model("admin", "openai:gpt-4o") is True
    assert can_use_model("analyst", "openai:gpt-4o") is False
    assert can_use_model("analyst", "google:gemini-1.5-pro") is True


def test_provider_interfaces_for_all_actions():
    provider = create_provider("local:deterministic")
    actions = [
        provider.generate_intelligence,
        provider.generate_detections,
        provider.generate_playbook,
        provider.analyze_behavior,
        provider.generate_report,
    ]
    for action in actions:
        output = action("deterministic prompt")
        assert isinstance(output.content, str)
        assert output.estimated_tokens > 0

    streamed = list(provider.stream("stream this"))
    assert streamed
    assert isinstance(streamed[0], str)
