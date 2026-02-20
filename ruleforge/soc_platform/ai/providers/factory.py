from __future__ import annotations

from dataclasses import dataclass

from soc_platform.ai.providers.anthropic_provider import AnthropicProvider
from soc_platform.ai.providers.base import BaseAIProvider
from soc_platform.ai.providers.google_provider import GoogleProvider
from soc_platform.ai.providers.local_provider import LocalProvider
from soc_platform.ai.providers.openai_provider import OpenAIProvider


@dataclass(frozen=True)
class ModelChoice:
    label: str
    provider: str
    model: str
    high_cost: bool


MODEL_REGISTRY = {
    "openai:gpt-4o": ModelChoice("OpenAI GPT-4o", "openai", "gpt-4o", True),
    "anthropic:claude-3-5-sonnet": ModelChoice(
        "Anthropic Claude 3.5 Sonnet", "anthropic", "claude-3-5-sonnet", True
    ),
    "google:gemini-1.5-pro": ModelChoice("Google Gemini", "google", "gemini-1.5-pro", False),
    "local:deterministic": ModelChoice("Local Deterministic", "local", "deterministic", False),
}


PROVIDER_CLASSES = {
    "openai": OpenAIProvider,
    "anthropic": AnthropicProvider,
    "google": GoogleProvider,
    "local": LocalProvider,
}


def create_provider(
    choice_key: str,
    temperature: float = 0.2,
    streaming: bool = False,
    max_tokens: int = 1200,
    system_prompt: str = "",
) -> BaseAIProvider:
    choice = MODEL_REGISTRY.get(choice_key, MODEL_REGISTRY["local:deterministic"])
    provider_cls = PROVIDER_CLASSES[choice.provider]
    return provider_cls(
        model=choice.model,
        temperature=temperature,
        streaming=streaming,
        max_tokens=max_tokens,
        system_prompt=system_prompt,
    )


def model_choices() -> list[str]:
    return list(MODEL_REGISTRY.keys())
