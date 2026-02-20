from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Iterator


class AIProviderError(Exception):
    """Provider error normalized for upstream handling."""

    def __init__(self, message: str, provider: str, model: str):
        super().__init__(message)
        self.provider = provider
        self.model = model


@dataclass
class AIResult:
    content: str
    model: str
    provider: str
    estimated_tokens: int
    request_id: str = ""
    latency_ms: int = 0


class BaseAIProvider(ABC):
    provider_name: str = "base"

    def __init__(
        self,
        model: str,
        temperature: float = 0.2,
        streaming: bool = False,
        max_tokens: int = 1200,
        system_prompt: str = "",
    ):
        self.model = model
        self.temperature = temperature
        self.streaming = streaming
        self.max_tokens = max_tokens
        self.system_prompt = system_prompt

    @abstractmethod
    def generate_intelligence(self, prompt: str) -> AIResult:
        raise NotImplementedError

    @abstractmethod
    def generate_detections(self, prompt: str) -> AIResult:
        raise NotImplementedError

    @abstractmethod
    def generate_playbook(self, prompt: str) -> AIResult:
        raise NotImplementedError

    @abstractmethod
    def analyze_behavior(self, prompt: str) -> AIResult:
        raise NotImplementedError

    @abstractmethod
    def generate_report(self, prompt: str) -> AIResult:
        raise NotImplementedError

    def stream(self, prompt: str) -> Iterator[str]:
        """Default chunking behavior for providers that return full responses."""
        result = self.generate_intelligence(prompt)
        words = result.content.split()
        for i in range(0, len(words), 16):
            yield " ".join(words[i : i + 16])

    def _estimate_tokens(self, text: str) -> int:
        # Rough estimate: ~0.75 words/token => tokens ~= words / 0.75
        words = len(text.split())
        return max(1, int(words / 0.75))

    def _result(self, content: str, request_id: str = "", latency_ms: int = 0) -> AIResult:
        return AIResult(
            content=content,
            model=self.model,
            provider=self.provider_name,
            estimated_tokens=self._estimate_tokens(content),
            request_id=request_id,
            latency_ms=latency_ms,
        )
