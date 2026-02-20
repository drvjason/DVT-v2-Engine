from __future__ import annotations

import os
import time

from soc_platform.ai.providers.base import AIProviderError, AIResult, BaseAIProvider
from soc_platform.ai.providers.sdk_utils import guard, log_usage, with_retry


class AnthropicProvider(BaseAIProvider):
    provider_name = "anthropic"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()

    def _client(self):
        guard(bool(self.api_key), "ANTHROPIC_API_KEY is required.", self.provider_name, self.model)
        try:
            import anthropic
        except Exception as exc:  # noqa: BLE001
            raise AIProviderError(
                "Anthropic SDK not installed. Install `anthropic` package.",
                provider=self.provider_name,
                model=self.model,
            ) from exc
        return anthropic.Anthropic(api_key=self.api_key)

    def _invoke(self, action: str, prompt: str) -> AIResult:
        def _call():
            client = self._client()
            if self.streaming:
                return client.messages.stream(
                    model=self.model,
                    temperature=self.temperature,
                    max_tokens=self.max_tokens,
                    system=self.system_prompt or None,
                    messages=[{"role": "user", "content": prompt}],
                )
            return client.messages.create(
                model=self.model,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                system=self.system_prompt or None,
                messages=[{"role": "user", "content": prompt}],
            )

        started = time.time()
        try:
            response = with_retry(_call, retries=2, delay=0.6)
            if self.streaming:
                with response as stream:
                    content = "".join(chunk for chunk in stream.text_stream).strip()
                    final = stream.get_final_message()
                    usage = getattr(final, "usage", None)
                    request_id = getattr(final, "id", "")
            else:
                content = " ".join(
                    getattr(part, "text", "") for part in getattr(response, "content", []) if getattr(part, "text", "")
                ).strip()
                usage = getattr(response, "usage", None)
                request_id = getattr(response, "id", "")

            tokens = 0
            if usage:
                tokens = int(getattr(usage, "input_tokens", 0) + getattr(usage, "output_tokens", 0))
            latency_ms = int((time.time() - started) * 1000)
            result = self._result(content or "No content returned.", request_id=request_id, latency_ms=latency_ms)
            result.estimated_tokens = tokens or result.estimated_tokens
            log_usage(self.provider_name, self.model, action, result.estimated_tokens, result.latency_ms)
            return result
        except AIProviderError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AIProviderError(
                f"Anthropic request failed: {exc}",
                provider=self.provider_name,
                model=self.model,
            ) from exc

    def generate_intelligence(self, prompt: str) -> AIResult:
        return self._invoke("generate_intelligence", prompt)

    def generate_detections(self, prompt: str) -> AIResult:
        return self._invoke("generate_detections", prompt)

    def generate_playbook(self, prompt: str) -> AIResult:
        return self._invoke("generate_playbook", prompt)

    def analyze_behavior(self, prompt: str) -> AIResult:
        return self._invoke("analyze_behavior", prompt)

    def generate_report(self, prompt: str) -> AIResult:
        return self._invoke("generate_report", prompt)
