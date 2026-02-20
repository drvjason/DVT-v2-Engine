from __future__ import annotations

import os
import time

from soc_platform.ai.providers.base import AIProviderError, AIResult, BaseAIProvider
from soc_platform.ai.providers.sdk_utils import guard, log_usage, with_retry


class OpenAIProvider(BaseAIProvider):
    provider_name = "openai"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.api_key = os.environ.get("OPENAI_API_KEY", "").strip()

    def _client(self):
        guard(bool(self.api_key), "OPENAI_API_KEY is required.", self.provider_name, self.model)
        try:
            from openai import OpenAI
        except Exception as exc:  # noqa: BLE001
            raise AIProviderError(
                "OpenAI SDK not installed. Install `openai` package.",
                provider=self.provider_name,
                model=self.model,
            ) from exc
        return OpenAI(api_key=self.api_key)

    def _invoke(self, action: str, prompt: str) -> AIResult:
        def _call():
            client = self._client()
            msgs = []
            if self.system_prompt:
                msgs.append({"role": "system", "content": self.system_prompt})
            msgs.append({"role": "user", "content": prompt})
            return client.chat.completions.create(
                model=self.model,
                messages=msgs,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                stream=self.streaming,
            )

        started = time.time()
        try:
            response = with_retry(_call, retries=2, delay=0.6)
            if self.streaming:
                chunks = []
                for event in response:
                    delta = event.choices[0].delta.content if event.choices else None
                    if delta:
                        chunks.append(delta)
                content = "".join(chunks).strip()
                request_id = ""
                tokens = self._estimate_tokens(content)
            else:
                content = (response.choices[0].message.content or "").strip()
                request_id = getattr(response, "id", "")
                usage = getattr(response, "usage", None)
                tokens = getattr(usage, "total_tokens", 0) if usage else self._estimate_tokens(content)
            latency_ms = int((time.time() - started) * 1000)
            result = self._result(content or "No content returned.", request_id=request_id, latency_ms=latency_ms)
            result.estimated_tokens = int(tokens or result.estimated_tokens)
            log_usage(self.provider_name, self.model, action, result.estimated_tokens, result.latency_ms)
            return result
        except AIProviderError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AIProviderError(
                f"OpenAI request failed: {exc}",
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
