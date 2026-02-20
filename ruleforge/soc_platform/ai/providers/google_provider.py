from __future__ import annotations

import os
import time

from soc_platform.ai.providers.base import AIProviderError, AIResult, BaseAIProvider
from soc_platform.ai.providers.sdk_utils import guard, log_usage, with_retry


class GoogleProvider(BaseAIProvider):
    provider_name = "google"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.api_key = os.environ.get("GOOGLE_API_KEY", "").strip()

    def _invoke(self, action: str, prompt: str) -> AIResult:
        guard(bool(self.api_key), "GOOGLE_API_KEY is required.", self.provider_name, self.model)

        try:
            import google.generativeai as genai
        except Exception as exc:  # noqa: BLE001
            raise AIProviderError(
                "Google Generative AI SDK not installed. Install `google-generativeai` package.",
                provider=self.provider_name,
                model=self.model,
            ) from exc

        def _call():
            genai.configure(api_key=self.api_key)
            model = genai.GenerativeModel(
                self.model,
                system_instruction=self.system_prompt or None,
            )
            return model.generate_content(
                prompt,
                generation_config={
                    "temperature": self.temperature,
                    "max_output_tokens": self.max_tokens,
                },
                stream=self.streaming,
            )

        started = time.time()
        try:
            response = with_retry(_call, retries=2, delay=0.6)
            if self.streaming:
                parts = []
                for chunk in response:
                    if getattr(chunk, "text", None):
                        parts.append(chunk.text)
                content = "".join(parts).strip()
                request_id = ""
            else:
                content = getattr(response, "text", "") or ""
                content = content.strip()
                request_id = ""
            latency_ms = int((time.time() - started) * 1000)
            result = self._result(content or "No content returned.", request_id=request_id, latency_ms=latency_ms)
            log_usage(self.provider_name, self.model, action, result.estimated_tokens, result.latency_ms)
            return result
        except AIProviderError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AIProviderError(
                f"Google Gemini request failed: {exc}",
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
