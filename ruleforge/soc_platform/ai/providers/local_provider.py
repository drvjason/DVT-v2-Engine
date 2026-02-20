from __future__ import annotations

from soc_platform.ai.providers.base import AIResult, BaseAIProvider


class LocalProvider(BaseAIProvider):
    provider_name = "local"

    def _render(self, task: str, prompt: str) -> AIResult:
        text = f"[local:{self.model}] {task}: deterministic fallback. Input digest: {prompt[:240]}"
        return self._result(text)

    def generate_intelligence(self, prompt: str) -> AIResult:
        return self._render("intelligence", prompt)

    def generate_detections(self, prompt: str) -> AIResult:
        return self._render("detections", prompt)

    def generate_playbook(self, prompt: str) -> AIResult:
        return self._render("playbook", prompt)

    def analyze_behavior(self, prompt: str) -> AIResult:
        return self._render("behavior", prompt)

    def generate_report(self, prompt: str) -> AIResult:
        return self._render("report", prompt)
