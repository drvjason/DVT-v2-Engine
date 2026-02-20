from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field

from soc_platform.ai.providers.factory import MODEL_REGISTRY

logger = logging.getLogger("ruleforge.governance")


@dataclass
class RateLimiter:
    max_requests: int
    window_seconds: int
    events: dict[str, list[float]] = field(default_factory=dict)

    def allow(self, principal: str) -> bool:
        now = time.time()
        start = now - self.window_seconds
        bucket = [ts for ts in self.events.get(principal, []) if ts >= start]
        if len(bucket) >= self.max_requests:
            self.events[principal] = bucket
            return False
        bucket.append(now)
        self.events[principal] = bucket
        return True


@dataclass
class TokenMonitor:
    usage: dict[str, int] = field(default_factory=dict)

    def add(self, principal: str, tokens: int) -> None:
        self.usage[principal] = self.usage.get(principal, 0) + max(0, tokens)

    def get(self, principal: str) -> int:
        return self.usage.get(principal, 0)


@dataclass(frozen=True)
class AccessPolicy:
    role: str
    allow_model_selection: bool
    allow_high_cost_models: bool
    allow_deploy_generated_rules: bool


def policy_for_role(role: str) -> AccessPolicy:
    role_norm = (role or "analyst").strip().lower()
    if role_norm in {"admin", "soc_admin"}:
        return AccessPolicy(role_norm, True, True, True)
    if role_norm in {"senior_analyst", "detection_engineer"}:
        return AccessPolicy(role_norm, True, True, True)
    if role_norm in {"analyst", "hunter"}:
        return AccessPolicy(role_norm, True, False, False)
    return AccessPolicy(role_norm, False, False, False)


def can_use_model(role: str, model_key: str) -> bool:
    policy = policy_for_role(role)
    model = MODEL_REGISTRY.get(model_key)
    if not model:
        return False
    if model.high_cost and not policy.allow_high_cost_models:
        return False
    return policy.allow_model_selection


def audit_ai_request(
    principal: str,
    role: str,
    action: str,
    model_key: str,
    allowed: bool,
    estimated_tokens: int,
) -> None:
    payload = {
        "event": "ai_request",
        "principal": principal,
        "role": role,
        "action": action,
        "model": model_key,
        "allowed": allowed,
        "estimated_tokens": estimated_tokens,
        "env": os.environ.get("RULEFORGE_ENV", "development"),
    }
    logger.info(json.dumps(payload))


def default_rate_limiter() -> RateLimiter:
    max_reqs = int(os.environ.get("RF_RATE_LIMIT_REQUESTS", "30"))
    window = int(os.environ.get("RF_RATE_LIMIT_WINDOW_SECONDS", "60"))
    return RateLimiter(max_requests=max_reqs, window_seconds=window)
