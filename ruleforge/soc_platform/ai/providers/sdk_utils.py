from __future__ import annotations

import logging
import time
from collections.abc import Callable
from typing import TypeVar

from soc_platform.ai.providers.base import AIProviderError

logger = logging.getLogger("ruleforge.ai.providers")

T = TypeVar("T")


def with_retry(call: Callable[[], T], retries: int = 2, delay: float = 0.5) -> T:
    last_exc: Exception | None = None
    for attempt in range(retries + 1):
        try:
            return call()
        except Exception as exc:  # noqa: BLE001 - provider sdk normalization boundary
            last_exc = exc
            if attempt >= retries:
                break
            time.sleep(delay * (attempt + 1))
    assert last_exc is not None
    raise last_exc


def log_usage(provider: str, model: str, action: str, tokens: int, latency_ms: int) -> None:
    logger.info(
        "ai_provider_usage",
        extra={
            "provider": provider,
            "model": model,
            "action": action,
            "tokens": tokens,
            "latency_ms": latency_ms,
        },
    )


def guard(condition: bool, message: str, provider: str, model: str) -> None:
    if not condition:
        raise AIProviderError(message, provider=provider, model=model)
