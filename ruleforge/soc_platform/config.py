from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class AppConfig:
    """Runtime config sourced from environment or Streamlit secrets."""

    app_name: str = "RuleForge SOC Intelligence Platform"
    default_theme: str = "dark"
    env: str = "development"
    anthropic_api_key: str = ""
    openai_api_key: str = ""
    google_api_key: str = ""
    default_model: str = "openai:gpt-4o"
    user_role: str = "analyst"

    @property
    def has_llm_keys(self) -> bool:
        return bool(self.anthropic_api_key or self.openai_api_key or self.google_api_key)



def _read_secret(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if value:
        return value

    # Streamlit secrets fallback (safe in local + cloud)
    try:
        import streamlit as st

        secret_value = st.secrets.get(name, "")
        if isinstance(secret_value, str):
            return secret_value.strip()
    except Exception:
        pass

    return ""



def load_config() -> AppConfig:
    return AppConfig(
        env=os.environ.get("RULEFORGE_ENV", "development").strip().lower() or "development",
        anthropic_api_key=_read_secret("ANTHROPIC_API_KEY"),
        openai_api_key=_read_secret("OPENAI_API_KEY"),
        google_api_key=_read_secret("GOOGLE_API_KEY"),
        default_model=os.environ.get("RF_DEFAULT_MODEL", "openai:gpt-4o").strip() or "openai:gpt-4o",
        user_role=os.environ.get("RF_USER_ROLE", "analyst").strip().lower() or "analyst",
    )
