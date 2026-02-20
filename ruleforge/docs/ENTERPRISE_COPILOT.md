# Enterprise Copilot Integration Guide

## Scope

RuleForge supports GitHub Copilot Enterprise workflows with a model-provider abstraction and governance controls suitable for SOC engineering teams.

## Supported Model Paths

- `openai:gpt-4o`
- `anthropic:claude-3-5-sonnet`
- `google:gemini-1.5-pro`
- `local:deterministic` (fallback/testing)

## Provider Abstraction

- Interface location: `soc_platform/ai/providers/base.py`
- Factory: `soc_platform/ai/providers/factory.py`
- Provider implementations:
  - `openai_provider.py`
  - `anthropic_provider.py`
  - `google_provider.py`

### Required provider methods

- `generate_intelligence()`
- `generate_detections()`
- `generate_playbook()`
- `analyze_behavior()`
- `generate_report()`

## Governance Controls

Defined in `soc_platform/governance.py`:

- AI request audit logging
- rate limiting
- token usage monitoring
- RBAC for model usage and detection deployment

## Operational Notes

- Default model is set by `RF_DEFAULT_MODEL`.
- User role is controlled by `RF_USER_ROLE`.
- High-cost models are restricted for lower-privilege roles.
- Model selection is persisted per session in Streamlit state.
- Every AI-generated action is logged with provider/model attribution.
- Adapters support streaming and non-streaming generation.
- Runtime controls include temperature, max tokens, and system prompts.
- Provider calls include retry and normalized error handling.

## Adding a New Provider

1. Create `soc_platform/ai/providers/<new_provider>.py` implementing `BaseAIProvider`.
2. Register provider class in `PROVIDER_CLASSES` in `factory.py`.
3. Add a new key to `MODEL_REGISTRY` in `factory.py`.
4. No core engine/UI changes are required.
