# RuleForge SOC Intelligence Platform

AI-driven threat intelligence, detection engineering, and threat hunting platform for SOC operations.

## Architecture Overview

- `app.py`: multi-page Streamlit UI and workflow orchestration
- `soc_platform/config.py`: environment-first runtime config and secret loading
- `soc_platform/ai/providers/`: provider abstraction and model factory for OpenAI, Anthropic, Google, local fallback
- `soc_platform/governance.py`: AI request audit logging, rate limiting, token tracking, RBAC policy
- `soc_platform/engines/intelligence.py`: IOC extraction, TI enrichment scaffolding, detection query generation
- `soc_platform/engines/hunting.py`: SPECTRA lifecycle and weighted severity scoring
- `soc_platform/engines/mitre.py`: ATT&CK parsing and coverage scoring
- `soc_platform/engines/playbook.py`: playbook generation and SOAR documentation
- `soc_platform/exports.py`: dark print-ready report/export builders

## Core Capabilities

- Dark-first, WCAG-aware SOC dashboard with light-mode toggle
- Threat Intelligence Engine (IOC extraction + ATT&CK mapping + query operationalization)
- Threat Hunting Engine v2.0 (Project SPECTRA lifecycle)
- MITRE ATT&CK Coverage Engine with weighted scoring and drill-down
- Playbook Builder (scenario -> MITRE -> query templates -> SOAR export)
- Reporting exports: print-ready HTML (PDF-ready), executive summary, Word-compatible guide, JSON, STIX-like bundle
- Live SDK adapters: OpenAI (GPT-4o), Anthropic (Claude 3.5 Sonnet), Google (Gemini)

## Security and Governance

- No API key input fields in UI
- Environment/secret-based key resolution:
  - `ANTHROPIC_API_KEY`
  - `OPENAI_API_KEY`
  - `GOOGLE_API_KEY`
- Role-based controls for model selection, high-cost model usage, and rule deployment
- AI audit trail with model/provider attribution for each generated output
- Rate limiting and token usage monitoring

## Environment Separation

- `RULEFORGE_ENV=development|staging|production`
- Recommended:
  - Dev: local `.env`
  - Staging: GitHub Environment secrets (`staging`)
  - Production: GitHub Environment secrets (`production`) or enterprise secret vault

## Quick Start (Dev)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
streamlit run app.py
```

## CI/CD and Quality Gates

- Workflows:
  - `CI`: lint, type-check, tests, coverage gate, security scans, container scan
  - `CodeQL`: static security analysis
  - `Build & Push`: signed multi-arch image and SBOM
  - `Deploy`: staged/production promotion with health checks
- Coverage threshold is enforced and configurable via CI workflow input.
- UI behavior coverage is provided by Streamlit `AppTest` integration tests in `tests/test_ui_app_streamlit.py`.

## Copilot Enterprise Notes

- The codebase supports provider abstraction and model switching for enterprise AI governance.
- Copilot Chat can be used to iterate on:
  - detection query tuning,
  - MITRE mapping refinement,
  - playbook drafting.
- Enforce enterprise policies via repository rulesets, CODEOWNERS, required checks, and environment protections.

## GitHub Enterprise Migration Notes

- Keep workflows and environment secrets identical between GitHub and GitHub Enterprise.
- Update container registry and org/team references (`CODEOWNERS`, deployment secrets).
- Use GitHub Environments (`staging`, `production`) with required approvers for controlled releases.

## Export Notes

"Professional PDF" export is delivered as dark print-optimized HTML so analysts can save directly to PDF from browser/enterprise print pipelines.

## Testing

```bash
pytest tests/ -v
```
