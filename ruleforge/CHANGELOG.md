# Changelog

All notable changes to RuleForge DVT Engine are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased] — v6.2.0

### Security
- **SEC: Enforce upload controls in application code** — uploads above 10 MB are rejected before parsing; imports are capped at 5,000 rows.
- **SEC: Harden regex evaluation** — detection regex now enforces a max pattern length and uses timeout-aware matching (`regex` package) when available.
- **SEC: CSV export formula injection mitigation** — spreadsheet-dangerous prefixes (`=`, `+`, `-`, `@`) are escaped.
- **SEC: HTML report escaping in framework export path** — user-controlled fields are escaped in `detection_validator.py` HTML exports.
- **SEC: Restrict KB file resolution** — removed broad recursive fallback matching to avoid unintended JSON file loading.

### Changed
- **Deploy pipeline rollback fixed** — removed invalid `docker compose rollback` usage and replaced with previous-tag rollback logic.
- **Deploy tag resolution fixed for workflow-run trigger** — deploy tag now resolves from `github.event.workflow_run.head_sha`.
- **Container hardening in production compose** — read-only filesystems, `tmpfs`, dropped Linux capabilities, and `no-new-privileges`.
- **Added dependency update automation** — `.github/dependabot.yml` added for pip and GitHub Actions.
- **Added release packaging script** — `scripts/package_release.sh` builds a validated tarball for deployment handoff.
- **Added enterprise rollout docs** — `docs/PRODUCTION_READINESS.md` and `docs/GHE_PROMOTION.md`.

### Security
- **SEC: Strip HTML/script tags from AI prompt before base64 encoding** — prevents reflected XSS
  via the clipboard copy button's `atob()` call when rule text contains embedded HTML.
- **SEC: Production API key hardening** — in production mode, `ANTHROPIC_API_KEY` and
  `OPENAI_API_KEY` resolve from environment variables / Streamlit secrets and session keys
  are ignored. (Resolves audit finding A-04.)
- **SEC: Wire structlog audit logging to Okta identity headers** — every validation run now
  emits a structured JSON audit event with `user`, `email`, `platform`, `rule_name`, `grade`,
  and `env`. Headers injected by nginx/oauth2-proxy (`X-Auth-Request-User`,
  `X-Auth-Request-Email`) are now read and logged via `_get_auth_identity()`.

### Added
- **OpenAI live API integration** — `_call_openai()` added; GPT-4o, GPT-4, o1, and o3-mini
  chips now make live API calls when `OPENAI_API_KEY` is set. Reasoning models (o1, o3-*)
  use `max_completion_tokens` per OpenAI spec. Falls back to Copilot clipboard prompt when
  key is absent.
- **`OPENAI_API_KEY` env var support** — added to `.env.example`, `docker-compose_prod.yml`,
  and all documentation.
- **`.env.example`** — documents all required and optional environment variables with descriptions.
- **`.pre-commit-config.yaml`** — gitleaks, black, isort, ruff, bandit hooks wired.
- **`pyproject.toml`** — unified tool configuration for ruff, black, isort, mypy, bandit.
- **`.github/workflows/ci.yml`** — 6-stage CI gate: lint → typecheck → test (≥80%) →
  KB validate → security-scan (pip-audit + bandit + gitleaks) → container-scan (Trivy).
- **`.github/workflows/build-push.yml`** — multi-arch (amd64/arm64) GHCR publish, cosign
  keyless OIDC signing, SPDX SBOM generation and attestation.
- **`.github/workflows/deploy.yml`** — staging auto-deploy + production manual approval gate
  with health-check smoke tests and rollback instruction on failure.
- **`nginx/` directory** — nginx.conf and ruleforge.conf moved under `nginx/` for clarity.
- **`scripts/kb_split.py`** — moved from project root to `scripts/` per README reference.
- **`tests/` directory** — all test files and conftest.py moved from project root into `tests/`.
- **`knowledge_bases/` directory** — KB JSON files moved from project root into `knowledge_bases/`.

### Changed
- **`_DEFAULT_MODEL` changed from `"gpt-4o"` → `"claude-sonnet-4"`** — Anthropic is the only
  provider with a live API integration; defaulting to it gives users live generation out of
  the box rather than a clipboard prompt.
- **`get_kb_field_schema()` refactored** — replaced 7-branch if/elif chain with a dispatch table
  (`_KB_FIELD_EXTRACTORS`). Adding a new platform now requires only a new dict entry.
- **`_random_guid()` fixed** — replaced MD5-based hex string (not UUID format) with
  `uuid.UUID(int=..., version=4)` seeded from the instance RNG. Output is now a properly
  formatted RFC 4122 UUID.
- **`pytest.ini`** — `testpaths` corrected to `tests` (was referencing non-existent `tests/`
  subdirectory while files lived at project root). `--cov-fail-under` raised to 80.
  `--strict-markers` added.
- **`conftest.py`** — `PROJECT_ROOT` fixed (`parent` vs `parent.parent`) to reflect correct
  relative position now that conftest lives in `tests/`.
- **`requirements.txt`** — removed unused production dependencies: `httpx`, `authlib`,
  `pydantic`, `pydantic-settings`. These inflate the image and generate CVE alerts for
  code that is never executed.
- **`requirements-dev.txt`** — added `pytest-timeout` (required by `pytest.ini --timeout=30`
  but missing from dev deps). Commented out `playwright` as no test files use it yet.
- **Dockerfile** — `LABEL version` parameterized via `--build-arg VERSION`. Healthcheck URL
  corrected to `/_stcore/health`. Both `ARG VERSION` declarations are correct (one per stage).
- **`nginx/ruleforge.conf`** — fixed `X-Frame-Options: SAMEORIGIN` → `DENY` to match
  `nginx/nginx.conf`. Added `/_stcore/stream` WebSocket block. Aligned CSP `font-src` and
  cipher suite with `nginx.conf`.
- **`docker-compose_prod.yml`** — added `OPENAI_API_KEY` environment pass-through.

### Fixed
- Proofpoint KB `_fix_json()` repair function retained pending confirmation that the
  upstream source file has been corrected. Remove once verified clean.

---

## [6.1.0] — 2025-Q3

### Fixed
- `evasion_resistance` metric can be `None` when no evasion events are tested;
  all display paths now use a safe fallback (`None → 0.0` or `"N/A"`)
- HTML report: blob URL now correctly revoked on popup close (memory leak fix)
- Log importer: 10 MB / 300-event cap now applied before full memory allocation
  (previously the cap check happened after the array was built)
- Sidebar API key input removed; key sourced from env / Streamlit secrets only
- ReDoS guard: regex compilation wrapped in `try/except re.error → False`

---

## [6.0.0] — 2025-Q3

### Added
- Support for 7 SIEM platforms: SentinelOne, Okta, Armis, Cribl, Obsidian, Palo Alto, ProofPoint
- Support for 8 rule formats: Sigma, KQL, S1QL, ASQ, OQL, PAN-OS, EventHook, Smart Search
- KB-grounded recommendation engine with priority-ranked remediation guidance
- AI-assisted rule generation via Anthropic Claude API
- GitHub Copilot integration (clipboard workflow) for non-Anthropic models
- `LogImporter`: JSON/JSONL/NDJSON/CSV real-log upload and evaluation
- `RuleComparator`: side-by-side baseline vs. improved rule scoring
- HTML report export with self-contained popup viewer
- CSV export for confusion matrix and per-event results
- Evasion Resistance Score metric
- Composite Score and Letter Grade (A/B/C/D/F) grading

### Changed
- Apple HIG-inspired design system with CSS custom property token architecture
- JetBrains Mono / Inter font pairing

---

## [5.x] — Legacy (security fixes only)

See internal engineering wiki for v5 release history.
