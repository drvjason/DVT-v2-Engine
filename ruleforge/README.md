# RuleForge DVT Engine — v6.2

**Detection Rule Validation Toolkit** · KB-grounded · AI-powered · Production-ready

Validate any detection rule against synthetic and real-log telemetry, score it with precision/recall/F1/evasion metrics, and get AI-generated improvements — all in a single Streamlit interface.

---

## Supported Platforms & Rule Formats

| Platform | Rule Format |
|----------|-------------|
| SentinelOne Singularity | S1QL 2.0 |
| Okta | EventHook / Smart Search |
| Armis Centrix | ASQ |
| Cribl Data Lake | OQL |
| Obsidian Security | Custom |
| Palo Alto Firewall | PAN-OS / KQL |
| ProofPoint Email Security | Generic |

---

## Quick Start (local dev)

```bash
# 1. Clone and install
git clone https://github.com/your-org/ruleforge.git
cd ruleforge
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2. Configure environment
cp .env.example .env
# Edit .env — add ANTHROPIC_API_KEY for live AI generation

# 3. Install pre-commit hooks
pip install -r requirements-dev.txt
pre-commit install

# 4. Run locally
streamlit run app.py
# Opens at http://localhost:8501

# 5. Create a release package for deployment handoff
./scripts/package_release.sh
# Outputs dist/ruleforge_release_<timestamp>.tar.gz
```

---

## Production Deployment

```bash
# 1. Configure secrets (never commit .env with real values)
cp .env.example .env.prod

# 2. Place TLS certificate
mkdir -p nginx/ssl
cp /path/to/ruleforge.crt nginx/ssl/
cp /path/to/ruleforge.key nginx/ssl/  # Never commit this file

# 3. Start full production stack
docker compose -f docker-compose_prod.yml --env-file .env.prod up -d

# App available at https://ruleforge.internal (Okta login required)
```

---

## Development & Testing

```bash
# Run test suite (requires ≥80% coverage on detection_validator.py)
pytest tests/ -v

# Lint
ruff check . && black --check . && isort --check-only .

# Type check
mypy detection_validator.py --ignore-missing-imports

# Security scan
pip-audit -r requirements.txt --severity high
bandit -r app.py detection_validator.py -c pyproject.toml

# Validate KB files only
pytest tests/test_kb.py -v

# Security hardening tests
pytest tests/test_security_hardening.py -v

# Regenerate KB files from combined source
python scripts/kb_split.py
python scripts/kb_split.py --dry-run   # Preview without writing
```

---

## Repository Structure

```
ruleforge/
├── app.py                          # Streamlit application (main — 3,400+ lines)
├── detection_validator.py          # Detection engine framework
│
├── knowledge_bases/                # Platform knowledge bases (7 files)
│   ├── armis_centrix_knowledge_base.json
│   ├── cribl_datalake_detection_knowledge_base.json
│   ├── obsidian_security_detection_knowledge_base.json
│   ├── okta_detection_engineering_knowledge_base.json
│   ├── palo_alto_firewall_knowledge_base.json
│   ├── proofpoint_email_security_knowledge_base.json
│   └── sentinelone_knowledge_base.json
│
├── tests/                          # pytest test suite
│   ├── conftest.py                 # Shared fixtures and project root path
│   ├── test_kb.py                  # KB presence, validity, schema, staleness
│   ├── test_grading.py             # GradingConfig (100% coverage required)
│   ├── test_engines.py             # DetectionEngine field matchers
│   └── test_parsers.py             # Full pipeline integration tests
│
├── scripts/
│   ├── kb_split.py                 # Split vendor_kb_combined.json → 7 KB files
│   └── package_release.sh          # Compile-check + tar.gz release packaging
│
├── docs/
│   ├── PRODUCTION_READINESS.md     # Pre-production hardening checklist
│   └── GHE_PROMOTION.md            # GitHub → GitHub Enterprise promotion model
│
├── nginx/
│   ├── nginx.conf                  # Full nginx config (standalone deployment)
│   ├── ruleforge.conf              # Server block for conf.d include pattern
│   └── ssl/                        # TLS cert/key — NEVER COMMIT (gitignored)
│
├── .github/
│   └── workflows/
│       ├── ci.yml                  # PR gate: lint → test → KB validate → security → container
│       ├── build-push.yml          # GHCR publish + cosign signing + SPDX SBOM
│       ├── deploy.yml              # Staging auto-deploy + production approval gate
│       └── pre-promotion-validation.yml # Structured promotion checklist workflow
│
├── Dockerfile                      # Multi-stage production image (VERSION via --build-arg)
├── docker-compose.yml              # Local dev (no auth)
├── docker-compose_prod.yml         # Production (Okta SSO + nginx + Redis)
├── requirements.txt                # Production dependencies (minimal — no unused deps)
├── requirements-dev.txt            # Dev/test dependencies
├── pyproject.toml                  # Tool configuration (ruff, black, isort, mypy, bandit)
├── .streamlit/config.toml          # Streamlit runtime security defaults
├── pytest.ini                      # Test configuration (testpaths=tests, --cov-fail-under=80)
├── runtime.txt                     # Python 3.11 pin (Streamlit Cloud context)
├── .env.example                    # Environment variable template (no secrets)
├── .pre-commit-config.yaml         # Git hooks: gitleaks, black, isort, ruff, bandit
├── CODEOWNERS                      # Review enforcement (update team slugs for GHE)
├── SECURITY.md                     # Vulnerability reporting & security architecture
└── CHANGELOG.md                    # Release history
```

---

## CI/CD Pipeline

```
PR opened
  └─ CI Gate ─────────────────────────────────────────────────────────
       ├─ 1. Lint (ruff, black, isort)
       ├─ 2. Type check (mypy)
       ├─ 3. Unit tests (pytest ≥80% coverage)
       ├─ 4. KB validation (all 7 files present + valid JSON + schema)
       ├─ 5. Security scan (pip-audit + bandit + gitleaks)
       └─ 6. Container scan (Trivy — zero CRITICAL CVEs)
            │ All pass → merge to main
            ▼
Build & Push ────────────────────────────────────────────────────────
       ├─ Multi-arch build (amd64, arm64)
       ├─ Push to GHCR
       ├─ cosign keyless OIDC signing
       └─ SPDX SBOM generated and attached
            ▼
Deploy → Staging (automatic)
       └─ Health check smoke test
            │ Passes
            ▼
Approval gate (detection-engineering-leads)
            │ Approved
            ▼
Deploy → Production
       └─ Health check + automatic rollback on failure
```

For structured pre-promotion validation before GitHub Enterprise rollout, run
the `Pre-Promotion Validation` workflow (`.github/workflows/pre-promotion-validation.yml`)
with the candidate `sha-<commit>` image tag.

---

## Security Architecture

See [SECURITY.md](SECURITY.md) for full details. Key points:

- **Never expose Streamlit directly** — traffic flows: Internet → nginx → oauth2-proxy → Streamlit
- **Okta group-based access** — only members of `detection-engineering` Okta group can access
- **Non-root container** — UID/GID 1001, no shell
- **API keys** — in production mode, API keys resolve from secrets/env (session-stored keys are ignored)
- **Audit logging** — every validation run logged with Okta user identity, platform, grade, and env
- **Input safeguards** — uploads capped at 10MB and 5,000 rows; regex rule evaluation enforces max pattern length and timeout-aware execution
- **Export safeguards** — HTML output escapes user-controlled fields; CSV output protects against spreadsheet formula injection

---

## Contributing

1. Branch from `main` — direct pushes blocked by branch protection
2. Run `pre-commit install` to enable local hook checks
3. Ensure `pytest tests/ --cov=detection_validator --cov-fail-under=80` passes
4. Open PR — all CI checks must pass, CODEOWNERS review required

**Update CODEOWNERS team slugs** before migrating to GitHub Enterprise. Placeholder
`@your-org/detection-engineering-leads` must be replaced with real GHE org/team paths,
otherwise code ownership enforcement silently fails.

---

## License

Internal use only. See your organization's software license policy.
