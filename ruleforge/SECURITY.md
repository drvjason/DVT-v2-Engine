# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| v6.x    | ✅ Active support |
| v5.x    | ⚠️ Security fixes only |
| < v5    | ❌ End of life |

## Reporting a Vulnerability

**Do not report security vulnerabilities through public GitHub Issues.**

Report vulnerabilities privately to the detection engineering security team:

1. **GitHub Private Advisory:** Use [Security → Report a Vulnerability](../../security/advisories/new) in this repository (preferred).
2. **Email:** security-deteng@your-org.internal *(PGP key available on request)*

### What to Include

- Description of the vulnerability and potential impact
- Steps to reproduce (proof-of-concept if possible)
- Affected version(s)
- Any suggested mitigations

### Response Timeline

| Stage | Target |
|-------|--------|
| Acknowledgment | Within 48 hours |
| Initial assessment | Within 5 business days |
| Fix or mitigation | Within 30 days for HIGH/CRITICAL |
| Disclosure | Coordinated after fix deployment |

## Security Architecture

### Authentication
- All production traffic is gated through **Okta OIDC** via oauth2-proxy.
- Streamlit is never exposed directly — only reachable via authenticated reverse proxy.
- Session tokens stored in Redis; session lifetime: 8 hours with 1-hour refresh.

### Network
- HTTPS enforced at nginx layer; HTTP → HTTPS redirect with HSTS `max-age=31536000`.
- Internal services (`ruleforge-app`, `redis`) run on isolated Docker network not reachable from the internet.
- Rate limiting: 30 requests/minute per IP globally; 10 requests/minute for validation runs.

### Secret Management
- **No secrets in code or environment files.** All secrets injected at runtime via secrets vault.
- In production mode, API keys are resolved from environment/secrets and session-stored keys are ignored.
- Gitleaks and GitHub secret scanning block commits containing detected secret patterns.

### Input Handling
- File uploads capped at 10 MB and 5,000 events.
- All user-controlled values in HTML report output pass through `html.escape()`.
- CSV export cells are formula-hardened to prevent spreadsheet injection.
- Regex matching enforces pattern-length bounds and uses timeout-aware execution when the `regex` package is present.

### Supply Chain
- All container images signed with cosign (keyless OIDC).
- SPDX SBOM generated and attached to each release.
- Trivy scans container images for CRITICAL CVEs; Dependabot monitors dependencies.
- pip-audit runs on every PR; HIGH/CRITICAL CVEs block merge.
- Dependabot is configured for both pip and GitHub Actions manifests.

## Known Security Limitations

| Limitation | Mitigation | Tracking |
|-----------|-----------|---------|
| Streamlit requires `'unsafe-inline'` for CSP script-src | Document as accepted risk; enforce strict-dynamic when Streamlit supports nonces | Internal #SEC-001 |
| Knowledge base files loaded from filesystem | Volume mount validated at container startup; KB directory is read-only | Internal #SEC-002 |
| oauth2-proxy session expiry causes in-progress workflow loss | Implement Redis-backed session persistence in v6.1 | Internal #SEC-003 |

## Security-Relevant Configuration

### Required Environment Variables (production)

```
ANTHROPIC_API_KEY       — Injected from vault. Never committed.
OKTA_CLIENT_SECRET      — Injected from vault. Never committed.
OAUTH2_COOKIE_SECRET    — 32-byte random base64. Rotate every 90 days.
```

### GitHub Repository Settings

Configure the following in **Settings → Branches → Branch protection on `main`:**
- ✅ Require a pull request before merging
- ✅ Require at least 1 approving review from CODEOWNERS
- ✅ Require status checks to pass (all CI jobs)
- ✅ Require signed commits
- ✅ Do not allow bypassing the above settings
