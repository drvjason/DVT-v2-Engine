# Production Readiness Checklist

## Application
- `RULEFORGE_ENV=production` is set on runtime containers.
- Upload controls enforced: 10 MB max payload and 5,000 max imported rows.
- Regex rule evaluation hardened with timeout-aware matching (`regex` package).
- HTML/CSV exports sanitized for XSS and formula-injection resistance.

## Security
- Secrets injected from vault/runner secrets, never committed.
- `OAUTH2_COOKIE_SECRET` rotated on a defined cadence.
- `CODEOWNERS` updated to real organization/team slugs.
- Branch protections enforce required checks + code owner approval.

## Infrastructure
- `docker-compose_prod.yml` runs with read-only filesystems and `no-new-privileges`.
- nginx TLS cert/key mounted at `nginx/ssl`.
- Okta OIDC app redirect URI set to `https://<domain>/oauth2/callback`.

## CI/CD
- CI checks pass (`lint`, `typecheck`, `test`, `kb-validate`, `security-scan`, `container-scan`).
- Build pipeline publishes signed image and SBOM.
- Deploy workflow resolves image tag from built commit SHA and supports rollback to previous tag.

## Validation
- Run structured test plan in staging before production promotion:
  - Authentication/authorization checks
  - Upload limits and parsing behavior
  - Rule execution + export behavior
  - Health checks and rollback drill
