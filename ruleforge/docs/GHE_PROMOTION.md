# GitHub to GitHub Enterprise Promotion Model

## Goal
Promote only validated, signed, and reproducible artifacts from public GitHub into GitHub Enterprise.

## Recommended Flow
1. Public GitHub CI validates code quality and security controls.
2. Build workflow publishes image (`sha-<commit>`) with cosign signature + SBOM.
3. Promotion job records release metadata (`release-metadata.json`).
4. GitHub Enterprise consumes immutable image tags/digests and re-validates policy.
5. Staging deployment and smoke tests execute before production approval.

## Controls
- Deploy by immutable SHA tag (or digest when enterprise registry supports digest pinning).
- Verify signatures (`cosign verify`) before pull in enterprise environments.
- Keep environment-scoped secrets separate across `staging` and `production`.
- Require manual approval in protected production environment.

## Migration Notes
- Replace all `@your-org/...` entries in `CODEOWNERS`.
- Mirror repository settings:
  - branch protection
  - required status checks
  - required signed commits
  - required code owner review
- Set enterprise registry values in `.env.prod`:
  - `REGISTRY`
  - `IMAGE_REPO`
  - `IMAGE_TAG`
