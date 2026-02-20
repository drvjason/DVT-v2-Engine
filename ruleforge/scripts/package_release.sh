#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${ROOT_DIR}/dist"
STAMP="$(date +%Y%m%d_%H%M%S)"
ARCHIVE="ruleforge_release_${STAMP}.tar.gz"
PYTHON_BIN="${PYTHON_BIN:-python3}"

if command -v python3.11 >/dev/null 2>&1; then
  PYTHON_BIN="python3.11"
fi

if ! "${PYTHON_BIN}" - <<'PY' >/dev/null 2>&1
import sys
raise SystemExit(0 if sys.version_info >= (3, 11) else 1)
PY
then
  echo "ERROR: Python 3.11+ is required to package this project."
  echo "Detected: $("${PYTHON_BIN}" --version 2>/dev/null || echo "unknown")"
  exit 1
fi

mkdir -p "${DIST_DIR}"

echo "Running lightweight validation..."
PYTHONPYCACHEPREFIX="${DIST_DIR}/.pycache" \
  "${PYTHON_BIN}" -m compileall "${ROOT_DIR}/app.py" "${ROOT_DIR}/detection_validator.py" >/dev/null

echo "Creating archive: ${DIST_DIR}/${ARCHIVE}"
tar -czf "${DIST_DIR}/${ARCHIVE}" \
  --exclude=".git" \
  --exclude=".venv" \
  --exclude="venv" \
  --exclude="__pycache__" \
  --exclude=".pytest_cache" \
  --exclude="htmlcov" \
  --exclude="dist" \
  -C "${ROOT_DIR}" .

cat > "${DIST_DIR}/BUILD_INFO.txt" <<EOF
archive=${ARCHIVE}
created_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
python=$("${PYTHON_BIN}" --version 2>/dev/null || true)
git_commit=$(git -C "${ROOT_DIR}" rev-parse HEAD 2>/dev/null || echo "unknown")
EOF

echo "Release package ready:"
echo "  - ${DIST_DIR}/${ARCHIVE}"
echo "  - ${DIST_DIR}/BUILD_INFO.txt"
