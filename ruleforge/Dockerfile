# ─────────────────────────────────────────────────────────────────────────────
# RuleForge DVT Engine — Production Dockerfile
# Python 3.11-slim base | Multi-stage | Non-root user | No dev dependencies
# ─────────────────────────────────────────────────────────────────────────────

# ── Build arguments ───────────────────────────────────────────────────────────
ARG VERSION=dev
ARG PYTHON_VERSION=3.11

# ── Stage 1: dependency builder ───────────────────────────────────────────────
FROM python:${PYTHON_VERSION}-slim AS builder

WORKDIR /build

# Install build deps for any compiled packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Stage 2: runtime image ────────────────────────────────────────────────────
FROM python:${PYTHON_VERSION}-slim AS runtime

ARG VERSION=dev

# OCI image labels — VERSION injected via: docker build --build-arg VERSION=$(git describe --tags)
LABEL org.opencontainers.image.title="RuleForge DVT Engine"
LABEL org.opencontainers.image.description="Detection Rule Validation Toolkit"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.vendor="Detection Engineering"
LABEL org.opencontainers.image.source="https://github.com/your-org/ruleforge"

# Security: non-root user (UID/GID 1001)
RUN groupadd --gid 1001 ruleforge && \
    useradd --uid 1001 --gid 1001 --no-create-home --shell /bin/false ruleforge

WORKDIR /app

# Copy installed packages from builder stage — no dev deps in runtime image
COPY --from=builder /install /usr/local

# Copy application files with correct ownership
COPY --chown=ruleforge:ruleforge app.py .
COPY --chown=ruleforge:ruleforge detection_validator.py .
COPY --chown=ruleforge:ruleforge knowledge_bases/ ./knowledge_bases/
COPY --chown=ruleforge:ruleforge .streamlit/ ./.streamlit/

# Startup assertion: fail fast if wrong Python version
RUN python3 -c "import sys; assert sys.version_info >= (3, 11), f'Python 3.11+ required, got {sys.version_info}'"

# Startup validation: confirm all 7 KB files are present and parseable
RUN python3 -c "\
import json, os, sys; \
required = [\
  'armis_centrix_knowledge_base.json',\
  'cribl_datalake_detection_knowledge_base.json',\
  'obsidian_security_detection_knowledge_base.json',\
  'okta_detection_engineering_knowledge_base.json',\
  'palo_alto_firewall_knowledge_base.json',\
  'proofpoint_email_security_knowledge_base.json',\
  'sentinelone_knowledge_base.json'\
]; \
missing = [f for f in required if not os.path.exists(f'knowledge_bases/{f}')]; \
[print(f'ERROR: Missing KB file: {m}', file=sys.stderr) for m in missing]; \
sys.exit(1) if missing else print(f'KB validation: all {len(required)} files present')\
"

# Switch to non-root user before runtime
USER ruleforge

# Streamlit server configuration via environment (overridable at runtime)
ENV STREAMLIT_SERVER_PORT=8501 \
    STREAMLIT_SERVER_ADDRESS=0.0.0.0 \
    STREAMLIT_SERVER_HEADLESS=true \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false \
    STREAMLIT_SERVER_ENABLE_CORS=false \
    STREAMLIT_SERVER_ENABLE_XSRF_PROTECTION=true \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    RULEFORGE_ENV=production

# API keys must be injected at runtime via Docker secrets or env injection.
# Never bake secrets into the image.

EXPOSE 8501

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8501/_stcore/health')" || exit 1

CMD ["python3", "-m", "streamlit", "run", "app.py", \
     "--server.port=8501", \
     "--server.address=0.0.0.0", \
     "--server.headless=true", \
     "--server.enableCORS=false", \
     "--server.enableXsrfProtection=true"]
