"""
test_kb.py
──────────
Knowledge Base validation tests.
These tests run in CI on every PR to enforce KB file integrity.
ALL 7 KB files must be present, valid JSON, and contain required schema fields.

If any test in this file fails, the CI gate blocks merge.
"""
import json
import os
import datetime
import pytest
from pathlib import Path

KB_DIR = Path(__file__).parent.parent / "knowledge_bases"

REQUIRED_KB_FILES = [
    "armis_centrix_knowledge_base.json",
    "cribl_datalake_detection_knowledge_base.json",
    "obsidian_security_detection_knowledge_base.json",
    "okta_detection_engineering_knowledge_base.json",
    "palo_alto_firewall_knowledge_base.json",
    "proofpoint_email_security_knowledge_base.json",
    "sentinelone_knowledge_base.json",
]

MAX_KB_AGE_DAYS = 90   # Alert if KB not updated within 90 days


# ── Presence Tests ────────────────────────────────────────────────────────────

class TestKBPresence:
    """Every required KB file must exist in knowledge_bases/."""

    @pytest.mark.parametrize("filename", REQUIRED_KB_FILES)
    def test_kb_file_exists(self, filename: str):
        path = KB_DIR / filename
        assert path.exists(), (
            f"CRITICAL: Missing KB file: {filename}\n"
            f"Expected at: {path}\n"
            f"Run: python scripts/kb_split.py to regenerate from vendor_kb_combined.json"
        )

    def test_kb_directory_exists(self):
        assert KB_DIR.is_dir(), (
            f"knowledge_bases/ directory not found at {KB_DIR}. "
            "Ensure the directory is committed to the repository."
        )

    def test_no_extra_unexpected_files(self):
        """Warn if unknown files are present in knowledge_bases/ (not fail)."""
        existing = {f.name for f in KB_DIR.glob("*.json")}
        expected = set(REQUIRED_KB_FILES)
        extra = existing - expected
        if extra:
            # Issue warning only — extra files are not a blocker
            import warnings
            warnings.warn(f"Unexpected files in knowledge_bases/: {extra}", UserWarning)


# ── JSON Validity Tests ───────────────────────────────────────────────────────

class TestKBJsonValidity:
    """Every KB file must be parseable as valid JSON."""

    @pytest.mark.parametrize("filename", REQUIRED_KB_FILES)
    def test_kb_is_valid_json(self, filename: str):
        path = KB_DIR / filename
        if not path.exists():
            pytest.skip(f"{filename} not present — covered by TestKBPresence")
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            assert isinstance(data, dict), f"{filename} must contain a JSON object at root"
        except json.JSONDecodeError as e:
            pytest.fail(
                f"INVALID JSON in {filename}: {e}\n"
                f"Run: python scripts/kb_split.py to regenerate clean KB files"
            )

    @pytest.mark.parametrize("filename", REQUIRED_KB_FILES)
    def test_kb_not_empty(self, filename: str):
        path = KB_DIR / filename
        if not path.exists():
            pytest.skip(f"{filename} not present")
        with open(path) as f:
            data = json.load(f)
        assert len(data) > 1, f"{filename} appears empty (only metadata key present)"

    @pytest.mark.parametrize("filename", REQUIRED_KB_FILES)
    def test_kb_minimum_size(self, filename: str):
        """KB files must be at least 10KB — catches accidentally truncated files."""
        path = KB_DIR / filename
        if not path.exists():
            pytest.skip(f"{filename} not present")
        size = path.stat().st_size
        assert size >= 10_000, (
            f"{filename} is suspiciously small ({size} bytes). "
            "Minimum expected: 10,000 bytes. File may be truncated."
        )


# ── Schema Contract Tests ─────────────────────────────────────────────────────

class TestKBSchema:
    """Every KB file must contain the required metadata schema fields."""

    @pytest.mark.parametrize("filename", REQUIRED_KB_FILES)
    def test_schema_version_present(self, filename: str):
        path = KB_DIR / filename
        if not path.exists():
            pytest.skip(f"{filename} not present")
        with open(path) as f:
            data = json.load(f)
        assert "metadata" in data, (
            f"{filename} is missing top-level 'metadata' key. "
            "Add: {\"metadata\": {\"schema_version\": \"1.0\", \"kb_updated_at\": \"YYYY-MM-DD\"}}"
        )
        assert "schema_version" in data["metadata"], (
            f"{filename} metadata is missing 'schema_version'. "
            "Required for KB versioning and CI validation."
        )
        assert isinstance(data["metadata"]["schema_version"], str), (
            f"{filename} schema_version must be a string (e.g., '1.0')"
        )

    @pytest.mark.parametrize("filename", REQUIRED_KB_FILES)
    def test_kb_updated_at_present(self, filename: str):
        path = KB_DIR / filename
        if not path.exists():
            pytest.skip(f"{filename} not present")
        with open(path) as f:
            data = json.load(f)
        assert "metadata" in data, pytest.skip("covered by schema_version test")
        assert "kb_updated_at" in data.get("metadata", {}), (
            f"{filename} metadata is missing 'kb_updated_at'. "
            "Required format: YYYY-MM-DD"
        )

    @pytest.mark.parametrize("filename", REQUIRED_KB_FILES)
    def test_kb_updated_at_format(self, filename: str):
        """kb_updated_at must be a valid YYYY-MM-DD date string."""
        path = KB_DIR / filename
        if not path.exists():
            pytest.skip(f"{filename} not present")
        with open(path) as f:
            data = json.load(f)
        metadata = data.get("metadata", {})
        if "kb_updated_at" not in metadata:
            pytest.skip("covered by kb_updated_at_present test")
        date_str = metadata["kb_updated_at"]
        try:
            datetime.date.fromisoformat(date_str)
        except ValueError:
            pytest.fail(
                f"{filename}: kb_updated_at='{date_str}' is not a valid ISO date. "
                "Use YYYY-MM-DD format."
            )

    @pytest.mark.parametrize("filename", REQUIRED_KB_FILES)
    def test_kb_staleness_warning(self, filename: str):
        """Warn (not fail) if KB has not been updated within MAX_KB_AGE_DAYS."""
        path = KB_DIR / filename
        if not path.exists():
            pytest.skip(f"{filename} not present")
        with open(path) as f:
            data = json.load(f)
        date_str = data.get("metadata", {}).get("kb_updated_at", "")
        if not date_str:
            pytest.skip("no kb_updated_at to check staleness")
        try:
            kb_date = datetime.date.fromisoformat(date_str)
        except ValueError:
            pytest.skip("invalid date format")
        age = (datetime.date.today() - kb_date).days
        if age > MAX_KB_AGE_DAYS:
            import warnings
            warnings.warn(
                f"STALE KB: {filename} was last updated {age} days ago "
                f"(threshold: {MAX_KB_AGE_DAYS} days). "
                "Update kb_updated_at when the KB content is refreshed.",
                UserWarning,
            )


# ── Platform Coverage Tests ───────────────────────────────────────────────────

class TestKBPlatformCoverage:
    """Platform-specific content validation for critical detection surfaces."""

    def _load(self, filename: str) -> dict:
        path = KB_DIR / filename
        if not path.exists():
            pytest.skip(f"{filename} not present")
        with open(path) as f:
            return json.load(f)

    def test_sentinelone_has_s1ql_section(self):
        data = self._load("sentinelone_knowledge_base.json")
        assert any("s1ql" in k.lower() or "search" in k.lower() for k in data.keys()), (
            "sentinelone_knowledge_base.json should contain an S1QL or search_methods section"
        )

    def test_okta_has_detection_patterns(self):
        data = self._load("okta_detection_engineering_knowledge_base.json")
        content = json.dumps(data).lower()
        assert "detection" in content or "threat" in content, (
            "okta_detection_engineering_knowledge_base.json should contain detection guidance"
        )

    def test_armis_has_asq_section(self):
        data = self._load("armis_centrix_knowledge_base.json")
        content = json.dumps(data).lower()
        assert "asq" in content or "query" in content, (
            "armis_centrix_knowledge_base.json should contain ASQ query language documentation"
        )

    def test_palo_alto_has_query_examples(self):
        data = self._load("palo_alto_firewall_knowledge_base.json")
        content = json.dumps(data).lower()
        assert "query" in content or "filter" in content or "log" in content, (
            "palo_alto_firewall_knowledge_base.json should contain query or log filter guidance"
        )

    def test_cribl_has_routing_or_pipeline(self):
        data = self._load("cribl_datalake_detection_knowledge_base.json")
        content = json.dumps(data).lower()
        assert "pipeline" in content or "route" in content or "search" in content, (
            "cribl_datalake_detection_knowledge_base.json should contain pipeline or search guidance"
        )

    def test_proofpoint_has_email_fields(self):
        data = self._load("proofpoint_email_security_knowledge_base.json")
        content = json.dumps(data).lower()
        assert "sender" in content or "recipient" in content or "email" in content or "dmarc" in content, (
            "proofpoint_email_security_knowledge_base.json should contain email field documentation"
        )

    def test_obsidian_has_saas_or_identity(self):
        data = self._load("obsidian_security_detection_knowledge_base.json")
        content = json.dumps(data).lower()
        assert "user" in content or "saas" in content or "identity" in content or "access" in content, (
            "obsidian_security_detection_knowledge_base.json should contain SaaS/identity content"
        )
