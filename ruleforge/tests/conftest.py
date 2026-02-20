"""
Shared pytest fixtures for RuleForge DVT Engine test suite.

conftest.py lives in tests/; project root is one level up.
"""
import json
import os
import sys
import pytest
from pathlib import Path

# Ensure project root (parent of tests/) is on the import path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

KB_DIR = PROJECT_ROOT / "knowledge_bases"

REQUIRED_KB_FILES = [
    "armis_centrix_knowledge_base.json",
    "cribl_datalake_detection_knowledge_base.json",
    "obsidian_security_detection_knowledge_base.json",
    "okta_detection_engineering_knowledge_base.json",
    "palo_alto_firewall_knowledge_base.json",
    "proofpoint_email_security_knowledge_base.json",
    "sentinelone_knowledge_base.json",
]


@pytest.fixture(scope="session")
def project_root() -> Path:
    return PROJECT_ROOT


@pytest.fixture(scope="session")
def kb_dir() -> Path:
    return KB_DIR


@pytest.fixture(scope="session")
def loaded_kbs() -> dict:
    """Load all 7 KB files into memory once per session."""
    kbs = {}
    for fname in REQUIRED_KB_FILES:
        path = KB_DIR / fname
        if path.exists():
            with open(path, encoding="utf-8") as f:
                kbs[fname] = json.load(f)
    return kbs


@pytest.fixture
def sample_sysmon_event() -> dict:
    return {
        "EventID": 1,
        "Image": "C:\\Windows\\System32\\rundll32.exe",
        "CommandLine": "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";alert('test')",
        "ParentImage": "C:\\Windows\\explorer.exe",
        "User": "CORP\\jsmith",
        "ProcessGuid": "{12345678-1234-1234-1234-123456789012}",
        "UtcTime": "2025-01-15 10:30:00.123",
        "ProcessId": 4512,
        "ParentProcessId": 3024,
        "Hashes": "SHA256=abc123def456",
        "OriginalFileName": "RUNDLL32.EXE",
    }


@pytest.fixture
def sample_benign_event() -> dict:
    return {
        "EventID": 1,
        "Image": "C:\\Windows\\System32\\svchost.exe",
        "CommandLine": "svchost.exe -k NetworkService -p",
        "ParentImage": "C:\\Windows\\System32\\services.exe",
        "User": "NT AUTHORITY\\NETWORK SERVICE",
        "ProcessGuid": "{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}",
        "UtcTime": "2025-01-15 10:28:00.000",
        "ProcessId": 1234,
        "ParentProcessId": 576,
    }
