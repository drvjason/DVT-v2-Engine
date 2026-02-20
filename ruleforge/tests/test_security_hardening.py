"""
Security-focused regression tests for core engine hardening.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from detection_validator import DetectionEngine


def test_field_regex_rejects_overlong_pattern():
    event = {"CommandLine": "powershell.exe -enc AAA"}
    pattern = "A" * 600
    assert DetectionEngine.field_regex(event, "CommandLine", pattern) is False


def test_field_regex_handles_potentially_expensive_pattern():
    event = {"CommandLine": "a" * 10000}
    # Common catastrophic-backtracking style pattern; hardened code should
    # fail closed (False) or quickly return without raising.
    result = DetectionEngine.field_regex(event, "CommandLine", r"(a+)+$")
    assert isinstance(result, bool)
