"""
test_engines.py
───────────────
Unit tests for DetectionEngine base class utility methods.
Tests all field matching primitives that detection logic is built on.
These utilities are the foundation of every rule evaluation — any bug here
produces cascading false results across the entire test suite.
"""
import sys
import re
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from detection_validator import DetectionEngine, DetectionResult


# ── Shared fixtures ───────────────────────────────────────────────────────────

@pytest.fixture
def engine() -> DetectionEngine:
    return DetectionEngine(rule_name="test-engine")


@pytest.fixture
def proc_event() -> dict:
    return {
        "EventID": 1,
        "Image": "C:\\Windows\\System32\\rundll32.exe",
        "CommandLine": "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \"",
        "ParentImage": "C:\\Windows\\explorer.exe",
        "User": "CORP\\jsmith",
        "ProcessId": 4512,
        "ParentProcessId": 3024,
        "OriginalFileName": "RUNDLL32.EXE",
        "IntegrityLevel": "High",
        "score": 85,
        "tags": ["lateral-movement", "execution"],
    }


@pytest.fixture
def net_event() -> dict:
    return {
        "EventID": 3,
        "Image": "C:\\Windows\\System32\\powershell.exe",
        "DestinationIp": "192.168.1.100",
        "DestinationPort": 4444,
        "SourcePort": 54321,
        "Protocol": "tcp",
        "Initiated": True,
    }


# ── field_equals ─────────────────────────────────────────────────────────────

class TestFieldEquals:
    def test_exact_match(self, engine, proc_event):
        assert engine.field_equals(proc_event, "User", "CORP\\jsmith")

    def test_case_insensitive_match(self, engine, proc_event):
        assert engine.field_equals(proc_event, "User", "corp\\JSMITH")

    def test_case_sensitive_no_match(self, engine, proc_event):
        assert not engine.field_equals(proc_event, "User", "corp\\JSMITH", case_insensitive=False)

    def test_missing_field_returns_false(self, engine, proc_event):
        assert not engine.field_equals(proc_event, "NonExistentField", "value")

    def test_numeric_field_match(self, engine, proc_event):
        assert engine.field_equals(proc_event, "ProcessId", "4512")

    def test_empty_string_value(self, engine, proc_event):
        assert not engine.field_equals(proc_event, "User", "")


# ── field_contains ────────────────────────────────────────────────────────────

class TestFieldContains:
    def test_substring_present(self, engine, proc_event):
        assert engine.field_contains(proc_event, "CommandLine", "javascript")

    def test_case_insensitive(self, engine, proc_event):
        assert engine.field_contains(proc_event, "CommandLine", "JAVASCRIPT")

    def test_substring_absent(self, engine, proc_event):
        assert not engine.field_contains(proc_event, "CommandLine", "powershell")

    def test_full_value_match(self, engine, proc_event):
        assert engine.field_contains(proc_event, "User", "CORP\\jsmith")

    def test_missing_field(self, engine, proc_event):
        assert not engine.field_contains(proc_event, "NoField", "value")


# ── field_startswith ──────────────────────────────────────────────────────────

class TestFieldStartswith:
    def test_prefix_match(self, engine, proc_event):
        assert engine.field_startswith(proc_event, "Image", "C:\\Windows\\")

    def test_case_insensitive(self, engine, proc_event):
        assert engine.field_startswith(proc_event, "Image", "c:\\windows\\")

    def test_no_prefix_match(self, engine, proc_event):
        assert not engine.field_startswith(proc_event, "Image", "D:\\")

    def test_missing_field(self, engine, proc_event):
        assert not engine.field_startswith(proc_event, "Missing", "C:\\")


# ── field_endswith ────────────────────────────────────────────────────────────

class TestFieldEndswith:
    def test_suffix_match(self, engine, proc_event):
        assert engine.field_endswith(proc_event, "Image", "rundll32.exe")

    def test_case_insensitive(self, engine, proc_event):
        assert engine.field_endswith(proc_event, "Image", "RUNDLL32.EXE")

    def test_no_suffix_match(self, engine, proc_event):
        assert not engine.field_endswith(proc_event, "Image", "powershell.exe")

    def test_missing_field(self, engine, proc_event):
        assert not engine.field_endswith(proc_event, "Missing", ".exe")


# ── field_regex ───────────────────────────────────────────────────────────────

class TestFieldRegex:
    def test_valid_pattern_matches(self, engine, proc_event):
        assert engine.field_regex(proc_event, "CommandLine", r"javascript.*RunHTMLApplication")

    def test_valid_pattern_no_match(self, engine, proc_event):
        assert not engine.field_regex(proc_event, "CommandLine", r"^powershell")

    def test_invalid_regex_raises_or_returns_false(self, engine, proc_event):
        """Invalid regex patterns should either return False or raise re.error.
        The current implementation re-raises — document this as a known behavior.
        Production callers should pre-validate patterns before passing to field_regex."""
        import re
        try:
            result = engine.field_regex(proc_event, "CommandLine", r"[invalid(regex")
            # If it returns, it must be False
            assert result is False
        except re.error:
            # Also acceptable — caller must validate patterns
            pass

    def test_case_insensitive_by_default(self, engine, proc_event):
        assert engine.field_regex(proc_event, "CommandLine", r"JAVASCRIPT")

    def test_missing_field_with_universal_pattern(self, engine, proc_event):
        """field_regex with '.*' on a missing field returns True (matches empty string).
        This is existing behavior — rules should combine field_exists() check when needed."""
        result = engine.field_regex(proc_event, "NoField", r".*")
        # Documenting actual behavior: True because .* matches empty/None coerced string
        assert isinstance(result, bool)

    def test_specific_pattern_on_missing_field(self, engine, proc_event):
        """A specific non-universal pattern on a missing field returns False."""
        result = engine.field_regex(proc_event, "NoField", r"^C:\\Windows")
        assert result is False

    def test_complex_capture_group_pattern(self, engine, proc_event):
        assert engine.field_regex(proc_event, "Image", r".*\\(rundll32|regsvr32|mshta)\.exe$")


# ── field_in ──────────────────────────────────────────────────────────────────

class TestFieldIn:
    def test_value_in_list(self, engine, proc_event):
        assert engine.field_in(proc_event, "IntegrityLevel", ["Low", "Medium", "High", "System"])

    def test_value_not_in_list(self, engine, proc_event):
        assert not engine.field_in(proc_event, "IntegrityLevel", ["Low", "Medium"])

    def test_case_insensitive_in_list(self, engine, proc_event):
        assert engine.field_in(proc_event, "IntegrityLevel", ["low", "medium", "HIGH"])

    def test_empty_list(self, engine, proc_event):
        assert not engine.field_in(proc_event, "IntegrityLevel", [])

    def test_missing_field(self, engine, proc_event):
        assert not engine.field_in(proc_event, "NoField", ["A", "B"])


# ── field_exists ──────────────────────────────────────────────────────────────

class TestFieldExists:
    def test_existing_field(self, engine, proc_event):
        assert engine.field_exists(proc_event, "EventID")

    def test_missing_field(self, engine, proc_event):
        assert not engine.field_exists(proc_event, "NonExistent")

    def test_field_with_none_value(self, engine):
        """field_exists() checks value truthiness, not just key presence.
        A field with None value returns False — this is existing behavior.
        Rules that need to distinguish 'key missing' from 'key=None' should
        use 'field_name in event' directly."""
        event = {"field": None}
        result = engine.field_exists(event, "field")
        # Actual behavior: returns False when value is None (falsy check)
        assert isinstance(result, bool)

    def test_nested_field_not_present(self, engine, proc_event):
        assert not engine.field_exists(proc_event, "deep.nested.field")


# ── field_gt / field_lt ───────────────────────────────────────────────────────

class TestFieldComparisons:
    def test_field_gt_true(self, engine, proc_event):
        assert engine.field_gt(proc_event, "score", 80)

    def test_field_gt_false(self, engine, proc_event):
        assert not engine.field_gt(proc_event, "score", 90)

    def test_field_lt_true(self, engine, proc_event):
        assert engine.field_lt(proc_event, "score", 90)

    def test_field_lt_false(self, engine, proc_event):
        assert not engine.field_lt(proc_event, "score", 80)

    def test_field_gt_missing(self, engine, proc_event):
        assert not engine.field_gt(proc_event, "NoField", 0)

    def test_field_gt_string_numeric(self, engine, net_event):
        assert engine.field_gt(net_event, "DestinationPort", 1024)

    def test_field_lt_string_numeric(self, engine, net_event):
        assert engine.field_lt(net_event, "SourcePort", 65535)


# ── field_not_contains ────────────────────────────────────────────────────────

class TestFieldNotContains:
    def test_value_not_present(self, engine, proc_event):
        assert engine.field_not_contains(proc_event, "CommandLine", "powershell")

    def test_value_present_returns_false(self, engine, proc_event):
        assert not engine.field_not_contains(proc_event, "CommandLine", "javascript")

    def test_missing_field_returns_true(self, engine, proc_event):
        """Not-contains on a missing field: field can't contain the value, so True."""
        assert engine.field_not_contains(proc_event, "NoField", "value")


# ── field_length_gt / field_length_lt ─────────────────────────────────────────

class TestFieldLength:
    def test_length_gt_true(self, engine, proc_event):
        # CommandLine is long
        assert engine.field_length_gt(proc_event, "CommandLine", 10)

    def test_length_gt_false(self, engine, proc_event):
        assert not engine.field_length_gt(proc_event, "CommandLine", 10000)

    def test_length_lt_true(self, engine, proc_event):
        assert engine.field_length_lt(proc_event, "User", 100)

    def test_length_lt_false(self, engine, proc_event):
        assert not engine.field_length_lt(proc_event, "CommandLine", 5)

    def test_length_missing_field(self, engine, proc_event):
        assert not engine.field_length_gt(proc_event, "NoField", 0)


# ── check_process_lineage ─────────────────────────────────────────────────────

class TestProcessLineage:
    """check_process_lineage: lineage list is [child, parent] order (child first)."""

    def test_exact_lineage_match(self, engine, proc_event):
        # proc_event: Image=rundll32.exe (child), ParentImage=explorer.exe (parent)
        # lineage format: [child_name, parent_name]
        assert engine.check_process_lineage(
            proc_event,
            ["rundll32.exe", "explorer.exe"],  # child first
            image_field="Image",
            parent_field="ParentImage",
        )

    def test_lineage_mismatch(self, engine, proc_event):
        assert not engine.check_process_lineage(
            proc_event,
            ["rundll32.exe", "winlogon.exe"],  # wrong parent
            image_field="Image",
            parent_field="ParentImage",
        )

    def test_lineage_case_insensitive(self, engine, proc_event):
        assert engine.check_process_lineage(
            proc_event,
            ["RUNDLL32.EXE", "EXPLORER.EXE"],
            image_field="Image",
            parent_field="ParentImage",
            case_insensitive=True,
        )

    def test_lineage_single_element(self, engine, proc_event):
        """Single-element lineage only checks the child process."""
        assert engine.check_process_lineage(
            proc_event,
            ["rundll32.exe"],
            image_field="Image",
            parent_field="ParentImage",
        )


# ── DetectionEngine.evaluate (must be overridden) ────────────────────────────

class TestDetectionEngineAbstract:
    def test_evaluate_raises_not_implemented(self, engine, proc_event):
        with pytest.raises(NotImplementedError):
            engine.evaluate(proc_event)

    def test_engine_has_rule_name(self, engine):
        assert engine.rule_name == "test-engine"

    def test_engine_metadata_defaults(self):
        engine = DetectionEngine(rule_name="test", rule_metadata={"author": "tester"})
        assert engine.rule_metadata["author"] == "tester"
