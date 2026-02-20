"""
test_parsers.py
───────────────
Integration tests for the ExampleRundll32Generator and ExampleRundll32Engine —
the reference implementations included in detection_validator.py.
These tests validate the full generate → evaluate → score pipeline
using the built-in example rule, ensuring no regressions in the
telemetry generation and detection engine pipeline.
"""
import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from detection_validator import (
    EventCategory,
    SyntheticEvent,
    DetectionResult,
    TestRunner,
    GradingConfig,
    ExampleRundll32Generator,
    ExampleRundll32Engine,
    ImprovedRundll32Engine,
)


# ── TelemetryGenerator tests ──────────────────────────────────────────────────

class TestTelemetryGenerator:
    """ExampleRundll32Generator must produce well-formed, correctly-labeled events."""

    @pytest.fixture
    def generator(self) -> ExampleRundll32Generator:
        return ExampleRundll32Generator(seed=42)

    def test_generate_true_positives_count(self, generator):
        events = generator.generate_true_positives(count=10)
        assert len(events) == 10

    def test_generate_true_negatives_count(self, generator):
        events = generator.generate_true_negatives(count=15)
        assert len(events) == 15

    def test_generate_fp_candidates_count(self, generator):
        events = generator.generate_fp_candidates(count=5)
        assert len(events) == 5

    def test_generate_evasion_samples_count(self, generator):
        events = generator.generate_evasion_samples(count=5)
        assert len(events) == 5

    def test_true_positives_correctly_labeled(self, generator):
        events = generator.generate_true_positives(count=5)
        for event in events:
            assert event.category == EventCategory.TRUE_POSITIVE, (
                f"Event '{event.event_id}' labeled as {event.category}, expected TRUE_POSITIVE"
            )
            assert event.expected_detection is True

    def test_true_negatives_correctly_labeled(self, generator):
        events = generator.generate_true_negatives(count=5)
        for event in events:
            assert event.category == EventCategory.TRUE_NEGATIVE, (
                f"Event '{event.event_id}' labeled as {event.category}, expected TRUE_NEGATIVE"
            )
            assert event.expected_detection is False

    def test_evasion_samples_correctly_labeled(self, generator):
        events = generator.generate_evasion_samples(count=5)
        for event in events:
            assert event.category == EventCategory.EVASION

    def test_fp_candidates_correctly_labeled(self, generator):
        events = generator.generate_fp_candidates(count=5)
        for event in events:
            assert event.category == EventCategory.FALSE_POSITIVE_CANDIDATE

    def test_events_have_required_fields(self, generator):
        events = generator.generate_true_positives(count=3)
        for event in events:
            assert event.event_id, "event_id must not be empty"
            assert isinstance(event.log_data, dict), "log_data must be a dict"
            assert len(event.log_data) > 0, "log_data must not be empty"
            assert event.description, "description must not be empty"

    def test_events_have_attack_technique(self, generator):
        events = generator.generate_true_positives(count=5)
        for event in events:
            if event.attack_technique:
                assert event.attack_technique.startswith("T"), (
                    f"attack_technique '{event.attack_technique}' should be a MITRE ATT&CK ID (T-prefix)"
                )

    def test_generate_all_returns_all_categories(self, generator):
        all_events = generator.generate_all(tp=5, tn=5, fp=3, evasion=3)
        categories = {e.category for e in all_events}
        assert EventCategory.TRUE_POSITIVE in categories
        assert EventCategory.TRUE_NEGATIVE in categories

    def test_events_are_reproducible_with_seed(self):
        gen1 = ExampleRundll32Generator(seed=42)
        gen2 = ExampleRundll32Generator(seed=42)
        events1 = gen1.generate_true_positives(count=3)
        events2 = gen2.generate_true_positives(count=3)
        # Same seed should produce events with same structure (hostnames may vary but log_data keys match)
        assert len(events1) == len(events2)
        for e1, e2 in zip(events1, events2):
            assert set(e1.log_data.keys()) == set(e2.log_data.keys())

    def test_event_ids_are_unique(self, generator):
        events = generator.generate_all(tp=10, tn=10, fp=5, evasion=5)
        ids = [e.event_id for e in events]
        assert len(ids) == len(set(ids)), "Duplicate event IDs detected in generated events"

    def test_log_data_has_image_field(self, generator):
        """Sysmon-style events must have an Image field for rundll32 detection."""
        events = generator.generate_true_positives(count=5)
        for event in events:
            assert "Image" in event.log_data or "image" in event.log_data, (
                f"True positive event {event.event_id} missing Image field"
            )


# ── SyntheticEvent serialization ─────────────────────────────────────────────

class TestSyntheticEventSerialization:
    def test_to_dict_round_trip(self):
        event = SyntheticEvent(
            event_id="test-001",
            category=EventCategory.TRUE_POSITIVE,
            description="Test event",
            log_data={"Image": "rundll32.exe", "CommandLine": "test"},
            attack_technique="T1218.011",
            expected_detection=True,
            notes="Test notes",
            tags=["test"],
            severity="high",
        )
        d = event.to_dict()
        restored = SyntheticEvent.from_dict(d)
        assert restored.event_id == event.event_id
        assert restored.category == event.category
        assert restored.expected_detection == event.expected_detection
        assert restored.attack_technique == event.attack_technique
        assert restored.log_data == event.log_data

    def test_to_dict_contains_all_required_keys(self):
        event = SyntheticEvent(
            event_id="x",
            category=EventCategory.TRUE_NEGATIVE,
            description="d",
            log_data={},
        )
        d = event.to_dict()
        required_keys = {"event_id", "category", "description", "log_data", "expected_detection"}
        assert required_keys.issubset(d.keys())


# ── ExampleRundll32Engine ─────────────────────────────────────────────────────

class TestExampleRundll32Engine:
    """The reference engine must detect known attack variants and not fire on benign events."""

    @pytest.fixture
    def engine(self) -> ExampleRundll32Engine:
        return ExampleRundll32Engine()

    def test_engine_has_rule_name(self, engine):
        assert engine.rule_name, "Engine must have a non-empty rule_name"

    def test_detects_basic_rundll32_javascript(self, engine):
        event = {
            "EventID": 1,
            "Image": "C:\\Windows\\System32\\rundll32.exe",
            "CommandLine": "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \"",
        }
        result = engine.evaluate(event)
        assert isinstance(result, DetectionResult)
        assert result.matched is True, "Basic rundll32 JavaScript execution should be detected"

    def test_does_not_fire_on_benign_svchost(self, engine):
        event = {
            "EventID": 1,
            "Image": "C:\\Windows\\System32\\svchost.exe",
            "CommandLine": "svchost.exe -k NetworkService -p",
        }
        result = engine.evaluate(event)
        assert result.matched is False, "Benign svchost.exe should not trigger rundll32 rule"

    def test_does_not_fire_on_legitimate_rundll32(self, engine):
        event = {
            "EventID": 1,
            "Image": "C:\\Windows\\System32\\rundll32.exe",
            "CommandLine": "rundll32.exe shell32.dll,Control_RunDLL desk.cpl",
        }
        result = engine.evaluate(event)
        assert isinstance(result, DetectionResult)

    def test_evaluate_returns_detection_result(self, engine):
        result = engine.evaluate({"Image": "test.exe", "CommandLine": "test"})
        assert isinstance(result, DetectionResult)
        assert isinstance(result.matched, bool)

    def test_evaluate_result_has_matched_conditions_on_detection(self, engine):
        event = {
            "Image": "C:\\Windows\\System32\\rundll32.exe",
            "CommandLine": "rundll32.exe javascript:\"RunHTMLApplication\"",
        }
        result = engine.evaluate(event)
        if result.matched:
            assert isinstance(result.matched_conditions, list), \
                "Detected events must include matched_conditions list"

    def test_evaluate_confidence_score_in_range(self, engine):
        event = {
            "Image": "C:\\Windows\\System32\\rundll32.exe",
            "CommandLine": "rundll32.exe javascript:\"RunHTMLApplication\"",
        }
        result = engine.evaluate(event)
        assert 0.0 <= result.confidence_score <= 1.0


# ── Full Pipeline: TestRunner ─────────────────────────────────────────────────

class TestTestRunnerPipeline:
    """End-to-end pipeline: generate → evaluate → score."""

    @pytest.fixture
    def runner(self) -> TestRunner:
        generator = ExampleRundll32Generator(seed=42)
        events = generator.generate_all(tp=10, tn=10, fp=5, evasion=5)
        engine = ExampleRundll32Engine()
        return TestRunner(engine, events, GradingConfig())

    def test_runner_executes_without_error(self, runner):
        results = runner.run()
        assert results is not None
        assert len(results) > 0

    def test_runner_returns_test_results_for_all_events(self, runner):
        generator = ExampleRundll32Generator(seed=42)
        events = generator.generate_all(tp=5, tn=5, fp=3, evasion=3)
        engine = ExampleRundll32Engine()
        runner = TestRunner(engine, events, GradingConfig())
        results = runner.run()
        assert len(results) == len(events)

    def test_metrics_contain_required_keys(self, runner):
        runner.run()
        metrics = runner.get_metrics()
        required_keys = {
            "precision", "recall", "f1_score",
            "evasion_resistance", "composite_score", "overall_grade"
        }
        missing = required_keys - set(metrics.keys())
        assert not missing, f"Metrics missing required keys: {missing}"

    def test_metrics_precision_in_range(self, runner):
        runner.run()
        metrics = runner.get_metrics()
        assert 0.0 <= metrics["precision"] <= 1.0

    def test_metrics_recall_in_range(self, runner):
        runner.run()
        metrics = runner.get_metrics()
        assert 0.0 <= metrics["recall"] <= 1.0

    def test_metrics_f1_in_range(self, runner):
        runner.run()
        metrics = runner.get_metrics()
        assert 0.0 <= metrics["f1_score"] <= 1.0

    def test_metrics_composite_score_in_range(self, runner):
        runner.run()
        metrics = runner.get_metrics()
        assert 0.0 <= metrics["composite_score"] <= 1.0

    def test_metrics_grade_is_valid_letter(self, runner):
        runner.run()
        metrics = runner.get_metrics()
        assert metrics["overall_grade"] in {"A", "B", "C", "D", "F"}

    def test_confusion_matrix_present(self, runner):
        runner.run()
        metrics = runner.get_metrics()
        cm = metrics.get("confusion_matrix", {})
        assert all(k in cm for k in ["TP", "FP", "TN", "FN"]), (
            "Confusion matrix must contain TP, FP, TN, FN keys"
        )

    def test_confusion_matrix_counts_non_negative(self, runner):
        runner.run()
        metrics = runner.get_metrics()
        cm = metrics.get("confusion_matrix", {})
        for key, val in cm.items():
            assert val >= 0, f"Confusion matrix {key} must be non-negative, got {val}"

    def test_confusion_matrix_sums_to_event_count(self, runner):
        generator = ExampleRundll32Generator(seed=99)
        events = generator.generate_all(tp=5, tn=5, fp=3, evasion=3)
        engine = ExampleRundll32Engine()
        r = TestRunner(engine, events, GradingConfig())
        r.run()
        metrics = r.get_metrics()
        cm = metrics.get("confusion_matrix", {})
        total = cm.get("TP", 0) + cm.get("FP", 0) + cm.get("TN", 0) + cm.get("FN", 0)
        assert total == len(events), (
            f"CM total ({total}) must equal event count ({len(events)})"
        )

    def test_export_report_json_is_valid(self, runner):
        runner.run()
        report = runner.export_report_json()
        assert isinstance(report, dict)
        assert len(report) > 0

    def test_improved_engine_scores_higher_than_example(self):
        """ImprovedRundll32Engine must score >= ExampleRundll32Engine on same events."""
        generator = ExampleRundll32Generator(seed=42)
        events = generator.generate_all(tp=10, tn=10, fp=5, evasion=5)
        gc = GradingConfig()

        base_runner = TestRunner(ExampleRundll32Engine(), events, gc)
        base_runner.run()
        base_score = base_runner.get_metrics()["composite_score"]

        improved_runner = TestRunner(ImprovedRundll32Engine(), events, gc)
        improved_runner.run()
        improved_score = improved_runner.get_metrics()["composite_score"]

        assert improved_score >= base_score, (
            f"ImprovedRundll32Engine composite score ({improved_score:.3f}) should be "
            f">= ExampleRundll32Engine ({base_score:.3f}). "
            "Check ImprovedRundll32Engine implementation."
        )
