"""
test_grading.py
───────────────
Unit tests for GradingConfig — the scoring and letter grade engine.
100% coverage required on GradingConfig per engineering review.

Actual thresholds as implemented:
  A: score >= 0.90
  B: score >= 0.80
  C: score >= 0.70
  D: score >= 0.60
  F: score < 0.60
"""
import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from detection_validator import GradingConfig


class TestGradingConfigDefaults:
    """Default weight configuration must exist and expose the correct attributes."""

    def test_default_f1_weight(self):
        gc = GradingConfig()
        assert gc.f1_weight == 0.4

    def test_default_evasion_weight(self):
        gc = GradingConfig()
        assert gc.evasion_weight == 0.3

    def test_default_fp_weight(self):
        """GradingConfig uses fp_weight (false-positive penalty weight), not precision_weight."""
        gc = GradingConfig()
        assert gc.fp_weight == 0.3

    def test_default_weights_sum_to_one(self):
        gc = GradingConfig()
        total = gc.f1_weight + gc.evasion_weight + gc.fp_weight
        assert abs(total - 1.0) < 1e-9, (
            f"Default weights must sum to 1.0, got {total:.6f}"
        )

    def test_grade_thresholds_exposed(self):
        gc = GradingConfig()
        assert hasattr(gc, "grade_thresholds"), "GradingConfig must expose grade_thresholds dict"
        assert isinstance(gc.grade_thresholds, dict)

    def test_grade_thresholds_keys(self):
        gc = GradingConfig()
        assert set(gc.grade_thresholds.keys()) == {"A", "B", "C", "D"}

    def test_grade_thresholds_values(self):
        gc = GradingConfig()
        assert gc.grade_thresholds["A"] == 0.9
        assert gc.grade_thresholds["B"] == 0.8
        assert gc.grade_thresholds["C"] == 0.7
        assert gc.grade_thresholds["D"] == 0.6

    def test_compute_grade_callable(self):
        gc = GradingConfig()
        assert callable(gc.compute_grade)


class TestGradeThresholds:
    """Letter grades must match the actual implemented thresholds."""

    @pytest.fixture
    def gc(self):
        return GradingConfig()

    # Grade A: >= 0.90
    @pytest.mark.parametrize("score,expected", [
        (1.00, "A"), (0.95, "A"), (0.90, "A"),
    ])
    def test_grade_a_range(self, gc, score, expected):
        assert gc.compute_grade(score) == expected, (
            f"Score {score} should yield '{expected}', got '{gc.compute_grade(score)}'"
        )

    # Grade B: >= 0.80, < 0.90
    @pytest.mark.parametrize("score,expected", [
        (0.89, "B"), (0.85, "B"), (0.80, "B"),
    ])
    def test_grade_b_range(self, gc, score, expected):
        assert gc.compute_grade(score) == expected

    # Grade C: >= 0.70, < 0.80
    @pytest.mark.parametrize("score,expected", [
        (0.79, "C"), (0.75, "C"), (0.70, "C"),
    ])
    def test_grade_c_range(self, gc, score, expected):
        assert gc.compute_grade(score) == expected

    # Grade D: >= 0.60, < 0.70
    @pytest.mark.parametrize("score,expected", [
        (0.69, "D"), (0.65, "D"), (0.60, "D"),
    ])
    def test_grade_d_range(self, gc, score, expected):
        assert gc.compute_grade(score) == expected

    # Grade F: < 0.60
    @pytest.mark.parametrize("score,expected", [
        (0.59, "F"), (0.50, "F"), (0.20, "F"), (0.00, "F"),
    ])
    def test_grade_f_range(self, gc, score, expected):
        assert gc.compute_grade(score) == expected

    def test_grade_never_returns_none(self, gc):
        for score in [0.0, 0.1, 0.5, 0.9, 1.0]:
            result = gc.compute_grade(score)
            assert result is not None
            assert isinstance(result, str)
            assert len(result) == 1

    def test_grade_only_valid_letters(self, gc):
        valid = {"A", "B", "C", "D", "F"}
        for score in [i / 100 for i in range(0, 101, 5)]:
            grade = gc.compute_grade(score)
            assert grade in valid, f"compute_grade({score}) returned '{grade}'"

    def test_zero_score_is_f(self, gc):
        assert gc.compute_grade(0.0) == "F"

    def test_perfect_score_is_a(self, gc):
        assert gc.compute_grade(1.0) == "A"


class TestCustomWeights:
    """Custom weight configurations must be accepted."""

    def test_custom_weights_accepted(self):
        gc = GradingConfig(f1_weight=0.5, evasion_weight=0.3, fp_weight=0.2)
        assert gc.f1_weight == 0.5
        assert gc.evasion_weight == 0.3
        assert gc.fp_weight == 0.2

    def test_custom_weights_grade_still_valid(self):
        gc = GradingConfig(f1_weight=0.2, evasion_weight=0.6, fp_weight=0.2)
        valid = {"A", "B", "C", "D", "F"}
        for score in [0.0, 0.5, 1.0]:
            assert gc.compute_grade(score) in valid

    def test_custom_grade_thresholds(self):
        """Custom grade_thresholds dict can be passed to override defaults."""
        custom = {"A": 0.95, "B": 0.85, "C": 0.75, "D": 0.65}
        gc = GradingConfig(grade_thresholds=custom)
        assert gc.compute_grade(0.96) == "A"
        assert gc.compute_grade(0.94) == "B"
        assert gc.compute_grade(0.84) == "C"
        assert gc.compute_grade(0.74) == "D"
        assert gc.compute_grade(0.64) == "F"
