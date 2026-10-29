"""
Tests for Evaluation Metrics Engine (Phase 14)
Verifies:
1. Exact arithmetic for precision, recall, specificity, FPR, FNR, F1, accuracy.
2. Wilson score confidence interval boundary enforcement [0.0, 1.0].
3. Edge cases: zero predicted positives, zero actual positives, all-inconclusive, empty datasets.
4. Mathematical separation between decisive accuracy and operational accuracy.
"""
import pytest
from ai_engineering.evaluation.metrics import EvaluationMetrics, wilson_score_interval


def test_metrics_perfect_classification():
    m = EvaluationMetrics(tp=50, fp=0, tn=50, fn=0, inconclusive_benign=0, inconclusive_malicious=0)
    d = m.to_dict()

    assert m.precision() == 1.0
    assert m.recall() == 1.0
    assert m.specificity() == 1.0
    assert m.false_positive_rate() == 0.0
    assert m.false_negative_rate() == 0.0
    assert m.f1_score() == 1.0
    assert m.decisive_accuracy() == 1.0
    assert m.operational_accuracy() == 1.0
    assert m.abstention_rate() == 0.0
    assert m.coverage() == 1.0

    p_low, p_high = m.precision_ci()
    assert 0.90 <= p_low <= 1.0
    assert p_high == 1.0


def test_metrics_zero_predicted_positives():
    # Detector predicts NO positives at all
    m = EvaluationMetrics(tp=0, fp=0, tn=50, fn=10)
    assert m.decisive_positives == 0
    assert m.precision() == 0.0
    assert m.recall() == 0.0
    assert m.specificity() == 1.0
    assert m.false_positive_rate() == 0.0
    assert m.false_negative_rate() == 1.0
    assert m.f1_score() == 0.0
    assert m.decisive_accuracy() == round(50 / 60, 4)


def test_metrics_zero_actual_positives():
    # Dataset contains NO malicious samples
    m = EvaluationMetrics(tp=0, fp=5, tn=45, fn=0)
    assert m.total_malicious == 0
    assert m.recall() == 0.0
    assert m.specificity() == 0.9
    assert m.false_positive_rate() == 0.1
    assert m.false_negative_rate() == 0.0


def test_metrics_all_inconclusive():
    # Model abstained on all samples
    m = EvaluationMetrics(tp=0, fp=0, tn=0, fn=0, inconclusive_benign=25, inconclusive_malicious=25)
    assert m.total_samples == 50
    assert m.total_decisive == 0
    assert m.decisive_accuracy() == 0.0
    assert m.operational_accuracy() == 0.0
    assert m.coverage() == 0.0
    assert m.abstention_rate() == 1.0
    assert m.inconclusive_rate_benign() == 1.0
    assert m.inconclusive_rate_malicious() == 1.0


def test_metrics_empty_dataset():
    # Empty dataset should not crash with ZeroDivisionError
    m = EvaluationMetrics()
    assert m.total_samples == 0
    assert m.precision() == 0.0
    assert m.recall() == 0.0
    assert m.specificity() == 0.0
    assert m.operational_accuracy() == 0.0
    assert m.abstention_rate() == 0.0
    assert m.coverage() == 0.0
    assert m.precision_ci() == (0.0, 0.0)


def test_metrics_distinguishes_decisive_vs_operational_accuracy():
    # Scenario: High decisive accuracy masked by massive abstention
    # Out of 100 samples, model abstains on 80.
    # On the 20 it evaluated, it got 10 TP, 10 TN (0 FP, 0 FN).
    m = EvaluationMetrics(
        tp=10, fp=0, tn=10, fn=0,
        inconclusive_benign=40, inconclusive_malicious=40
    )
    # Decisive accuracy is 100% (20/20)
    assert m.decisive_accuracy() == 1.0
    # Operational accuracy is 20% (20/100) because abstentions do not count as correct classifications
    assert m.operational_accuracy() == 0.20
    assert m.abstention_rate() == 0.80
    assert m.coverage() == 0.20


def test_wilson_score_interval_properties():
    # Boundary clamps
    low, high = wilson_score_interval(0, 20)
    assert low == 0.0
    assert 0.0 < high <= 0.20

    low, high = wilson_score_interval(20, 20)
    assert 0.80 <= low < 1.0
    assert high == 1.0

    # Sample size narrowing
    low_small, high_small = wilson_score_interval(5, 10)
    spread_small = high_small - low_small

    low_large, high_large = wilson_score_interval(500, 1000)
    spread_large = high_large - low_large

    assert spread_large < spread_small
    assert 0.0 <= low_large <= high_large <= 1.0
