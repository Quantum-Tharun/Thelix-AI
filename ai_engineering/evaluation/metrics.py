"""
Thelix AI — Evaluation Metrics Engine
Computes mathematically sound, robust confusion matrices, decisive metrics,
operational end-to-end metrics, and Wilson score confidence intervals.
"""
import math
from typing import Dict, Any, Tuple, Optional


def wilson_score_interval(successes: int, total: int, confidence: float = 0.95) -> Tuple[float, float]:
    """
    Calculates Wilson score interval for a binomial proportion.
    Accurate for small sample sizes and extreme probabilities (0 or 1).
    Guarantees output is strictly clamped within [0.0, 1.0].
    """
    if total <= 0:
        return 0.0, 0.0
    if successes < 0 or successes > total:
        raise ValueError(f"Invalid successes count {successes} for total {total}")

    # z-value for confidence level
    if confidence == 0.95:
        z = 1.959963984540054
    elif confidence == 0.99:
        z = 2.5758293035489004
    elif confidence == 0.90:
        z = 1.6448536269514722
    else:
        # Default fallback to 95%
        z = 1.959963984540054

    p_hat = successes / total
    denom = 1.0 + (z * z) / total
    center = (p_hat + (z * z) / (2.0 * total)) / denom
    spread = (z * math.sqrt((p_hat * (1.0 - p_hat) / total) + (z * z) / (4.0 * total * total))) / denom

    lower = max(0.0, round(center - spread, 4))
    upper = min(1.0, round(center + spread, 4))
    return lower, upper


class EvaluationMetrics:
    """
    Evaluator for classification outcomes that strictly distinguishes
    decisive predictions from operational outcomes with abstentions/inconclusives.
    """
    def __init__(
        self,
        tp: int = 0,
        fp: int = 0,
        tn: int = 0,
        fn: int = 0,
        inconclusive_benign: int = 0,
        inconclusive_malicious: int = 0,
        extraction_failures: int = 0,
    ):
        self.tp = max(0, tp)
        self.fp = max(0, fp)
        self.tn = max(0, tn)
        self.fn = max(0, fn)
        self.inconclusive_benign = max(0, inconclusive_benign)
        self.inconclusive_malicious = max(0, inconclusive_malicious)
        self.extraction_failures = max(0, extraction_failures)

    @property
    def total_inconclusive(self) -> int:
        return self.inconclusive_benign + self.inconclusive_malicious

    @property
    def total_decisive(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @property
    def total_samples(self) -> int:
        return self.total_decisive + self.total_inconclusive

    @property
    def total_benign(self) -> int:
        return self.tn + self.fp + self.inconclusive_benign

    @property
    def total_malicious(self) -> int:
        return self.tp + self.fn + self.inconclusive_malicious

    @property
    def decisive_positives(self) -> int:
        return self.tp + self.fp

    @property
    def decisive_negatives(self) -> int:
        return self.tn + self.fn

    # Decisive Metrics
    def precision(self) -> float:
        if self.decisive_positives == 0:
            return 0.0
        return round(self.tp / self.decisive_positives, 4)

    def precision_ci(self) -> Tuple[float, float]:
        return wilson_score_interval(self.tp, self.decisive_positives)

    def recall(self) -> float:
        decisive_malicious = self.tp + self.fn
        if decisive_malicious == 0:
            return 0.0
        return round(self.tp / decisive_malicious, 4)

    def recall_ci(self) -> Tuple[float, float]:
        return wilson_score_interval(self.tp, self.tp + self.fn)

    def specificity(self) -> float:
        decisive_benign = self.tn + self.fp
        if decisive_benign == 0:
            return 0.0
        return round(self.tn / decisive_benign, 4)

    def specificity_ci(self) -> Tuple[float, float]:
        return wilson_score_interval(self.tn, self.tn + self.fp)

    def false_positive_rate(self) -> float:
        decisive_benign = self.tn + self.fp
        if decisive_benign == 0:
            return 0.0
        return round(self.fp / decisive_benign, 4)

    def false_positive_rate_ci(self) -> Tuple[float, float]:
        return wilson_score_interval(self.fp, self.tn + self.fp)

    def false_negative_rate(self) -> float:
        decisive_malicious = self.tp + self.fn
        if decisive_malicious == 0:
            return 0.0
        return round(self.fn / decisive_malicious, 4)

    def false_negative_rate_ci(self) -> Tuple[float, float]:
        return wilson_score_interval(self.fn, self.tp + self.fn)

    def f1_score(self) -> float:
        p = self.precision()
        r = self.recall()
        if (p + r) == 0.0:
            return 0.0
        return round((2.0 * p * r) / (p + r), 4)

    def decisive_accuracy(self) -> float:
        if self.total_decisive == 0:
            return 0.0
        return round((self.tp + self.tn) / self.total_decisive, 4)

    def decisive_accuracy_ci(self) -> Tuple[float, float]:
        return wilson_score_interval(self.tp + self.tn, self.total_decisive)

    # Operational (End-to-End) Metrics
    def operational_accuracy(self) -> float:
        """Accuracy evaluated across ALL submitted samples, where abstentions/inconclusive count as non-decisive."""
        if self.total_samples == 0:
            return 0.0
        return round((self.tp + self.tn) / self.total_samples, 4)

    def operational_accuracy_ci(self) -> Tuple[float, float]:
        return wilson_score_interval(self.tp + self.tn, self.total_samples)

    def abstention_rate(self) -> float:
        if self.total_samples == 0:
            return 0.0
        return round(self.total_inconclusive / self.total_samples, 4)

    def coverage(self) -> float:
        if self.total_samples == 0:
            return 0.0
        return round(self.total_decisive / self.total_samples, 4)

    def inconclusive_rate_benign(self) -> float:
        if self.total_benign == 0:
            return 0.0
        return round(self.inconclusive_benign / self.total_benign, 4)

    def inconclusive_rate_malicious(self) -> float:
        if self.total_malicious == 0:
            return 0.0
        return round(self.inconclusive_malicious / self.total_malicious, 4)

    def extraction_failure_rate(self) -> float:
        if self.total_samples == 0:
            return 0.0
        return round(self.extraction_failures / self.total_samples, 4)

    def to_dict(self) -> Dict[str, Any]:
        """Returns structured dictionary documenting metrics, confidence intervals, and exact denominators."""
        return {
            "counts": {
                "total_samples": self.total_samples,
                "total_decisive": self.total_decisive,
                "total_inconclusive": self.total_inconclusive,
                "total_benign": self.total_benign,
                "total_malicious": self.total_malicious,
                "true_positives": self.tp,
                "false_positives": self.fp,
                "true_negatives": self.tn,
                "false_negatives": self.fn,
                "inconclusive_benign": self.inconclusive_benign,
                "inconclusive_malicious": self.inconclusive_malicious,
                "extraction_failures": self.extraction_failures,
            },
            "metrics_decisive": {
                "precision": self.precision(),
                "precision_ci_95": self.precision_ci(),
                "precision_denominator": self.decisive_positives,
                "recall": self.recall(),
                "recall_ci_95": self.recall_ci(),
                "recall_denominator": self.tp + self.fn,
                "specificity": self.specificity(),
                "specificity_ci_95": self.specificity_ci(),
                "specificity_denominator": self.tn + self.fp,
                "false_positive_rate": self.false_positive_rate(),
                "false_positive_rate_ci_95": self.false_positive_rate_ci(),
                "false_positive_rate_denominator": self.tn + self.fp,
                "false_negative_rate": self.false_negative_rate(),
                "false_negative_rate_ci_95": self.false_negative_rate_ci(),
                "false_negative_rate_denominator": self.tp + self.fn,
                "accuracy": self.decisive_accuracy(),
                "accuracy_ci_95": self.decisive_accuracy_ci(),
                "accuracy_denominator": self.total_decisive,
                "f1_score": self.f1_score(),
            },
            "metrics_operational": {
                "operational_accuracy": self.operational_accuracy(),
                "operational_accuracy_ci_95": self.operational_accuracy_ci(),
                "operational_accuracy_denominator": self.total_samples,
                "coverage": self.coverage(),
                "abstention_rate": self.abstention_rate(),
                "inconclusive_rate_benign": self.inconclusive_rate_benign(),
                "inconclusive_rate_malicious": self.inconclusive_rate_malicious(),
                "extraction_failure_rate": self.extraction_failure_rate(),
            },
        }
