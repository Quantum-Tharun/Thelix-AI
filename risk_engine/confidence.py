"""
Confidence Calculator
Quantifies the statistical reliability and certainty of the assessment.
Separates confidence (epistemic uncertainty) from risk severity (potential impact).
"""
from typing import List
from risk_engine.evidence import Evidence, Finding


class ConfidenceCalculator:
    """
    Computes overall confidence score [0.0 - 1.0] for an assessment.
    """

    @classmethod
    def calculate(
        cls,
        evidence: List[Evidence],
        findings: List[Finding],
        coverage_ratio: float
    ) -> float:
        """
        Calculates holistic confidence based on evidence volume, source reliability,
        engine corroboration, and coverage ratio.
        """
        if not evidence and not findings:
            # When no threat evidence is found, confidence is directly bounded by analysis coverage
            # E.g. If we only completed 30% of checks, our confidence in "safe" is at most 0.30
            return round(max(0.10, min(coverage_ratio * 0.90, 0.95)), 4)

        # Average reliability of contributing evidence sources
        reliabilities = [e.reliability for e in evidence if e.reliability > 0]
        avg_reliability = sum(reliabilities) / len(reliabilities) if reliabilities else 0.70

        # Corroboration across independent source engines
        unique_engines = {e.source_engine for e in evidence}
        corroboration_factor = min(1.0, 0.70 + (0.15 * (len(unique_engines) - 1)))

        # Average confidence of findings
        finding_confs = [f.confidence for f in findings]
        avg_finding_conf = sum(finding_confs) / len(finding_confs) if finding_confs else 0.70

        # Blended confidence: 40% evidence reliability, 30% corroboration, 30% coverage
        raw_conf = (
            (avg_reliability * 0.35) +
            (avg_finding_conf * 0.25) +
            (corroboration_factor * 0.20) +
            (coverage_ratio * 0.20)
        )

        return round(max(0.10, min(1.0, raw_conf)), 4)
