"""
Deterministic Scoring Engine
Versioned risk scoring algorithm.
Fuses atomic findings using non-linear bounded aggregation with explicit hard safety constraints.
"""
from typing import List, Tuple, Dict, Any
from risk_engine.evidence import Finding, Severity, RiskLevel

POLICY_VERSION = "1.0.0"


class ScoringEngine:
    """
    Computes deterministic, reproducible risk scores.
    """

    POLICY_VERSION = POLICY_VERSION

    # Floor constraints for confirmed severe threats (Rule of Maximum Danger)
    CRITICAL_RISK_FLOOR = 86
    HIGH_RISK_FLOOR = 60

    @classmethod
    def calculate_score(cls, findings: List[Finding]) -> Tuple[int, int, RiskLevel, Dict[str, Any]]:
        """
        Calculates:
        - risk_score: 0 to 100
        - trust_score: 100 - risk_score
        - risk_level: LOW, MEDIUM, HIGH, CRITICAL
        - audit_metadata: details on scoring calculation
        """
        if not findings:
            return 0, 100, RiskLevel.LOW, {
                "policy_version": cls.POLICY_VERSION,
                "base_score": 0,
                "floor_applied": None,
                "finding_contributions": [],
            }

        # Calculate bounded non-linear aggregation:
        # P(at least one finding is true and harmful) = 1 - prod(1 - c_i)
        # where c_i = severity_weight * confidence
        prod_complement = 1.0
        contributions: List[Dict[str, Any]] = []
        max_severity = Severity.INFO

        for f in findings:
            c_i = min(max(f.contribution, 0.0), 0.99)
            prod_complement *= (1.0 - c_i)
            contributions.append({
                "code": f.finding_code,
                "severity": f.severity.value,
                "confidence": round(f.confidence, 4),
                "contribution": round(c_i, 4),
            })
            if f.severity_weight > max_severity.weight:
                max_severity = f.severity

        aggregated_prob = 1.0 - prod_complement
        raw_score = int(round(aggregated_prob * 100))

        # Enforce Rule of Maximum Danger (floors for high/critical threats)
        floor_applied = None
        final_score = raw_score

        if max_severity == Severity.CRITICAL:
            if final_score < cls.CRITICAL_RISK_FLOOR:
                final_score = cls.CRITICAL_RISK_FLOOR
                floor_applied = "CRITICAL_RISK_FLOOR"
        elif max_severity == Severity.HIGH:
            if final_score < cls.HIGH_RISK_FLOOR:
                final_score = cls.HIGH_RISK_FLOOR
                floor_applied = "HIGH_RISK_FLOOR"

        # Hard clamping between 0 and 100
        risk_score = max(0, min(100, final_score))
        trust_score = 100 - risk_score
        risk_level = cls._map_risk_level(risk_score)

        audit_meta = {
            "policy_version": cls.POLICY_VERSION,
            "raw_score": raw_score,
            "risk_score": risk_score,
            "trust_score": trust_score,
            "floor_applied": floor_applied,
            "finding_contributions": contributions,
        }

        return risk_score, trust_score, risk_level, audit_meta

    @staticmethod
    def _map_risk_level(score: int) -> RiskLevel:
        if score <= 20:
            return RiskLevel.LOW
        elif score <= 50:
            return RiskLevel.MEDIUM
        elif score <= 85:
            return RiskLevel.HIGH
        else:
            return RiskLevel.CRITICAL
