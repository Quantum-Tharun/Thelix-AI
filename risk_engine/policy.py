"""
Decision Policy Engine
Translates Risk Score, Confidence, Coverage, and Safety Constraints into an actionable verdict:
ALLOW, WARN, BLOCK, or INCONCLUSIVE.
"""
from typing import List, Tuple
from risk_engine.evidence import ActionVerdict, RiskLevel, Finding, Severity
from risk_engine.coverage import CoverageAssessment


class PolicyEngine:
    """
    Enforces governance and risk decision policies.
    Guarantees fail-safe behavior: low score with low coverage never yields ALLOW.
    """

    POLICY_VERSION = "1.0.0"

    # Thresholds
    MIN_COVERAGE_FOR_ALLOW = 0.50
    MIN_CONFIDENCE_FOR_ALLOW = 0.50

    BLOCK_SCORE_THRESHOLD = 75
    WARN_SCORE_THRESHOLD = 30

    @classmethod
    def decide(
        cls,
        risk_score: int,
        confidence: float,
        coverage: CoverageAssessment,
        findings: List[Finding]
    ) -> Tuple[ActionVerdict, str, List[str]]:
        """
        Evaluates policy rules and returns (verdict, policy_reason, recommendations).
        """
        # 1. Hard Block on Critical Findings
        has_critical = any(f.severity == Severity.CRITICAL for f in findings)
        if has_critical or risk_score >= cls.BLOCK_SCORE_THRESHOLD:
            return (
                ActionVerdict.BLOCK,
                f"Action blocked due to high-risk threats detected (Risk Score: {risk_score}/100).",
                [
                    "Do not open, visit, or enter credentials into this destination.",
                    "Delete the message, email, or QR code immediately.",
                    "Report this incident to your security administrator or service provider."
                ]
            )

        # 2. Inconclusive on Poor Coverage / Engine Failures
        if coverage.coverage_ratio < cls.MIN_COVERAGE_FOR_ALLOW:
            return (
                ActionVerdict.INCONCLUSIVE,
                f"Analysis incomplete: only {int(coverage.coverage_ratio * 100)}% of intended checks succeeded. Cannot verify safety.",
                [
                    "Exercise extreme caution; the destination could not be fully verified.",
                    "Do not submit sensitive personal, financial, or authentication details.",
                    "Verify the source through a secondary authenticated channel before proceeding."
                ]
            )

        # 3. Warning on Medium Risk or Moderate Confidence
        if risk_score >= cls.WARN_SCORE_THRESHOLD:
            return (
                ActionVerdict.WARN,
                f"Suspicious indicators detected (Risk Score: {risk_score}/100). Proceed with caution.",
                [
                    "Review the domain name carefully for subtle spelling changes or brand impersonation.",
                    "Do not download files or authorize financial transactions.",
                    "Verify the legitimacy of this link directly with the apparent sender."
                ]
            )

        # 4. Low Risk with Low Confidence is INCONCLUSIVE, not ALLOW
        if confidence < cls.MIN_CONFIDENCE_FOR_ALLOW:
            return (
                ActionVerdict.INCONCLUSIVE,
                f"No explicit threats detected, but analytical confidence is low ({int(confidence * 100)}%).",
                [
                    "Exercise caution as this target is novel or unverified in threat databases.",
                    "Avoid entering passwords or sensitive personal data."
                ]
            )

        # 5. Allow only when Risk is Low, Coverage is Sufficient, and Confidence is High
        return (
            ActionVerdict.ALLOW,
            f"No malicious or suspicious indicators detected across {int(coverage.coverage_ratio * 100)}% coverage (Trust Score: {100 - risk_score}/100).",
            [
                "No known security threats were identified during analysis.",
                "Always verify HTTPS certificates when entering sensitive credentials."
            ]
        )
