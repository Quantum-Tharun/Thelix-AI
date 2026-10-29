"""
Report Builder
Constructs the final, authoritative Security Assessment Report.
Maintains structured findings, traceable evidence, analytical limitations, and governance metadata.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import List, Dict, Any, Optional

from risk_engine.evidence import Evidence, Finding, ActionVerdict, RiskLevel
from risk_engine.coverage import CoverageAssessment


class VerdictCategory(str, Enum):
    LIKELY_SAFE = "LIKELY_SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    PHISHING_OR_SCAM = "PHISHING_OR_SCAM"
    MALWARE_INDICATORS_DETECTED = "MALWARE_INDICATORS_DETECTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    UNSUPPORTED_INPUT = "UNSUPPORTED_INPUT"


@dataclass
class SecurityReport:
    """
    Authoritative, structured report returned by the Thelix AI Risk Engine.
    """
    scan_id: str
    target_url: str
    normalized_url: str
    scan_status: str                            # e.g., 'completed', 'partial', 'failed', 'rejected'
    risk_score: int                             # 0 - 100
    trust_score: int                            # 100 - risk_score
    risk_level: RiskLevel                       # LOW, MEDIUM, HIGH, CRITICAL
    confidence: float                           # 0.0 - 1.0
    coverage_ratio: float                       # 0.0 - 1.0
    recommended_action: ActionVerdict           # ALLOW, WARN, BLOCK, INCONCLUSIVE
    summary: str
    findings: List[Finding] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    checks_completed: List[str] = field(default_factory=list)
    checks_failed: List[str] = field(default_factory=list)
    checks_skipped: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    recommended_next_steps: List[str] = field(default_factory=list)
    policy_version: str = "1.0.0"
    engine_versions: Dict[str, str] = field(default_factory=dict)
    explanation: Optional[str] = None
    inspection_type: str = "static_analysis_and_threat_intelligence"
    score_interpretation: str = "The risk score (0-100) is an ordinal severity index, not a percentage probability of compromise."
    principal_evidence: List[Dict[str, Any]] = field(default_factory=list)
    verdict_rationale: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # User-facing outcome categories and transparent sections
    verdict_category: str = VerdictCategory.LIKELY_SAFE.value
    verdict_label: str = "Likely safe / no significant threat detected"
    why_this_result: str = ""
    what_we_checked: List[Dict[str, Any]] = field(default_factory=list)
    what_we_could_not_check: List[Dict[str, Any]] = field(default_factory=list)
    next_steps: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "normalized_url": self.normalized_url,
            "scan_status": self.scan_status,
            "risk_score": self.risk_score,
            "trust_score": self.trust_score,
            "risk_level": self.risk_level.value,
            "confidence": round(self.confidence, 4),
            "coverage_ratio": round(self.coverage_ratio, 4),
            "recommended_action": self.recommended_action.value,
            "verdict_category": self.verdict_category,
            "verdict_label": self.verdict_label,
            "why_this_result": self.why_this_result or self.explanation or self.summary,
            "what_we_checked": self.what_we_checked,
            "what_we_could_not_check": self.what_we_could_not_check,
            "next_steps": self.next_steps or self.recommended_next_steps,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
            "evidence": [e.to_dict() for e in self.evidence],
            "checks_completed": self.checks_completed,
            "checks_failed": self.checks_failed,
            "checks_skipped": self.checks_skipped,
            "limitations": self.limitations,
            "recommended_next_steps": self.recommended_next_steps,
            "policy_version": self.policy_version,
            "engine_versions": self.engine_versions,
            "explanation": self.explanation,
            "inspection_type": self.inspection_type,
            "score_interpretation": self.score_interpretation,
            "principal_evidence": self.principal_evidence,
            "verdict_rationale": self.verdict_rationale,
            "created_at": self.created_at.isoformat(),
        }


class ReportBuilder:
    """
    Assembles evidence, findings, scores, and policy verdicts into a unified SecurityReport.
    """

    @classmethod
    def build(
        cls,
        scan_id: str,
        target_url: str,
        normalized_url: str,
        scan_status: str,
        risk_score: int,
        trust_score: int,
        risk_level: RiskLevel,
        confidence: float,
        coverage: CoverageAssessment,
        action: ActionVerdict,
        summary: str,
        findings: List[Finding],
        evidence: List[Evidence],
        recommendations: List[str],
        engine_versions: Dict[str, str],
        policy_version: str = "1.0.0",
        explanation: Optional[str] = None,
        inspection_type: str = "static_analysis_and_threat_intelligence",
    ) -> SecurityReport:
        # Build principal evidence summaries for high/medium findings
        principal_evidence = []
        for f in findings:
            principal_evidence.append({
                "finding_code": f.finding_code,
                "title": f.title,
                "severity": f.severity.value,
                "confidence": round(f.confidence, 4),
                "source_engine": f.source_engine,
                "evidence_count": len(f.evidence_references),
                "observed_versus_inferred": getattr(f, "observed_versus_inferred", "directly_observed"),
            })

        # Build transparent verdict rationale
        rationale_parts = [
            f"Verdict: {action.value.upper()} (Risk Score: {risk_score}/100, Trust Score: {trust_score}/100).",
            f"Inspection Type: {inspection_type}.",
            f"Coverage: {len(coverage.completed_checks)} check(s) completed ({int(coverage.coverage_ratio * 100)}%), {len(coverage.failed_checks)} failed.",
        ]
        if findings:
            top_finding = findings[0]
            rationale_parts.append(
                f"Primary Threat Indicator: {top_finding.title} (Severity: {top_finding.severity.value.upper()}, Finding Code: {top_finding.finding_code})."
            )
        else:
            rationale_parts.append("Primary Threat Indicator: None. No suspicious structural or reputation signals identified.")

        if coverage.limitations:
            rationale_parts.append(f"Analytical Limitations: {'; '.join(coverage.limitations[:3])}.")

        verdict_rationale = " ".join(rationale_parts)

        # Map to defined user-facing vocabulary
        if scan_status.lower() in ("rejected", "unsupported"):
            verdict_category = VerdictCategory.UNSUPPORTED_INPUT.value
            verdict_label = "Unsupported input: format cannot be reliably analyzed"
        elif action == ActionVerdict.INCONCLUSIVE:
            verdict_category = VerdictCategory.INCONCLUSIVE.value
            verdict_label = "Inconclusive / insufficient coverage: target could not be verified"
        elif action == ActionVerdict.BLOCK:
            is_malware = any(
                "malware" in f.title.lower() or "trojan" in f.title.lower() or
                ("malware" in f.description.lower() and f.source_engine in ("virustotal", "safebrowsing"))
                for f in findings
            )
            if is_malware:
                verdict_category = VerdictCategory.MALWARE_INDICATORS_DETECTED.value
                verdict_label = "Malware indicators detected"
            else:
                verdict_category = VerdictCategory.PHISHING_OR_SCAM.value
                verdict_label = "Phishing / scam indicators detected"
        elif action == ActionVerdict.WARN:
            verdict_category = VerdictCategory.SUSPICIOUS.value
            verdict_label = "Suspicious: meaningful risk indicators require caution"
        else:
            verdict_category = VerdictCategory.LIKELY_SAFE.value
            verdict_label = "Likely safe / no significant threat detected"

        what_we_checked = [
            {"check": c, "status": "completed"} for c in coverage.completed_checks
        ]
        what_we_could_not_check = [
            {"check": c, "status": "failed", "reason": "Check execution failed or provider timed out"}
            for c in coverage.failed_checks
        ] + [
            {"check": c, "status": "skipped", "reason": "Check was not requested or prerequisites not met"}
            for c in coverage.skipped_checks
        ]
        if coverage.limitations:
            for lim in coverage.limitations:
                what_we_could_not_check.append({
                    "check": "capability_limitation",
                    "status": "limited",
                    "reason": lim,
                })

        next_steps = recommendations if recommendations else []
        why_this_result = explanation or summary

        return SecurityReport(
            scan_id=scan_id,
            target_url=target_url,
            normalized_url=normalized_url,
            scan_status=scan_status,
            risk_score=risk_score,
            trust_score=trust_score,
            risk_level=risk_level,
            confidence=confidence,
            coverage_ratio=coverage.coverage_ratio,
            recommended_action=action,
            summary=summary,
            findings=findings,
            evidence=evidence,
            checks_completed=coverage.completed_checks,
            checks_failed=coverage.failed_checks,
            checks_skipped=coverage.skipped_checks,
            limitations=coverage.limitations,
            recommended_next_steps=recommendations,
            policy_version=policy_version,
            engine_versions=engine_versions,
            explanation=explanation,
            inspection_type=inspection_type,
            score_interpretation="The risk score (0-100) is an ordinal severity index, not a percentage probability of compromise.",
            principal_evidence=principal_evidence,
            verdict_rationale=verdict_rationale,
            verdict_category=verdict_category,
            verdict_label=verdict_label,
            why_this_result=why_this_result,
            what_we_checked=what_we_checked,
            what_we_could_not_check=what_we_could_not_check,
            next_steps=next_steps,
        )
