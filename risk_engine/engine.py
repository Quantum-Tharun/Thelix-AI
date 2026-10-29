"""
Thelix AI Risk Engine
Central coordinator for deterministic security risk assessment.
Processes URLs, aggregates multi-detector evidence, applies policy, and emits authoritative reports.
"""
from typing import List, Optional, Dict, Any, Tuple
import uuid
import logging

from risk_engine.input_validator import InputValidator
from risk_engine.url_normalizer import URLNormalizer, NormalizedURL
from risk_engine.static_analyzer import StaticURLAnalyzer
from risk_engine.reputation_analyzer import ReputationAnalyzer, ReputationProvider
from risk_engine.evidence import Evidence, Finding, ActionVerdict, RiskLevel, Severity
from risk_engine.evidence_aggregator import EvidenceAggregator
from risk_engine.scoring import ScoringEngine
from risk_engine.confidence import ConfidenceCalculator
from risk_engine.coverage import CoverageTracker, CoverageAssessment
from risk_engine.policy import PolicyEngine
from risk_engine.report_builder import ReportBuilder, SecurityReport
from risk_engine.exceptions import (
    ValidationError,
    MalformedURLException,
    UnsupportedSchemeException,
)

logger = logging.getLogger("thelix.risk_engine")


class RiskEngine:
    """
    Deterministic Risk Engine for Thelix AI.
    Combines static analysis, threat intelligence, and isolated inspection into an authoritative report.
    """
    POLICY_VERSION = "1.0.0"

    def __init__(
        self,
        reputation_providers: Optional[List[ReputationProvider]] = None,
        enable_reputation: bool = True,
    ):
        self.reputation_analyzer = (
            ReputationAnalyzer(reputation_providers) if enable_reputation else None
        )
        self.engine_versions = {
            "risk_engine_policy": self.POLICY_VERSION,
            "static_url_analyzer": StaticURLAnalyzer.ENGINE_VERSION,
            "url_normalizer": "1.0.0",
        }

    async def analyze_url(
        self,
        raw_url: str,
        scan_id: Optional[str] = None,
        additional_evidence: Optional[List[Evidence]] = None,
        additional_findings: Optional[List[Finding]] = None,
        explanation: Optional[str] = None,
        normalized_url: Optional[NormalizedURL] = None,
    ) -> SecurityReport:
        """
        Executes complete risk evaluation workflow for a given URL.
        """
        scan_id = scan_id or str(uuid.uuid4())
        planned_checks = ["input_validation", "url_normalization", "static_analysis"]
        completed_checks: List[str] = []
        failed_checks: List[str] = []
        skipped_checks: List[str] = []

        # 1. Validation & Normalization
        if normalized_url is not None:
            norm = normalized_url
            completed_checks.extend(["input_validation", "url_normalization"])
        else:
            try:
                norm: NormalizedURL = URLNormalizer.normalize(raw_url)
                completed_checks.extend(["input_validation", "url_normalization"])
            except (ValidationError, MalformedURLException, UnsupportedSchemeException) as e:
                failed_checks.append("input_validation")
                coverage = CoverageTracker.evaluate(
                    planned=planned_checks,
                    completed=completed_checks,
                    failed=failed_checks,
                    skipped=skipped_checks + ["url_normalization", "static_analysis"],
                )
                # Rejected target report
                return ReportBuilder.build(
                    scan_id=scan_id,
                    target_url=str(raw_url)[:500],
                    normalized_url="",
                    scan_status="rejected",
                    risk_score=100,
                    trust_score=0,
                    risk_level=RiskLevel.CRITICAL,
                    confidence=1.0,
                    coverage=coverage,
                    action=ActionVerdict.BLOCK,
                    summary=f"Input rejected: {e.message}",
                    findings=[Finding(
                        finding_code=e.code,
                        title="Invalid or Prohibited Input",
                        description=e.message,
                        severity=Severity.CRITICAL,
                        confidence=1.0,
                        source_engine="input_validator",
                        source_version="1.0.0",
                    )],
                    evidence=[],
                    recommendations=["Do not attempt to process malformed or prohibited inputs."],
                    engine_versions=self.engine_versions,
                    policy_version=self.POLICY_VERSION,
                )

        raw_evidence: List[Evidence] = []
        raw_findings: List[Finding] = []

        # 2. Static URL Analysis
        try:
            static_ev, static_fn = StaticURLAnalyzer.analyze(norm)
            raw_evidence.extend(static_ev)
            raw_findings.extend(static_fn)
            completed_checks.append("static_analysis")
        except Exception as e:
            logger.error(f"Static analysis failed: {e}")
            failed_checks.append("static_analysis")

        # 3. Reputation Intelligence (if enabled and configured)
        has_active_providers = bool(self.reputation_analyzer and self.reputation_analyzer.providers)
        if has_active_providers:
            planned_checks.append("reputation_analysis")
            try:
                rep_ev, rep_fn, rep_meta = await self.reputation_analyzer.analyze(norm)
                raw_evidence.extend(rep_ev)
                raw_findings.extend(rep_fn)

                # Only report completed if at least one provider was available/queried
                any_queried = any(meta.get("available") for meta in rep_meta.values()) if rep_meta else False
                if any_queried:
                    completed_checks.append("reputation_analysis")
                else:
                    failed_checks.append("reputation_analysis")
            except Exception as e:
                logger.warning(f"Reputation checks failed: {e}")
                failed_checks.append("reputation_analysis")
        else:
            skipped_checks.append("external_threat_intelligence")

        # 4. Integrate Additional Evidence (e.g. from Sandbox or OCR)
        if additional_evidence:
            raw_evidence.extend(additional_evidence)
        if additional_findings:
            raw_findings.extend(additional_findings)

        # 5. Evidence Deduplication & Consolidation
        deduped_evidence, consolidated_findings = EvidenceAggregator.aggregate(
            raw_evidence, raw_findings
        )

        # 6. Deterministic Risk Scoring
        risk_score, trust_score, risk_level, audit_meta = ScoringEngine.calculate_score(
            consolidated_findings
        )

        # 7. Coverage Assessment
        coverage = CoverageTracker.evaluate(
            planned=planned_checks,
            completed=completed_checks,
            failed=failed_checks,
            skipped=skipped_checks,
        )

        # 8. Confidence Calculation
        confidence = ConfidenceCalculator.calculate(
            evidence=deduped_evidence,
            findings=consolidated_findings,
            coverage_ratio=coverage.coverage_ratio,
        )

        # 9. Policy Decision
        action, policy_reason, recommendations = PolicyEngine.decide(
            risk_score=risk_score,
            confidence=confidence,
            coverage=coverage,
            findings=consolidated_findings,
        )

        # 10. Generate Summary
        if action == ActionVerdict.BLOCK:
            summary = f"High-risk threats detected: destination blocked (Trust Score: {trust_score}/100)."
        elif action == ActionVerdict.WARN:
            summary = f"Suspicious activity detected: proceed with caution (Trust Score: {trust_score}/100)."
        elif action == ActionVerdict.INCONCLUSIVE:
            summary = f"Assessment inconclusive: {policy_reason}"
        else:
            summary = f"No security threats detected across completed checks (Trust Score: {trust_score}/100)."

        status = "completed" if not failed_checks else "partial"

        return ReportBuilder.build(
            scan_id=scan_id,
            target_url=norm.raw_url,
            normalized_url=norm.normalized_url,
            scan_status=status,
            risk_score=risk_score,
            trust_score=trust_score,
            risk_level=risk_level,
            confidence=confidence,
            coverage=coverage,
            action=action,
            summary=summary,
            findings=consolidated_findings,
            evidence=deduped_evidence,
            recommendations=recommendations,
            engine_versions=self.engine_versions,
            policy_version=self.POLICY_VERSION,
            explanation=explanation,
        )
