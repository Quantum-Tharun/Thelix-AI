"""
Tests for Risk Engine Evaluation, Policy Consistency, and Calibration (Phase 11)
Verifies severity floors, non-cancellation of threats, deduplication bounding,
missing intel handling, low-coverage/low-confidence inconclusive behavior,
conflicting provider resolution, and bit-for-bit reproducibility.
"""
import pytest
import asyncio
from unittest.mock import MagicMock, patch

from risk_engine.engine import RiskEngine
from risk_engine.evidence import Evidence, Finding, Severity, ActionVerdict, RiskLevel
from risk_engine.evidence_aggregator import EvidenceAggregator
from risk_engine.scoring import ScoringEngine
from risk_engine.policy import PolicyEngine
from risk_engine.coverage import CoverageTracker, CoverageAssessment
from risk_engine.reputation_analyzer import ReputationStatus, ReputationResult, MockThreatIntelProvider
from ai_engineering.evaluation.eval_runner import EvaluationRunner


def test_critical_evidence_enforces_severity_floor_and_block():
    """Verify that any CRITICAL finding enforces risk_score >= 86 and triggers ActionVerdict.BLOCK."""
    finding = Finding(
        finding_code="FIND-REP-CONFIRMED-MALICIOUS",
        title="Confirmed Malware",
        description="Target verified as malware distributor",
        severity=Severity.CRITICAL,
        confidence=0.50,  # Raw contribution would be 50, floor lifts to 86
        source_engine="threat_intel",
        source_version="1.0.0",
    )

    score, trust, level, meta = ScoringEngine.calculate_score([finding])
    assert score >= ScoringEngine.CRITICAL_RISK_FLOOR
    assert score >= 86
    assert trust <= 14
    assert level == RiskLevel.CRITICAL
    assert meta["floor_applied"] == "CRITICAL_RISK_FLOOR"

    coverage = CoverageAssessment(planned_checks=[], completed_checks=[], failed_checks=[], skipped_checks=[], coverage_ratio=1.0)
    verdict, reason, recs = PolicyEngine.decide(
        risk_score=score,
        confidence=0.90,
        coverage=coverage,
        findings=[finding],
    )
    assert verdict == ActionVerdict.BLOCK
    assert "high-risk threats" in reason.lower() or "blocked" in reason.lower()


def test_high_evidence_enforces_severity_floor():
    """Verify that a HIGH severity finding with low raw confidence enforces risk_score >= 60."""
    finding = Finding(
        finding_code="FIND-URL-IP-HOST",
        title="IP Literal Host",
        description="IP used as host",
        severity=Severity.HIGH,
        confidence=0.20,  # Low raw confidence
        source_engine="static_analyzer",
        source_version="1.0.0",
    )

    score, trust, level, meta = ScoringEngine.calculate_score([finding])
    assert score >= ScoringEngine.HIGH_RISK_FLOOR
    assert score >= 60
    assert meta["floor_applied"] == "HIGH_RISK_FLOOR"


def test_benign_evidence_cannot_cancel_confirmed_malicious():
    """Verify that neutral/benign evidence cannot cancel or lower confirmed malicious evidence."""
    malicious_finding = Finding(
        finding_code="FIND-REP-CONFIRMED-MALICIOUS",
        title="Confirmed Phishing",
        description="Target verified as phishing",
        severity=Severity.CRITICAL,
        confidence=0.95,
        source_engine="threat_intel",
        source_version="1.0.0",
    )

    # 10 benign evidence observations
    benign_evidence = [
        Evidence(
            indicator_type="reputation_clean",
            indicator_value_or_reference="https://evil.com",
            source_engine=f"clean_engine_{i}",
            source_version="1.0.0",
            observation={"status": "clean"},
            reliability=0.90,
            confidence=0.90,
        ) for i in range(10)
    ]

    deduped_ev, consolidated_fn = EvidenceAggregator.aggregate(benign_evidence, [malicious_finding])
    score, trust, level, meta = ScoringEngine.calculate_score(consolidated_fn)

    # Score must remain >= 86 despite clean evidence
    assert score >= 86
    coverage = CoverageAssessment(planned_checks=[], completed_checks=[], failed_checks=[], skipped_checks=[], coverage_ratio=1.0)
    verdict, _, _ = PolicyEngine.decide(score, 0.90, coverage, consolidated_fn)
    assert verdict == ActionVerdict.BLOCK


def test_duplicate_and_correlated_evidence_bounded_aggregation():
    """Verify that multiple findings in the same correlation group are consolidated into one."""
    findings = [
        Finding(
            finding_code="FIND-URL-BRAND-IMPERSONATION",
            title=f"Brand Impersonation Hit {i}",
            description="Misleading brand",
            severity=Severity.HIGH,
            confidence=0.70,
            source_engine="static_analyzer",
            source_version="1.0.0",
            correlation_group="brand_impersonation",
            evidence_references=[f"ev_{i}"],
        ) for i in range(5)
    ]

    deduped_ev, consolidated = EvidenceAggregator.aggregate([], findings)
    assert len(consolidated) == 1
    assert consolidated[0].correlation_group == "brand_impersonation"
    # Merged evidence references preserved
    assert len(consolidated[0].evidence_references) == 5

    score, _, _, _ = ScoringEngine.calculate_score(consolidated)
    # Consolidated HIGH finding score is strictly bounded to the HIGH band (< 86), not elevated to CRITICAL
    assert score <= 80
    assert score < ScoringEngine.CRITICAL_RISK_FLOOR


@pytest.mark.asyncio
async def test_missing_reputation_does_not_become_negative_evidence():
    """Verify that when threat intelligence is unavailable, no finding is created and score is not penalized."""
    mock_prov = MockThreatIntelProvider(canned_status=ReputationStatus.UNAVAILABLE)
    engine = RiskEngine(reputation_providers=[mock_prov], enable_reputation=True)

    report = await engine.analyze_url("https://example.com/clean-path")

    # No findings generated from the missing provider
    assert len(report.findings) == 0
    assert report.risk_score == 0
    assert report.trust_score == 100
    assert report.recommended_action == ActionVerdict.ALLOW


def test_low_coverage_produces_inconclusive_verdict():
    """Verify that low engine coverage (< 50%) yields INCONCLUSIVE, never ALLOW, even if risk_score == 0."""
    low_cov = CoverageAssessment(
        planned_checks=["input_validation", "url_normalization", "static_analysis", "reputation", "sandbox"],
        completed_checks=["input_validation", "url_normalization"],
        failed_checks=["static_analysis", "reputation", "sandbox"],
        skipped_checks=[],
        coverage_ratio=0.40,  # 40% < 50%
    )

    verdict, reason, _ = PolicyEngine.decide(
        risk_score=0,
        confidence=0.90,
        coverage=low_cov,
        findings=[],
    )
    assert verdict == ActionVerdict.INCONCLUSIVE
    assert "cannot verify safety" in reason.lower() or "incomplete" in reason.lower()


def test_low_confidence_produces_inconclusive_verdict():
    """Verify that low analytical confidence (< 50%) yields INCONCLUSIVE, not ALLOW."""
    good_cov = CoverageAssessment(
        planned_checks=["check1", "check2"],
        completed_checks=["check1", "check2"],
        failed_checks=[],
        skipped_checks=[],
        coverage_ratio=1.0,
    )

    verdict, reason, _ = PolicyEngine.decide(
        risk_score=5,         # Low risk score
        confidence=0.35,      # Low confidence (< 0.50)
        coverage=good_cov,
        findings=[],
    )
    assert verdict == ActionVerdict.INCONCLUSIVE
    assert "confidence is low" in reason.lower()


@pytest.mark.asyncio
async def test_conflicting_provider_responses_follow_policy():
    """Verify that when Provider A reports NO_MATCH but Provider B reports CONFIRMED_MALICIOUS, malicious hit wins."""
    prov_clean = MockThreatIntelProvider(canned_status=ReputationStatus.NO_MATCH)
    prov_clean.name = "provider_clean"

    prov_mal = MockThreatIntelProvider(
        canned_status=ReputationStatus.CONFIRMED_MALICIOUS,
        positives_count=15,
        threat_types=["PHISHING"],
    )
    prov_mal.name = "provider_malicious"

    engine = RiskEngine(reputation_providers=[prov_clean, prov_mal], enable_reputation=True)
    report = await engine.analyze_url("https://conflicting-intel-target.com")

    assert report.recommended_action == ActionVerdict.BLOCK
    assert report.risk_score >= 86
    assert any(f.finding_code.startswith("FIND-REP-") for f in report.findings)


@pytest.mark.asyncio
async def test_deterministic_reproducibility_bit_for_bit():
    """Verify that multiple consecutive analyses of the same URL yield bit-for-bit identical results."""
    engine = RiskEngine(enable_reputation=False)
    target_url = "http://paypal-verification-alert.xyz/signin?ref=update"

    first_report = await engine.analyze_url(target_url, scan_id="test-repro-1")

    for i in range(20):
        next_report = await engine.analyze_url(target_url, scan_id=f"test-repro-{i+2}")
        assert next_report.risk_score == first_report.risk_score
        assert next_report.trust_score == first_report.trust_score
        assert next_report.risk_level == first_report.risk_level
        assert next_report.recommended_action == first_report.recommended_action
        assert [f.finding_code for f in next_report.findings] == [f.finding_code for f in first_report.findings]


@pytest.mark.asyncio
async def test_evaluation_runner_reproducibility_on_dataset():
    """Verify that EvaluationRunner produces expected consistent zero-error metrics on the tuning dataset split."""
    runner = EvaluationRunner()
    results = await runner.run_evaluation(split="tuning")

    cm = results["confusion_matrix"]
    m = results["metrics_decisive"]

    assert cm["true_positives"] == 15
    assert cm["true_negatives"] == 15
    assert cm["false_positives"] == 0
    assert cm["false_negatives"] == 0
    assert m["precision"] == 1.0
    assert m["recall"] == 1.0
    assert m["false_positive_rate"] == 0.0
    assert m["false_negative_rate"] == 0.0
