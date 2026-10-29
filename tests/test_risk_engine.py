"""
Comprehensive Unit Tests for Risk Engine
Tests input validation, normalization, static heuristics, scoring, confidence, coverage, policy, and edge cases.
"""
import pytest
import asyncio
from risk_engine.engine import RiskEngine
from risk_engine.input_validator import InputValidator
from risk_engine.url_normalizer import URLNormalizer
from risk_engine.static_analyzer import StaticURLAnalyzer
from risk_engine.evidence import Evidence, Finding, Severity, ActionVerdict, RiskLevel
from risk_engine.evidence_aggregator import EvidenceAggregator
from risk_engine.scoring import ScoringEngine
from risk_engine.confidence import ConfidenceCalculator
from risk_engine.coverage import CoverageTracker
from risk_engine.policy import PolicyEngine
from risk_engine.exceptions import (
    ValidationError,
    MalformedURLException,
    UnsupportedSchemeException,
)


@pytest.mark.asyncio
async def test_valid_https_url():
    engine = RiskEngine(enable_reputation=False)
    report = await engine.analyze_url("https://www.example.com/about")

    assert report.scan_status == "completed"
    assert report.risk_score == 0
    assert report.trust_score == 100
    assert report.risk_level == RiskLevel.LOW
    assert report.recommended_action == ActionVerdict.ALLOW
    assert report.confidence >= 0.70
    assert report.coverage_ratio == 1.0


@pytest.mark.asyncio
async def test_valid_http_url():
    engine = RiskEngine(enable_reputation=False)
    report = await engine.analyze_url("http://sub.example.org/test?id=123")

    assert report.scan_status == "completed"
    assert report.risk_level == RiskLevel.LOW
    assert report.recommended_action == ActionVerdict.ALLOW


@pytest.mark.asyncio
async def test_empty_input():
    engine = RiskEngine(enable_reputation=False)
    report = await engine.analyze_url("   ")

    assert report.scan_status == "rejected"
    assert report.risk_score == 100
    assert report.recommended_action == ActionVerdict.BLOCK
    assert len(report.findings) > 0


@pytest.mark.asyncio
async def test_unsupported_scheme():
    engine = RiskEngine(enable_reputation=False)
    for bad_url in [
        "javascript:alert(1)",
        "file:///etc/passwd",
        "data:text/html,test",
        "ftp://ftp.example.com",
    ]:
        report = await engine.analyze_url(bad_url)
        assert report.scan_status == "rejected"
        assert report.recommended_action == ActionVerdict.BLOCK


@pytest.mark.asyncio
async def test_malformed_url():
    engine = RiskEngine(enable_reputation=False)
    report = await engine.analyze_url("https://")
    assert report.scan_status == "rejected"
    assert report.recommended_action == ActionVerdict.BLOCK


@pytest.mark.asyncio
async def test_null_byte_injection():
    engine = RiskEngine(enable_reputation=False)
    report = await engine.analyze_url("https://example.com/test%00.php")
    assert report.scan_status == "rejected"
    assert report.recommended_action == ActionVerdict.BLOCK


@pytest.mark.asyncio
async def test_excessively_long_url():
    engine = RiskEngine(enable_reputation=False)
    long_url = "https://example.com/" + "a" * 5000
    report = await engine.analyze_url(long_url)
    assert report.scan_status == "rejected"
    assert report.recommended_action == ActionVerdict.BLOCK


@pytest.mark.asyncio
async def test_ip_literal_hostname():
    engine = RiskEngine(enable_reputation=False)
    report = await engine.analyze_url("http://198.51.100.1/login")

    assert report.risk_score >= 60  # High risk floor
    assert any(f.finding_code == "FIND-URL-IP-HOST" for f in report.findings)
    assert report.recommended_action in (ActionVerdict.BLOCK, ActionVerdict.WARN)


@pytest.mark.asyncio
async def test_userinfo_trick():
    engine = RiskEngine(enable_reputation=False)
    report = await engine.analyze_url("https://google.com@evil-phishing.com/signin")

    assert report.risk_score >= 60
    assert any(f.finding_code == "FIND-URL-USERINFO" for f in report.findings)
    assert report.recommended_action == ActionVerdict.BLOCK


@pytest.mark.asyncio
async def test_misleading_brand_subdomain():
    engine = RiskEngine(enable_reputation=False)
    report = await engine.analyze_url("https://paypal.com.account-verify-support.net/login")

    assert report.risk_score >= 60
    assert any(f.finding_code == "FIND-URL-BRAND-IMPERSONATION" for f in report.findings)
    assert report.recommended_action in (ActionVerdict.BLOCK, ActionVerdict.WARN)


@pytest.mark.asyncio
async def test_idn_homograph_attack():
    engine = RiskEngine(enable_reputation=False)
    # Cyrillic 'а' in 'раypal.com'
    cyrillic_url = "https://pаypal.com/signin"
    report = await engine.analyze_url(cyrillic_url)

    assert any(f.finding_code == "FIND-URL-HOMOGRAPH" for f in report.findings)
    assert report.risk_score >= 50


@pytest.mark.asyncio
async def test_suspicious_tld():
    engine = RiskEngine(enable_reputation=False)
    report = await engine.analyze_url("https://free-gifts.click")

    assert any(f.finding_code == "FIND-URL-SUSPICIOUS-TLD" for f in report.findings)
    assert report.risk_level in (RiskLevel.LOW, RiskLevel.MEDIUM)


@pytest.mark.asyncio
async def test_double_percent_encoding():
    engine = RiskEngine(enable_reputation=False)
    report = await engine.analyze_url("https://example.com/%252e%252e/admin")

    assert any(f.finding_code == "FIND-URL-DOUBLE-ENCODING" for f in report.findings)


@pytest.mark.asyncio
async def test_open_redirect_parameters():
    engine = RiskEngine(enable_reputation=False)
    report = await engine.analyze_url("https://legit-site.com/login?redirect=https://evil.com/steal")

    assert any(f.finding_code == "FIND-URL-REDIRECT-PARAM" for f in report.findings)


@pytest.mark.asyncio
async def test_evidence_deduplication_and_correlation():
    ev1 = Evidence(
        indicator_type="ip_literal",
        indicator_value_or_reference="198.51.100.1",
        source_engine="engine_a",
        reliability=0.9,
        correlation_group="host_ip",
    )
    ev2 = Evidence(
        indicator_type="ip_literal",
        indicator_value_or_reference="198.51.100.1",
        source_engine="engine_a",  # Duplicate
        reliability=0.9,
        correlation_group="host_ip",
    )
    ev3 = Evidence(
        indicator_type="ip_host",
        indicator_value_or_reference="198.51.100.1",
        source_engine="engine_b",  # Correlated
        reliability=0.85,
        correlation_group="host_ip",
    )

    f1 = Finding(
        finding_code="FIND-1",
        title="Finding 1",
        description="Desc 1",
        severity=Severity.HIGH,
        confidence=0.8,
        source_engine="engine_a",
        source_version="1.0",
        evidence_references=[ev1.evidence_id],
        correlation_group="host_ip",
    )
    f2 = Finding(
        finding_code="FIND-2",
        title="Finding 2",
        description="Desc 2",
        severity=Severity.MEDIUM,
        confidence=0.7,
        source_engine="engine_b",
        source_version="1.0",
        evidence_references=[ev3.evidence_id],
        correlation_group="host_ip",
    )

    deduped_ev, consolidated_fn = EvidenceAggregator.aggregate([ev1, ev2, ev3], [f1, f2])

    assert len(deduped_ev) == 2  # Duplicate removed
    assert len(consolidated_fn) == 1  # Grouped by correlation_group
    assert consolidated_fn[0].severity == Severity.HIGH  # Max severity retained
    assert set(consolidated_fn[0].evidence_references) == {ev1.evidence_id, ev3.evidence_id}


@pytest.mark.asyncio
async def test_poor_coverage_yields_inconclusive_never_allow():
    """Verify hard requirement: A low score with poor coverage must NOT automatically produce an allow decision."""
    coverage = CoverageTracker.evaluate(
        planned=["check1", "check2", "check3", "check4"],
        completed=["check1"],  # only 25% coverage
        failed=["check2", "check3"],
        skipped=["check4"],
    )
    verdict, reason, recs = PolicyEngine.decide(
        risk_score=0,  # Zero risk score!
        confidence=0.9,
        coverage=coverage,
        findings=[],
    )

    assert verdict == ActionVerdict.INCONCLUSIVE
    assert "incomplete" in reason.lower()


@pytest.mark.asyncio
async def test_conflicting_findings_reputation_safe_vs_malicious_heuristics():
    """Verify that a safe reputation result does NOT dilute or cancel malicious static findings."""
    engine = RiskEngine(enable_reputation=False)
    # Target exhibits deceptive brand impersonation
    url = "https://paypal.com.phishingsite.com/login"
    report = await engine.analyze_url(url)

    assert report.risk_score >= 60
    assert report.recommended_action in (ActionVerdict.BLOCK, ActionVerdict.WARN)
    assert report.recommended_action != ActionVerdict.ALLOW


@pytest.mark.asyncio
async def test_missing_intelligence_does_not_prove_safety():
    """Verify that when planned checks fail or intelligence is unavailable, action defaults to INCONCLUSIVE, not ALLOW."""
    coverage = CoverageTracker.evaluate(
        planned=["static_url_analysis", "safebrowsing_check", "virustotal_check"],
        completed=["static_url_analysis"],
        failed=["safebrowsing_check", "virustotal_check"],
        skipped=[],
    )
    # Risk score is 0 because static analysis found nothing, but intelligence failed
    verdict, reason, recs = PolicyEngine.decide(
        risk_score=0,
        confidence=0.5,
        coverage=coverage,
        findings=[],
    )
    assert verdict == ActionVerdict.INCONCLUSIVE
    assert verdict != ActionVerdict.ALLOW


def test_scoring_floors_for_critical_and_high_severity():
    """Verify non-linear bounded scoring floors for Critical (>=86) and High (>=60) threats."""
    critical_finding = Finding(
        finding_code="CRIT-1",
        title="Active Malware Payload",
        description="Confirmed malicious binary",
        severity=Severity.CRITICAL,
        confidence=0.95,
        source_engine="threat_intel",
        source_version="1.0",
    )
    score_crit, trust_crit, level_crit, meta_crit = ScoringEngine.calculate_score([critical_finding])
    assert score_crit >= 86
    assert trust_crit <= 14
    assert level_crit == RiskLevel.CRITICAL

    high_finding = Finding(
        finding_code="HIGH-1",
        title="Credential Harvesting Form",
        description="Password submission detected",
        severity=Severity.HIGH,
        confidence=0.85,
        source_engine="dom_analyzer",
        source_version="1.0",
    )
    score_high, trust_high, level_high, meta_high = ScoringEngine.calculate_score([high_finding])
    assert score_high >= 60
    assert trust_high <= 40
    assert level_high in (RiskLevel.HIGH, RiskLevel.CRITICAL)


