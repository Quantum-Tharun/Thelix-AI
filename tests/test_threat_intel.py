"""
Unit and Integration Tests for Threat Intelligence and Reputation Subsystem (Phase 9)
Tests provider abstractions, caching, rate limits, timeouts, privacy sanitization,
evidence normalization, and Risk Engine integration.
"""
import pytest
import time
import httpx
from unittest.mock import patch, MagicMock

from risk_engine.url_normalizer import URLNormalizer
from risk_engine.evidence import Severity, ActionVerdict, RiskLevel
from risk_engine.reputation_analyzer import (
    ReputationStatus,
    ReputationResult,
    GoogleSafeBrowsingProvider,
    VirusTotalProvider,
    MockThreatIntelProvider,
    ReputationAnalyzer,
    PrivacySanitizer,
)
from risk_engine.reputation_cache import ReputationCache
from risk_engine.engine import RiskEngine


@pytest.fixture
def clean_cache():
    """Provides a fresh, isolated reputation cache."""
    return ReputationCache()


@pytest.fixture
def sample_url():
    return URLNormalizer.normalize("https://test-threat-domain.com/login?token=secret123&action=view")


@pytest.mark.asyncio
async def test_reputation_malicious_match(clean_cache, sample_url):
    """Verify that a confirmed malicious threat intel match produces a Critical finding."""
    mock_provider = MockThreatIntelProvider(
        canned_status=ReputationStatus.CONFIRMED_MALICIOUS,
        positives_count=12,
        threat_types=["MALWARE", "SOCIAL_ENGINEERING"],
        cache=clean_cache,
    )
    analyzer = ReputationAnalyzer(providers=[mock_provider], cache=clean_cache)
    ev_list, fn_list, meta = await analyzer.analyze(sample_url)

    assert len(ev_list) == 1
    assert ev_list[0].indicator_type == "reputation_mock_intel_match"
    assert ev_list[0].correlation_group == "threat_intel_match"
    assert ev_list[0].reliability >= 0.90

    assert len(fn_list) == 1
    assert fn_list[0].finding_code == "FIND-REP-MOCK_INTEL"
    assert fn_list[0].severity == Severity.CRITICAL
    assert fn_list[0].confidence >= 0.95


@pytest.mark.asyncio
async def test_reputation_no_match_does_not_prove_safety(clean_cache, sample_url):
    """Verify that a clean query (NO_MATCH) generates clean evidence but NO finding and NO score reduction."""
    mock_provider = MockThreatIntelProvider(
        canned_status=ReputationStatus.NO_MATCH,
        cache=clean_cache,
    )
    analyzer = ReputationAnalyzer(providers=[mock_provider], cache=clean_cache)
    ev_list, fn_list, meta = await analyzer.analyze(sample_url)

    # Generates clean evidence record for coverage, but 0 findings
    assert len(ev_list) == 1
    assert ev_list[0].indicator_type == "reputation_mock_intel_clean"
    assert len(fn_list) == 0  # No findings!


@pytest.mark.asyncio
async def test_virustotal_404_handled_as_no_match(clean_cache):
    """Verify that VirusTotal 404 (URL not seen) is normalized into NO_MATCH without throwing errors."""
    vt = VirusTotalProvider(api_key="mock_vt_key", cache=clean_cache)
    norm = URLNormalizer.normalize("https://unseen-site.org/index.html")

    # Mock HTTP 404 response from VirusTotal
    mock_resp = MagicMock()
    mock_resp.status_code = 404

    with patch("httpx.AsyncClient.get", return_value=mock_resp):
        res = await vt.check_url(norm)

    assert res.status == ReputationStatus.NO_MATCH
    assert res.is_available is True
    assert res.is_malicious is False


@pytest.mark.asyncio
async def test_provider_timeout_handled_gracefully(clean_cache):
    """Verify that provider network timeouts return UNAVAILABLE without crashing callers."""
    gsb = GoogleSafeBrowsingProvider(api_key="mock_key", timeout_seconds=1.0, cache=clean_cache)
    norm = URLNormalizer.normalize("https://slow-site.com")

    with patch("httpx.AsyncClient.post", side_effect=httpx.TimeoutException("Connection timed out")):
        res = await gsb.check_url(norm)

    assert res.status == ReputationStatus.UNAVAILABLE
    assert res.is_available is False
    assert "timed out" in res.error_message.lower()


@pytest.mark.asyncio
async def test_rate_limiting_records_backoff(clean_cache):
    """Verify that HTTP 429 causes RATE_LIMITED status and engages the backoff guard."""
    vt = VirusTotalProvider(api_key="mock_key", cache=clean_cache)
    norm = URLNormalizer.normalize("https://rate-limited-target.com")

    mock_resp = MagicMock()
    mock_resp.status_code = 429

    with patch("httpx.AsyncClient.get", return_value=mock_resp):
        res1 = await vt.check_url(norm)

    assert res1.status == ReputationStatus.RATE_LIMITED
    assert clean_cache.is_rate_limited("virustotal") is True

    # Immediate second call to a different URL should be throttled by cache backoff without HTTP calls
    norm2 = URLNormalizer.normalize("https://another-target.com")
    res2 = await vt.check_url(norm2)
    assert res2.status == ReputationStatus.RATE_LIMITED
    assert "throttled" in res2.error_message.lower()


def test_cache_ttl_and_expiration(clean_cache):
    """Verify that cache respects custom TTL and evicts expired records."""
    url = "https://cache-ttl-test.com"
    res = ReputationResult(
        provider_name="test_p",
        provider_version="1.0",
        status=ReputationStatus.CONFIRMED_MALICIOUS,
    )
    # Cache with 1 second TTL
    clean_cache.set("test_p", url, res, custom_ttl=1)
    assert clean_cache.get("test_p", url) is not None

    # Wait for expiration
    time.sleep(1.1)
    assert clean_cache.get("test_p", url) is None


@pytest.mark.asyncio
async def test_cache_deduplicates_repeated_lookups(clean_cache, sample_url):
    """Verify that duplicate lookups return from cache and do not re-query the provider."""
    mock_provider = MockThreatIntelProvider(
        canned_status=ReputationStatus.CONFIRMED_MALICIOUS,
        cache=clean_cache,
    )
    # First query
    res1 = await mock_provider.check_url(sample_url)
    assert mock_provider.call_count == 1

    # Second query for identical URL
    res2 = await mock_provider.check_url(sample_url)
    assert mock_provider.call_count == 1  # Did NOT call network again!
    assert res2.status == res1.status


@pytest.mark.asyncio
async def test_conflicting_provider_responses_preserves_malicious_finding(clean_cache, sample_url):
    """Verify that when Provider A returns clean but Provider B returns malicious, the threat finding is preserved."""
    p_clean = MockThreatIntelProvider(
        canned_status=ReputationStatus.NO_MATCH,
        cache=clean_cache,
    )
    p_clean.name = "provider_clean"

    p_malicious = MockThreatIntelProvider(
        canned_status=ReputationStatus.CONFIRMED_MALICIOUS,
        positives_count=8,
        threat_types=["PHISHING"],
        cache=clean_cache,
    )
    p_malicious.name = "provider_malicious"

    analyzer = ReputationAnalyzer(providers=[p_clean, p_malicious], cache=clean_cache)
    ev_list, fn_list, meta = await analyzer.analyze(sample_url)

    # Must contain the malicious finding from provider_malicious
    assert any(f.finding_code == "FIND-REP-PROVIDER_MALICIOUS" for f in fn_list)
    assert any(f.severity == Severity.CRITICAL for f in fn_list)


@pytest.mark.asyncio
async def test_threat_intel_evidence_deduplication(clean_cache, sample_url):
    """Verify that findings from multiple threat intel providers consolidate into a single correlation group."""
    p1 = MockThreatIntelProvider(
        canned_status=ReputationStatus.CONFIRMED_MALICIOUS,
        threat_types=["MALWARE"],
        cache=clean_cache,
    )
    p1.name = "intel_p1"

    p2 = MockThreatIntelProvider(
        canned_status=ReputationStatus.CONFIRMED_MALICIOUS,
        threat_types=["PHISHING"],
        cache=clean_cache,
    )
    p2.name = "intel_p2"

    engine = RiskEngine(reputation_providers=[p1, p2], enable_reputation=True)
    report = await engine.analyze_url(sample_url.raw_url)

    assert report.risk_score >= 86  # Critical floor applied
    assert report.recommended_action == ActionVerdict.BLOCK

    # Verify findings were correlated
    threat_intel_findings = [f for f in report.findings if f.correlation_group == "threat_intel_match"]
    assert len(threat_intel_findings) == 1  # Deduplicated to 1 consolidated finding!
    assert len(threat_intel_findings[0].evidence_references) >= 2  # References both provider evidence records


def test_privacy_sanitizer_redacts_sensitive_parameters():
    """Verify that sensitive query parameters and inline userinfo are stripped before transmission."""
    norm = URLNormalizer.normalize("https://alice:secretpass@bank-login.com/auth?token=eyJhbGciOi...&id=42&key=sec99")
    sanitized = PrivacySanitizer.sanitize(norm)

    assert "alice" not in sanitized
    assert "secretpass" not in sanitized
    assert "token=REDACTED" in sanitized
    assert "key=REDACTED" in sanitized
    assert "id=42" in sanitized  # Non-sensitive parameter preserved


@pytest.mark.asyncio
async def test_missing_credentials_fails_gracefully(clean_cache, sample_url):
    """Verify that providers with unconfigured credentials return UNAVAILABLE without errors."""
    gsb = GoogleSafeBrowsingProvider(api_key="", cache=clean_cache)
    vt = VirusTotalProvider(api_key="", cache=clean_cache)

    res_gsb = await gsb.check_url(sample_url)
    res_vt = await vt.check_url(sample_url)

    assert res_gsb.status == ReputationStatus.UNAVAILABLE
    assert res_vt.status == ReputationStatus.UNAVAILABLE
    assert "unconfigured" in res_gsb.error_message.lower()
    assert "unconfigured" in res_vt.error_message.lower()


@pytest.mark.asyncio
async def test_invalid_provider_response_handled_gracefully(clean_cache):
    """Verify that malformed or non-JSON responses from providers return UNAVAILABLE without crashing."""
    gsb = GoogleSafeBrowsingProvider(api_key="valid_key", cache=clean_cache)
    norm = URLNormalizer.normalize("https://test-site.org")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.side_effect = ValueError("Malformed JSON payload from server")

    with patch("httpx.AsyncClient.post", return_value=mock_resp):
        res = await gsb.check_url(norm)

    assert res.status == ReputationStatus.UNAVAILABLE
    assert "malformed" in res.error_message.lower()


def test_cache_invalidation_removes_entry(clean_cache):
    """Verify that cache.invalidate explicitly removes the cached entry."""
    url = "https://evict-test.com"
    res = ReputationResult(
        provider_name="test_p",
        provider_version="1.0",
        status=ReputationStatus.NO_MATCH,
    )
    clean_cache.set("test_p", url, res)
    assert clean_cache.get("test_p", url) is not None

    deleted = clean_cache.invalidate("test_p", url)
    assert deleted is True
    assert clean_cache.get("test_p", url) is None

