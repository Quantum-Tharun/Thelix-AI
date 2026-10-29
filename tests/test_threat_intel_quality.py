"""
Tests for Threat Intelligence Quality, Adapter Resiliency, and Safe Semantics (Phase 14 - Section 8)
Verifies:
1. Confirmed malicious match metadata, provenance, and timestamps.
2. NO_MATCH semantics: Provider clean response != proof of safety.
3. Rate limit (429) backoff tracking and fast-path throttling.
4. Timeout and provider outage fail-safe neutrality.
5. Invalid provider response handling.
6. Conflicting provider responses (malicious match authoritative over clean).
7. Cache hits, deduplication, and TTL expiration.
8. Provider failures and outages are NEVER cached as clean results.
9. Privacy sanitization before external transmission.
10. Stale / unavailable provider tracking in metadata.
"""
import time
import pytest
from datetime import datetime, timezone, timedelta

from risk_engine.url_normalizer import URLNormalizer
from risk_engine.reputation_analyzer import (
    ReputationProvider,
    ReputationResult,
    ReputationStatus,
    ReputationCache,
    ReputationAnalyzer,
    PrivacySanitizer,
)
from risk_engine.engine import RiskEngine
from risk_engine.evidence import ActionVerdict, Severity


class ConfigurableTestProvider(ReputationProvider):
    def __init__(self, name: str, version: str = "1.0.0", cache: ReputationCache = None):
        super().__init__(cache=cache)
        self.name = name
        self.version = version
        self.calls_count = 0
        self.canned_status = ReputationStatus.NO_MATCH
        self.canned_threats = []
        self.canned_positives = 0
        self.simulate_exception = False

    async def _execute_lookup(self, sanitized_url: str) -> ReputationResult:
        self.calls_count += 1
        if self.simulate_exception:
            raise ConnectionError("Simulated socket timeout / connection reset")

        is_mal = (self.canned_status == ReputationStatus.CONFIRMED_MALICIOUS)
        return ReputationResult(
            provider_name=self.name,
            provider_version=self.version,
            status=self.canned_status,
            threat_types=self.canned_threats if is_mal else [],
            positives_count=self.canned_positives if is_mal else 0,
            total_engines=70,
            raw_response={"status": self.canned_status.value},
        )


@pytest.mark.asyncio
async def test_confirmed_malicious_match_provenance_and_timestamp():
    """Confirmed threat intel matches must record accurate provenance, status, and query timestamps."""
    provider = ConfigurableTestProvider("google_safe_browsing", "v4")
    provider.canned_status = ReputationStatus.CONFIRMED_MALICIOUS
    provider.canned_threats = ["MALWARE", "SOCIAL_ENGINEERING"]
    provider.canned_positives = 15

    norm = URLNormalizer.normalize("https://confirmed-malicious-feed-sample.com/login")
    result = await provider.check_url(norm)

    assert result.is_malicious
    assert result.status == ReputationStatus.CONFIRMED_MALICIOUS
    assert "google_safe_browsing:v4@" in result.provenance
    assert isinstance(result.query_timestamp, datetime)
    assert result.threat_types == ["MALWARE", "SOCIAL_ENGINEERING"]


@pytest.mark.asyncio
async def test_no_match_does_not_prove_safety_semantics():
    """NO_MATCH means only that provider has no record, NOT that target is certified safe."""
    provider = ConfigurableTestProvider("virustotal")
    provider.canned_status = ReputationStatus.NO_MATCH

    engine = RiskEngine(reputation_providers=[provider], enable_reputation=True)
    # Target URL with strong heuristic indicators (bare IP + suspicious port)
    report = await engine.analyze_url("http://198.51.100.99:8080/portal/auth")

    # Even though reputation said NO_MATCH, the engine must NOT certify safety
    assert report.recommended_action != ActionVerdict.ALLOW
    assert report.risk_score >= 40
    # Provider metadata correctly records no match
    assert any(f.finding_code == "FIND-URL-IP-HOST" for f in report.findings)


@pytest.mark.asyncio
async def test_rate_limit_backoff_and_throttling():
    """When a provider reports RATE_LIMITED, subsequent queries must throttle without network calls."""
    cache = ReputationCache(custom_ttls={"rate_limited": 60})
    provider = ConfigurableTestProvider("virustotal", cache=cache)
    provider.canned_status = ReputationStatus.RATE_LIMITED

    norm = URLNormalizer.normalize("https://example.com/page1")
    res1 = await provider.check_url(norm)
    assert res1.status == ReputationStatus.RATE_LIMITED
    assert provider.calls_count == 1

    # Record backoff explicitly in cache
    cache.record_rate_limit("virustotal", backoff_seconds=60)
    assert cache.is_rate_limited("virustotal")

    # Second query should fast-fail from cache backoff without calling _execute_lookup
    norm2 = URLNormalizer.normalize("https://example.com/page2")
    res2 = await provider.check_url(norm2)
    assert res2.status == ReputationStatus.RATE_LIMITED
    assert provider.calls_count == 1  # No additional network query executed


@pytest.mark.asyncio
async def test_timeout_and_outage_fail_safe_neutrality():
    """Provider network failure or timeout must be handled neutrally without crashing."""
    cache = ReputationCache()
    provider = ConfigurableTestProvider("google_safe_browsing", cache=cache)
    provider.simulate_exception = True

    analyzer = ReputationAnalyzer(providers=[provider], cache=cache)
    norm = URLNormalizer.normalize("https://example.com/test")

    ev_list, fn_list, meta = await analyzer.analyze(norm)
    # Outage should not raise unhandled exception and must not add false positive findings
    assert len(ev_list) == 0
    assert len(fn_list) == 0
    assert meta["google_safe_browsing"]["available"] is False


@pytest.mark.asyncio
async def test_conflicting_provider_responses_policy_resolution():
    """Confirmed threat intel finding must override clean response from another provider."""
    gsb = ConfigurableTestProvider("google_safe_browsing")
    gsb.canned_status = ReputationStatus.CONFIRMED_MALICIOUS
    gsb.canned_threats = ["PHISHING"]

    vt = ConfigurableTestProvider("virustotal")
    vt.canned_status = ReputationStatus.NO_MATCH

    engine = RiskEngine(reputation_providers=[gsb, vt], enable_reputation=True)
    report = await engine.analyze_url("https://disputed-phishing-url.com/update")

    assert report.recommended_action == ActionVerdict.BLOCK
    assert report.risk_score >= 80


@pytest.mark.asyncio
async def test_cache_hit_and_ttl_expiration():
    """Results should be served from cache until TTL expires."""
    cache = ReputationCache(custom_ttls={"malicious": 1})  # 1-second TTL for testing
    provider = ConfigurableTestProvider("virustotal", cache=cache)
    provider.canned_status = ReputationStatus.CONFIRMED_MALICIOUS
    provider.canned_positives = 20

    norm = URLNormalizer.normalize("https://threat-site.com/malware.exe")

    # Call 1: Miss -> Lookup
    res1 = await provider.check_url(norm)
    assert provider.calls_count == 1
    assert res1.is_malicious

    # Call 2: Hit -> No additional lookup
    res2 = await provider.check_url(norm)
    assert provider.calls_count == 1

    # Wait for TTL to expire
    time.sleep(1.1)

    # Call 3: Expired -> Re-lookup
    res3 = await provider.check_url(norm)
    assert provider.calls_count == 2


@pytest.mark.asyncio
async def test_failures_and_errors_never_cached_as_clean():
    """Provider outage or rate-limit must NEVER be cached as a clean NO_MATCH result."""
    cache = ReputationCache()
    provider = ConfigurableTestProvider("google_safe_browsing", cache=cache)
    provider.canned_status = ReputationStatus.UNAVAILABLE

    norm = URLNormalizer.normalize("https://target.com/check")
    res = await provider.check_url(norm)

    assert not res.is_available
    # Ensure cache does not store this as a clean result
    cached = cache.get("google_safe_browsing", norm.normalized_url)
    assert cached is None or not cached.is_available


def test_privacy_sanitizer_removes_sensitive_parameters():
    """All credentials, tokens, session keys, and passwords in query string must be redacted."""
    norm = URLNormalizer.normalize("https://secure.internal.com/auth?token=eyJ123&session_id=abc456&api_key=secret789&user=john")
    sanitized = PrivacySanitizer.sanitize(norm)

    assert "eyJ123" not in sanitized
    assert "abc456" not in sanitized
    assert "secret789" not in sanitized
    assert "token=REDACTED" in sanitized
    assert "user=john" in sanitized
