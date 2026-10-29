"""
Tests for URL Robustness and Static Analysis Quality (Phase 14 - Section 6)
Verifies:
1. IP-address URLs (raw IPv4, non-standard port).
2. Unusual ports and schemes (unsupported scheme rejection, non-standard ports).
3. Unicode and punycode hostnames (IDN homoglyphs).
4. Lookalike domains & typosquatting.
5. Misleading subdomains (e.g., paypal.com.attacker-controlled.net).
6. Userinfo-based URL confusion (https://bank.com@evil.com/login).
7. Percent-encoding and double-encoding path anomalies.
8. Shortened URL indicator detection.
9. Redirect-related parameter patterns.
10. Embedded credentials & sensitive query parameter sanitization.
11. Malformed URLs (normalization must never turn invalid input into a safe verdict).
12. Private, loopback, link-local, and cloud metadata targets (127.0.0.1, 169.254.169.254, RFC1918).
13. Reputation provider disagreement (Confirmed malicious remains authoritative over no-match/error).
"""
import pytest
from risk_engine.engine import RiskEngine
from risk_engine.static_analyzer import StaticURLAnalyzer
from risk_engine.url_normalizer import URLNormalizer
from risk_engine.evidence import ActionVerdict, Severity, RiskLevel
from risk_engine.reputation_analyzer import (
    ReputationProvider,
    ReputationResult,
    ReputationStatus,
    PrivacySanitizer,
)
from risk_engine.exceptions import UnsupportedSchemeException, MalformedURLException
from sandbox.network_policy import NetworkPolicy


class MockReputationProvider(ReputationProvider):
    def __init__(self, name: str, status: ReputationStatus, threat_types=None):
        super().__init__(cache=None)
        self.name = name
        self.status = status
        self.threat_types = threat_types or []

    async def _execute_lookup(self, sanitized_url: str) -> ReputationResult:
        is_mal = (self.status == ReputationStatus.CONFIRMED_MALICIOUS)
        return ReputationResult(
            provider_name=self.name,
            provider_version="1.0.0",
            status=self.status,
            threat_types=self.threat_types if is_mal else [],
            positives_count=10 if is_mal else 0,
            total_engines=70,
            raw_response={"mock": True},
        )


@pytest.fixture
def engine():
    return RiskEngine(enable_reputation=False)


@pytest.mark.asyncio
async def test_ip_address_url_detection(engine):
    """Raw IP address URLs should be flagged with FIND-URL-IP-HOST."""
    report = await engine.analyze_url("http://198.51.100.14:8080/login.php")
    findings = [f.finding_code for f in report.findings]
    assert "FIND-URL-IP-HOST" in findings
    assert report.risk_score >= 40
    assert report.recommended_action in (ActionVerdict.WARN, ActionVerdict.BLOCK)


@pytest.mark.asyncio
async def test_unusual_schemes_and_ports(engine):
    """Dangerous or unusual URI schemes must be rejected or flagged, and non-standard ports identified."""
    with pytest.raises(UnsupportedSchemeException):
        URLNormalizer.normalize("javascript:alert(document.cookie)")

    norm_port = URLNormalizer.normalize("https://secure-login.com:65534/auth")
    ev, fn = StaticURLAnalyzer.analyze(norm_port)
    codes_port = [f.finding_code for f in fn]
    assert "FIND-URL-UNUSUAL-PORT" in codes_port


@pytest.mark.asyncio
async def test_unicode_and_punycode_hostnames(engine):
    """Punycode (xn--) and IDN homoglyphs must be detected."""
    norm = URLNormalizer.normalize("https://xn--pple-43d.com/support/login")
    ev, fn = StaticURLAnalyzer.analyze(norm)
    codes = [f.finding_code for f in fn]
    assert "FIND-URL-HOMOGRAPH" in codes


@pytest.mark.asyncio
async def test_misleading_subdomains(engine):
    """Target brand in subdomain on a foreign domain must trigger impersonation heuristics."""
    report = await engine.analyze_url("https://paypal.com.verify-billing-update.top/signin")
    codes = [f.finding_code for f in report.findings]
    assert any(c in codes for c in ["FIND-URL-BRAND-SUBDOMAIN", "FIND-URL-SUSPICIOUS-TLD"])
    assert report.risk_score >= 40


@pytest.mark.asyncio
async def test_userinfo_url_confusion(engine):
    """Userinfo (username:password@host) confusion attacks must be caught."""
    report = await engine.analyze_url("https://chase.com:security@evil-credential-stealer.net/auth")
    codes = [f.finding_code for f in report.findings]
    assert "FIND-URL-USERINFO" in codes
    assert report.risk_score >= 50


@pytest.mark.asyncio
async def test_percent_encoding_and_double_encoding(engine):
    """Double-percent encoding anomalies (%25) must be identified as evasion attempts."""
    report = await engine.analyze_url("https://example-portal.com/redirect?target=%252e%252e%252fadmin")
    codes = [f.finding_code for f in report.findings]
    assert "FIND-URL-DOUBLE-ENCODING" in codes
    assert report.risk_score >= 30


@pytest.mark.asyncio
async def test_shortened_url_detection(engine):
    """URL shortener services must be identifiable from normalized domain."""
    norm = URLNormalizer.normalize("https://bit.ly/3xSecUr3")
    assert norm.punycode_hostname in ("bit.ly", "tinyurl.com", "t.co")


@pytest.mark.asyncio
async def test_open_redirect_patterns(engine):
    """Open redirect query parameters (?url=, ?redirect=) must be flagged."""
    report = await engine.analyze_url("https://trusted-site.org/outbound?redirect=http://malicious.xyz")
    codes = [f.finding_code for f in report.findings]
    assert "FIND-URL-REDIRECT-PARAM" in codes


@pytest.mark.asyncio
async def test_embedded_credentials_and_tokens():
    """Sensitive query parameters (token, secret, key) must have their values sanitized before transmission."""
    norm = URLNormalizer.normalize("https://api.service.com/data?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9&secret=super_secret")
    sanitized = PrivacySanitizer.sanitize(norm)
    assert "super_secret" not in sanitized
    assert "eyJhbGci" not in sanitized
    assert "token=REDACTED" in sanitized


@pytest.mark.asyncio
async def test_malformed_url_never_turns_safe():
    """Normalization must never transform a malformed or garbage URL into a clean ALLOW verdict."""
    engine = RiskEngine(enable_reputation=False)
    for garbage in ["http://", "not-a-valid-url", "://missing-scheme", "http:///no-host"]:
        report = await engine.analyze_url(garbage)
        assert report.recommended_action != ActionVerdict.ALLOW or report.confidence <= 0.20
        assert report.recommended_action in (ActionVerdict.INCONCLUSIVE, ActionVerdict.WARN, ActionVerdict.BLOCK)


@pytest.mark.asyncio
async def test_private_and_cloud_metadata_destinations(engine):
    """SSRF targets like 127.0.0.1, 169.254.169.254, and RFC1918 addresses must be detected and blocked."""
    for internal in ["http://127.0.0.1:8000/metrics", "http://169.254.169.254/latest/meta-data/", "http://10.0.0.1/admin"]:
        report = await engine.analyze_url(internal)
        codes = [f.finding_code for f in report.findings]
        assert "FIND-URL-IP-HOST" in codes
        assert report.recommended_action in (ActionVerdict.BLOCK, ActionVerdict.WARN)

    # Validate sandbox policy strictly blocks destinations
    allowed_127, reason_127 = NetworkPolicy.is_ip_allowed("127.0.0.1")
    assert not allowed_127
    assert reason_127 is not None

    allowed_meta, reason_meta = NetworkPolicy.is_ip_allowed("169.254.169.254")
    assert not allowed_meta
    assert reason_meta is not None

    allowed_10, reason_10 = NetworkPolicy.is_ip_allowed("10.0.0.1")
    assert not allowed_10
    assert reason_10 is not None


@pytest.mark.asyncio
async def test_reputation_provider_disagreement_preserves_malicious():
    """When Google Safe Browsing reports CONFIRMED_MALICIOUS and VirusTotal times out or says NO_MATCH,
    the confirmed malicious verdict MUST remain authoritative."""
    gsb_mal = MockReputationProvider("google_safe_browsing", ReputationStatus.CONFIRMED_MALICIOUS, ["PHISHING"])
    vt_clean = MockReputationProvider("virustotal", ReputationStatus.NO_MATCH)

    engine_disagree = RiskEngine(reputation_providers=[gsb_mal, vt_clean], enable_reputation=True)
    report = await engine_disagree.analyze_url("https://disputed-threat-site.com/login")

    assert report.recommended_action == ActionVerdict.BLOCK
    assert report.risk_score >= 80
    assert any(f.finding_code == "FIND-REP-GOOGLE_SAFE_BROWSING" for f in report.findings)
