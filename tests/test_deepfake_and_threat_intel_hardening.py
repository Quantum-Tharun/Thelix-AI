"""
Verification Tests for Deepfake Detector and External Threat Feeds Hardening.
Verifies model architecture loading, weight checkpoint validation, safe error handling,
threat feed API queries, rate limits, timeouts, secret masking, and fallback behaviors.
"""
import pytest
import os
import io
import base64
import torch
from unittest.mock import patch, MagicMock

from app.schemas.ai_contracts import DeepfakeAnalysisRequest, DeepfakeAnalysisResponse
from app.ai.deepfake.vision import SimpleDeepfakeCNN, DeepfakeVisionService
from app.ai.deepfake.service import DeepfakeDetectorService
from risk_engine.url_normalizer import URLNormalizer
from risk_engine.evidence import Severity, ActionVerdict
from risk_engine.reputation_analyzer import (
    ReputationStatus,
    GoogleSafeBrowsingProvider,
    VirusTotalProvider,
    ReputationAnalyzer,
)
from risk_engine.reputation_cache import ReputationCache
from risk_engine.engine import RiskEngine


# ---------------------------------------------------------------------------
# DEEPFAKE DETECTOR TESTS
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def reset_deepfake_service():
    """Ensures DeepfakeVisionService memory cache is reset between tests."""
    DeepfakeVisionService.reset_model()
    yield
    DeepfakeVisionService.reset_model()


def create_test_image_b64(width=100, height=100, color="red") -> str:
    """Generates a small valid base64 PNG image for testing."""
    from PIL import Image
    buf = io.BytesIO()
    img = Image.new("RGB", (width, height), color=color)
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()


@pytest.mark.asyncio
async def test_deepfake_weights_unloaded_honest_disclosure():
    """Verify that when weights are absent, service truthfully returns PROTOTYPE_UNAVAILABLE."""
    # Ensure environment points to non-existent file
    with patch.dict(os.environ, {"DEEPFAKE_WEIGHTS_PATH": "non_existent_weights_path.pth"}):
        assert DeepfakeDetectorService.get_model_status() == "prototype_weights_unloaded"
        req = DeepfakeAnalysisRequest(media_base64=create_test_image_b64())
        res = await DeepfakeDetectorService.analyze_media(req)

        assert res.status == "PROTOTYPE_UNAVAILABLE"
        assert res.is_deepfake is None
        assert res.confidence_score is None
        assert "SimpleDeepfakeCNN" in res.processing_notes
        assert "DEEPFAKE_WEIGHTS_PATH" in res.processing_notes
        assert "LIMITATION-PRODUCTION-WEIGHTS-UNLOADED" in res.limitations


def test_deepfake_validate_weights_corrupt_file(tmp_path):
    """Verify that a corrupted checkpoint file fails validation gracefully."""
    corrupt_file = tmp_path / "corrupt_weights.pth"
    corrupt_file.write_bytes(b"NOT_A_PYTORCH_CHECKPOINT_RANDOM_GARBAGE")

    is_valid, msg = DeepfakeVisionService.validate_weights(str(corrupt_file))
    assert is_valid is False
    assert "validation failed" in msg.lower() or "checkpoint" in msg.lower()


def test_deepfake_validate_weights_mismatched_layers(tmp_path):
    """Verify that weights with mismatching layer geometries fail validation."""
    wrong_file = tmp_path / "wrong_architecture.pth"
    # Save weights from a totally different network
    dummy_dict = {"unrelated_layer.weight": torch.zeros(10, 10)}
    torch.save(dummy_dict, str(wrong_file))

    is_valid, msg = DeepfakeVisionService.validate_weights(str(wrong_file))
    assert is_valid is False
    assert "validation failed" in msg.lower() or "missing key" in msg.lower()


@pytest.mark.asyncio
async def test_deepfake_invalid_weights_status_and_rejection(tmp_path):
    """Verify that invalid weights file sets status to 'invalid_weights' and rejects analysis."""
    corrupt_file = tmp_path / "corrupt.pth"
    corrupt_file.write_bytes(b"corrupt_data")

    with patch.dict(os.environ, {"DEEPFAKE_WEIGHTS_PATH": str(corrupt_file)}):
        assert DeepfakeDetectorService.get_model_status() == "invalid_weights"

        req = DeepfakeAnalysisRequest(media_base64=create_test_image_b64())
        res = await DeepfakeDetectorService.analyze_media(req)
        assert res.status == "FAILED"
        assert "corrupted" in res.probabilistic_notice.lower()


@pytest.mark.asyncio
async def test_deepfake_valid_weights_successful_inference(tmp_path):
    """Verify that when a valid SimpleDeepfakeCNN state_dict is loaded, inference executes cleanly."""
    valid_file = tmp_path / "valid_model.pth"
    # Create and save a valid state_dict matching SimpleDeepfakeCNN
    model = SimpleDeepfakeCNN()
    torch.save(model.state_dict(), str(valid_file))

    with patch.dict(os.environ, {"DEEPFAKE_WEIGHTS_PATH": str(valid_file)}):
        assert DeepfakeDetectorService.get_model_status() == "ready"

        req = DeepfakeAnalysisRequest(media_base64=create_test_image_b64())
        res = await DeepfakeDetectorService.analyze_media(req)

        assert res.status == "COMPLETED"
        assert isinstance(res.is_deepfake, bool)
        assert res.confidence_score is not None
        assert 0.0 <= res.confidence_score <= 1.0
        assert "Inference successfully executed" in res.processing_notes


# ---------------------------------------------------------------------------
# EXTERNAL THREAT FEEDS TESTS
# ---------------------------------------------------------------------------

@pytest.fixture
def test_cache():
    return ReputationCache()


@pytest.fixture
def target_url():
    return URLNormalizer.normalize("https://security-verify.example.com/login")


@pytest.mark.asyncio
async def test_safebrowsing_missing_key_gracefully_unavailable(test_cache, target_url):
    """Verify Google Safe Browsing without an API key safely marks provider unavailable."""
    gsb = GoogleSafeBrowsingProvider(api_key="", cache=test_cache)
    res = await gsb.check_url(target_url)
    assert res.status == ReputationStatus.UNAVAILABLE
    assert "unconfigured" in res.error_message.lower()


@pytest.mark.asyncio
async def test_virustotal_missing_key_gracefully_unavailable(test_cache, target_url):
    """Verify VirusTotal without an API key safely marks provider unavailable."""
    vt = VirusTotalProvider(api_key="", cache=test_cache)
    res = await vt.check_url(target_url)
    assert res.status == ReputationStatus.UNAVAILABLE
    assert "unconfigured" in res.error_message.lower()


@pytest.mark.asyncio
async def test_safebrowsing_threat_match_detection(test_cache, target_url):
    """Verify that Google Safe Browsing threat match correctly produces CONFIRMED_MALICIOUS."""
    gsb = GoogleSafeBrowsingProvider(api_key="valid_test_key", cache=test_cache)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "matches": [
            {"threatType": "MALWARE", "platformType": "ANY_PLATFORM"}
        ]
    }

    with patch("httpx.AsyncClient.post", return_value=mock_resp):
        res = await gsb.check_url(target_url)

    assert res.status == ReputationStatus.CONFIRMED_MALICIOUS
    assert res.is_malicious is True
    assert "MALWARE" in res.threat_types


@pytest.mark.asyncio
async def test_safebrowsing_rate_limit_backoff(test_cache, target_url):
    """Verify that Google Safe Browsing HTTP 429 triggers RATE_LIMITED and cache backoff."""
    gsb = GoogleSafeBrowsingProvider(api_key="valid_test_key", cache=test_cache)

    mock_resp = MagicMock()
    mock_resp.status_code = 429

    with patch("httpx.AsyncClient.post", return_value=mock_resp):
        res = await gsb.check_url(target_url)

    assert res.status == ReputationStatus.RATE_LIMITED
    assert test_cache.is_rate_limited("google_safe_browsing") is True


@pytest.mark.asyncio
async def test_safebrowsing_secret_redaction_in_errors(test_cache, target_url):
    """Verify that the Google Safe Browsing API key is NEVER leaked in error messages or logs."""
    secret_key = "AIzaSySecretSafeBrowsingKey12345"
    gsb = GoogleSafeBrowsingProvider(api_key=secret_key, cache=test_cache)

    # Simulate an error string containing the API key in the URL
    simulated_err = f"Failed to connect to https://safebrowsing.googleapis.com/v4/threatMatches:find?key={secret_key}"
    with patch("httpx.AsyncClient.post", side_effect=RuntimeError(simulated_err)):
        res = await gsb.check_url(target_url)

    assert res.status == ReputationStatus.UNAVAILABLE
    assert secret_key not in res.error_message
    assert "[REDACTED]" in res.error_message


@pytest.mark.asyncio
async def test_virustotal_secret_redaction_in_errors(test_cache, target_url):
    """Verify that the VirusTotal API key is NEVER leaked in error messages or logs."""
    secret_key = "vt_super_secret_api_key_987654321"
    vt = VirusTotalProvider(api_key=secret_key, cache=test_cache)

    simulated_err = f"HTTP Error with header x-apikey: {secret_key}"
    with patch("httpx.AsyncClient.get", side_effect=RuntimeError(simulated_err)):
        res = await vt.check_url(target_url)

    assert res.status == ReputationStatus.UNAVAILABLE
    assert secret_key not in res.error_message
    assert "[REDACTED]" in res.error_message


@pytest.mark.asyncio
async def test_virustotal_malicious_detection(test_cache, target_url):
    """Verify that VirusTotal >= 3 engines produces CONFIRMED_MALICIOUS."""
    vt = VirusTotalProvider(api_key="test_key", cache=test_cache)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 8,
                    "suspicious": 2,
                    "harmless": 60,
                    "undetected": 10,
                }
            }
        }
    }

    with patch("httpx.AsyncClient.get", return_value=mock_resp):
        res = await vt.check_url(target_url)

    assert res.status == ReputationStatus.CONFIRMED_MALICIOUS
    assert res.positives_count == 10
    assert res.total_engines == 80


# ---------------------------------------------------------------------------
# RISK ENGINE EXTERNAL FEEDS BEHAVIOR
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_risk_engine_unconfigured_external_feeds_not_reported_as_verified():
    """
    CRITICAL: When credentials are unconfigured, RiskEngine must NOT claim
    'reputation_analysis' is completed, and must clearly report it as skipped in limitations.
    """
    engine = RiskEngine(reputation_providers=[], enable_reputation=True)
    report = await engine.analyze_url("https://example.com/test-url")

    # reputation_analysis must NOT be in completed checks
    assert "reputation_analysis" not in report.checks_completed

    # external_threat_intelligence must be explicitly in skipped checks
    assert "external_threat_intelligence" in report.checks_skipped

    # Limitations or what_we_could_not_check must mention unconfigured external threat feeds
    skipped_items = [c for c in report.what_we_could_not_check if c.get("check") == "external_threat_intelligence"]
    assert len(skipped_items) >= 1
    assert "unconfigured" in skipped_items[0]["reason"].lower()


@pytest.mark.asyncio
async def test_risk_engine_with_active_feed_flags_threat(test_cache):
    """
    When credentials are configured and a provider flags a target,
    reputation_analysis is in completed checks and the threat is blocked.
    """
    from risk_engine.reputation_analyzer import MockThreatIntelProvider
    provider = MockThreatIntelProvider(
        canned_status=ReputationStatus.CONFIRMED_MALICIOUS,
        positives_count=12,
        threat_types=["MALWARE"],
        cache=test_cache,
    )

    engine = RiskEngine(reputation_providers=[provider], enable_reputation=True)
    report = await engine.analyze_url("https://confirmed-bad-site.org")

    assert "reputation_analysis" in report.checks_completed
    assert report.recommended_action == ActionVerdict.BLOCK
    assert any("FIND-REP-" in f.finding_code for f in report.findings)
