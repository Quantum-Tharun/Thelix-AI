"""
Tests for Phase 2 AI Expansion:
- FallbackLLMRouter (Gemini -> Ollama -> Mock fallback)
- OllamaGemmaProvider availability & mock execution
- DeepfakeDetectorService bounds and prototype state handling
- QR code end-to-end decoding and safety checks
"""
import pytest
import base64
import io
from unittest.mock import patch, MagicMock

from llm.provider import MockLLMProvider
from llm.ollama_provider import OllamaGemmaProvider
from llm.fallback_router import FallbackLLMRouter
from app.schemas.ai_contracts import DeepfakeAnalysisRequest, DeepfakeAnalysisResponse
from app.ai.deepfake.service import DeepfakeDetectorService
from ai_engineering.qr.qr_analyzer import QRAnalyzer


@pytest.mark.asyncio
async def test_ollama_provider_unreachable():
    """Verify Ollama provider gracefully returns error result without crashing when unreachable."""
    provider = OllamaGemmaProvider(base_url="http://127.0.0.1:54321", model_name="gemma-2b-v3")
    res = await provider.generate_text("System", "User prompt", timeout_seconds=1.0)
    assert res.success is False
    assert "unreachable" in res.error.lower() or "connection" in res.error.lower()


@pytest.mark.asyncio
async def test_fallback_router_failover_to_mock():
    """Verify router falls back sequentially to mock provider when primary and secondary fail."""
    failing_primary = OllamaGemmaProvider(base_url="http://127.0.0.1:54321", model_name="primary")
    failing_secondary = OllamaGemmaProvider(base_url="http://127.0.0.1:54322", model_name="secondary")
    mock = MockLLMProvider(canned_response='{"headline": "Safe link verified"}')

    router = FallbackLLMRouter(
        primary_provider=failing_primary,
        secondary_provider=failing_secondary,
        mock_fallback=mock,
    )

    res = await router.generate_text("System prompt", "User prompt", timeout_seconds=0.5)
    assert res.success is True
    assert "Safe link verified" in res.content
    assert router.last_provider_used == "mock_provider"


@pytest.mark.asyncio
async def test_deepfake_detector_prototype_disclosure():
    """Verify deepfake detector honestly returns PROTOTYPE_UNAVAILABLE when weights are not present."""
    # 1x1 transparent PNG
    png_b64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
    req = DeepfakeAnalysisRequest(media_base64=png_b64, media_type="image")

    res = await DeepfakeDetectorService.analyze_media(req)
    assert res.status == "PROTOTYPE_UNAVAILABLE"
    assert res.is_deepfake is None
    assert res.confidence_score is None
    assert "weights" in res.probabilistic_notice.lower()


@pytest.mark.asyncio
async def test_deepfake_detector_rejects_oversized():
    """Verify deepfake detector strictly rejects oversized payloads."""
    large_b64 = "A" * (12 * 1024 * 1024)  # ~9MB decoded, let's construct explicit large bytes
    oversized_bytes = b"\x89PNG\r\n\x1a\n" + b"\x00" * (11 * 1024 * 1024)
    oversized_b64 = base64.b64encode(oversized_bytes).decode("utf-8")

    req = DeepfakeAnalysisRequest(media_base64=oversized_b64, media_type="image")
    res = await DeepfakeDetectorService.analyze_media(req)
    assert res.status == "FAILED"
    assert "LIMITATION-SIZE-EXCEEDED" in res.limitations


def test_qr_analyzer_real_decoding():
    """Verify QRAnalyzer correctly decodes an authentic generated QR code."""
    import qrcode
    qr = qrcode.QRCode()
    qr.add_data("https://verified-safe.thelix.local/login")
    qr.make()
    img = qr.make_image()
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    png_bytes = buf.getvalue()

    analyzer = QRAnalyzer()
    extract_res, evidence, findings = analyzer.analyze_image(png_bytes)
    assert extract_res.success is True
    assert "https://verified-safe.thelix.local/login" in extract_res.extracted_urls
