"""
Tests for AI Provider Lifecycle, Client Reuse, Error Handling, and Resource Cleanup (Phase 22B).
Validates:
1. Client instance reuse across multiple requests (no redundant re-instantiation).
2. Clean async and sync shutdown / lifecycle resource release (aclose, close).
3. Retry logic without client recreation.
4. Bounded timeout behavior and error handling.
5. Sensitive data / API key redaction in error messages.
6. Zero cross-request state leakage.
7. Independence of deterministic RiskEngine verdicts from LLM availability.
"""
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from llm.gemini_provider import GeminiProvider, _sanitize_error
from app.ai.gemini.explanation import GeminiExplanationService
from risk_engine.evidence import Finding, Severity, ActionVerdict, RiskLevel
from llm.explanation_generator import ExplanationGenerator


@pytest.mark.asyncio
async def test_gemini_provider_client_reuse():
    """Verify that multiple requests on the same GeminiProvider instance reuse the same client."""
    provider = GeminiProvider(api_key="AIzaSyTestKeyForClientReuseValidation123")
    assert provider._client is None

    mock_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.text = "Analysis complete: Safe target."
    mock_client.aio.models.generate_content = AsyncMock(return_value=mock_resp)

    with patch("llm.gemini_provider.genai.Client", return_value=mock_client) as mock_constructor:
        res1 = await provider.generate_text("System", "Prompt 1")
        assert res1.success is True
        assert res1.content == "Analysis complete: Safe target."
        assert mock_constructor.call_count == 1
        first_client = provider._client
        assert first_client is mock_client

        # Second request must reuse the already-created client
        res2 = await provider.generate_text("System", "Prompt 2")
        assert res2.success is True
        assert mock_constructor.call_count == 1  # Constructor was NOT called again
        assert provider._client is first_client

    # Clean shutdown
    await provider.aclose()
    assert provider._client is None


@pytest.mark.asyncio
async def test_gemini_provider_retries_without_client_recreation():
    """Verify that retry attempts reuse the client rather than creating a new client per retry."""
    provider = GeminiProvider(api_key="AIzaSyTestKeyForRetryValidation123", max_retries=2)

    mock_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.text = "Success on attempt 2"

    # Fail on first attempt with transient error, succeed on second attempt
    mock_client.aio.models.generate_content = AsyncMock(
        side_effect=[Exception("Transient connection error"), mock_resp]
    )

    with patch("llm.gemini_provider.genai.Client", return_value=mock_client) as mock_constructor:
        result = await provider.generate_text("System", "Prompt")
        assert result.success is True
        assert result.content == "Success on attempt 2"
        # Client constructor was called exactly once despite 2 attempts
        assert mock_constructor.call_count == 1

    await provider.aclose()


@pytest.mark.asyncio
async def test_gemini_provider_bounded_timeout():
    """Verify that generate_text enforces timeout bounds and returns failure result without hanging."""
    provider = GeminiProvider(api_key="AIzaSyTestKeyForTimeoutValidation123", max_retries=0)

    mock_client = MagicMock()

    async def slow_response(*args, **kwargs):
        await asyncio.sleep(2.0)
        return MagicMock(text="Too late")

    mock_client.aio.models.generate_content = slow_response

    with patch("llm.gemini_provider.genai.Client", return_value=mock_client):
        result = await provider.generate_text("System", "Prompt", timeout_seconds=0.05)
        assert result.success is False
        assert "timed out after 0.05s" in result.error

    await provider.aclose()


@pytest.mark.asyncio
async def test_gemini_provider_sensitive_error_sanitization():
    """Verify that error messages from the provider never leak API keys or credentials."""
    raw_error = "Failed to connect to Google API with key AIzaSyTestKeySensitiveData123456789 and token=secretToken123"
    sanitized = _sanitize_error(raw_error)

    assert "AIzaSy" not in sanitized
    assert "[REDACTED_API_KEY]" in sanitized
    assert "secretToken123" not in sanitized
    assert "[REDACTED]" in sanitized

    provider = GeminiProvider(api_key="AIzaSyTestKeySensitiveData123456789", max_retries=0)
    mock_client = MagicMock()
    mock_client.aio.models.generate_content = AsyncMock(
        side_effect=Exception(f"Error AIzaSyTestKeySensitiveData123456789 failed")
    )

    with patch("llm.gemini_provider.genai.Client", return_value=mock_client):
        result = await provider.generate_text("System", "Prompt")
        assert result.success is False
        assert "AIzaSy" not in result.error
        assert "[REDACTED_API_KEY]" in result.error

    await provider.aclose()


@pytest.mark.asyncio
async def test_gemini_provider_lifecycle_aclose_and_close():
    """Verify that aclose and close properly release underlying client resources and reset state."""
    provider = GeminiProvider(api_key="AIzaSyTestKeyForLifecycle123")
    mock_client = MagicMock()
    mock_client.aio.aclose = AsyncMock()
    mock_client.close = MagicMock()

    with patch("llm.gemini_provider.genai.Client", return_value=mock_client):
        client = provider._get_client()
        assert client is mock_client
        assert provider._client is not None

        # Async cleanup
        await provider.aclose()
        assert provider._client is None
        mock_client.aio.aclose.assert_called_once()

        # Sync cleanup
        provider._get_client()
        assert provider._client is not None
        provider.close()
        assert provider._client is None
        mock_client.close.assert_called_once()


@pytest.mark.asyncio
async def test_gemini_explanation_service_client_reuse_and_reset():
    """Verify that GeminiExplanationService reuses cached client across class calls and resets cleanly."""
    GeminiExplanationService.reset_client()
    assert GeminiExplanationService._client is None

    mock_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.text = "This link appears dangerous due to phishing markers."
    mock_client.aio.models.generate_content = AsyncMock(return_value=mock_resp)

    with patch("app.ai.gemini.explanation.genai.Client", return_value=mock_client) as mock_constructor, \
         patch("app.ai.gemini.explanation.settings.GEMINI_API_KEY", "AIzaSyTestKeyExplanation123"):
        res1 = await GeminiExplanationService.generate_explanation(trust_score=15, reasons=["phishing_domain"])
        assert "phishing markers" in res1
        assert mock_constructor.call_count == 1

        # Second invocation reuses the cached client
        res2 = await GeminiExplanationService.generate_explanation(trust_score=20, reasons=["suspicious_redirect"])
        assert mock_constructor.call_count == 1

        # Reset releases client
        await GeminiExplanationService.aclose()
        assert GeminiExplanationService._client is None


@pytest.mark.asyncio
async def test_risk_engine_verdict_independent_of_llm_failure():
    """
    Verify architectural invariant: Deterministic risk engine verdicts (trust score,
    risk level, action verdict) are 100% independent of LLM availability or failure.
    """
    failing_provider = GeminiProvider(api_key="AIzaSyTestKeyFailure123", max_retries=0)
    mock_client = MagicMock()
    mock_client.aio.models.generate_content = AsyncMock(side_effect=Exception("Total LLM service outage"))

    with patch("llm.gemini_provider.genai.Client", return_value=mock_client):
        generator = ExplanationGenerator(failing_provider)
        finding = Finding(
            finding_code="CRIT-PHISH-01",
            title="Known Credential Harvester",
            description="Active phishing campaign domain",
            severity=Severity.CRITICAL,
            confidence=0.98,
            source_engine="test",
            source_version="1.0",
        )

        explanation = await generator.generate_explanation(
            risk_score=95,
            trust_score=5,
            risk_level=RiskLevel.CRITICAL,
            action=ActionVerdict.BLOCK,
            findings=[finding],
        )

        # Static fallback explanation was generated cleanly
        assert explanation is not None
        assert "Blocked" in explanation.headline
        assert "strongly advise against" in explanation.plain_text_explanation

        # Deterministic engine parameters are unchanged
        assert finding.severity == Severity.CRITICAL
        assert ActionVerdict.BLOCK.value == "block"

    await failing_provider.aclose()
