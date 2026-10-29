"""
Tests for Unified Multimodal Pipeline & Shared Risk Engine Integration (Phase 12)
Verifies multi-detector fusion, severity floors, non-cancellation of threats,
bounded correlation grouping, fail-safe inconclusive handling, and bit-for-bit determinism.
"""
import io
import pytest
import qrcode
from PIL import Image

from ai_engineering.multimodal.contracts import InputType, MultimodalStatus
from ai_engineering.multimodal.multimodal_orchestrator import MultimodalOrchestrator
from risk_engine.evidence import ActionVerdict, RiskLevel, Severity
from risk_engine.reputation_analyzer import MockThreatIntelProvider, ReputationStatus


def generate_qr_bytes(target: str) -> bytes:
    img = qrcode.make(target)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


@pytest.mark.asyncio
async def test_multimodal_qr_with_malicious_url_enforces_block():
    """Verify that a confirmed malicious URL decoded from a QR code preserves Severity.CRITICAL and BLOCK verdict."""
    malicious_url = "http://paypal-verification-alert.xyz/signin"
    qr_bytes = generate_qr_bytes(malicious_url)

    mock_vt = MockThreatIntelProvider(
        canned_status=ReputationStatus.CONFIRMED_MALICIOUS,
        positives_count=12,
        threat_types=["PHISHING"],
    )
    orchestrator = MultimodalOrchestrator(reputation_providers=[mock_vt], enable_reputation=True)

    report = await orchestrator.analyze(
        input_type=InputType.QR_CODE,
        content_bytes=qr_bytes,
        filename="phish_qr.png",
    )

    assert report.status in (MultimodalStatus.COMPLETED, MultimodalStatus.PARTIAL)
    assert report.recommended_action == ActionVerdict.BLOCK
    assert report.risk_score >= 86
    assert report.risk_level == RiskLevel.CRITICAL
    assert malicious_url in report.extracted_urls


@pytest.mark.asyncio
async def test_multimodal_scam_message_triggers_high_risk_and_warn():
    """Verify that a suspicious message with credential lures and urgency produces high risk and WARN/BLOCK."""
    scam_msg = (
        "URGENT: Your Bank of America debit card has been suspended due to unauthorized activity. "
        "Please enter your password and submit your one-time password OTP code to restore access immediately."
    )

    orchestrator = MultimodalOrchestrator(enable_reputation=False)
    report = await orchestrator.analyze(
        input_type=InputType.MESSAGE_TEXT,
        text_content=scam_msg,
    )

    assert report.recommended_action in (ActionVerdict.WARN, ActionVerdict.BLOCK)
    assert report.risk_score >= 60  # HIGH severity floor
    assert any(f.finding_code == "FIND-SCAM-CREDENTIAL-LURE" for f in report.findings)


@pytest.mark.asyncio
async def test_multimodal_clean_text_produces_allow():
    """Verify that benign, clean text with no threat indicators produces ActionVerdict.ALLOW."""
    clean_msg = "Hello team, please find the meeting agenda for tomorrow morning at 10 AM attached. Thanks!"

    orchestrator = MultimodalOrchestrator(enable_reputation=False)
    report = await orchestrator.analyze(
        input_type=InputType.MESSAGE_TEXT,
        text_content=clean_msg,
    )

    assert report.recommended_action == ActionVerdict.ALLOW
    assert report.risk_score == 0
    assert report.trust_score == 100
    assert len(report.findings) == 0


@pytest.mark.asyncio
async def test_multimodal_failed_extraction_never_becomes_proof_of_safety():
    """Verify that empty, malformed, or rejected inputs never receive an ALLOW verdict."""
    orchestrator = MultimodalOrchestrator(enable_reputation=False)

    # Empty screenshot
    report = await orchestrator.analyze(
        input_type=InputType.SCREENSHOT,
        content_bytes=b"",
    )

    assert report.recommended_action != ActionVerdict.ALLOW
    assert report.status == MultimodalStatus.REJECTED
    assert report.risk_score == 100


@pytest.mark.asyncio
async def test_multimodal_correlated_indicators_bounded():
    """Verify that multiple scam indicators are aggregated without runaway score compounding."""
    scam_msg = (
        "Please confirm your password. Also enter your one-time password OTP code. "
        "And verify your security PIN immediately."
    )

    orchestrator = MultimodalOrchestrator(enable_reputation=False)
    report = await orchestrator.analyze(
        input_type=InputType.MESSAGE_TEXT,
        text_content=scam_msg,
    )

    # All 3 credential lure phrases share correlation_group="scam_credential_theft"
    cred_findings = [f for f in report.findings if f.correlation_group == "scam_credential_theft"]
    assert len(cred_findings) == 1
    # Bounded to HIGH severity floor
    assert report.risk_score >= 60
    assert report.risk_score <= 85


@pytest.mark.asyncio
async def test_multimodal_deterministic_reproducibility():
    """Verify that consecutive analyses of the same multimodal input yield identical reports."""
    orchestrator = MultimodalOrchestrator(enable_reputation=False)
    target_msg = "Your account will be suspended within 24 hours. Enter your password to unlock."

    report_1 = await orchestrator.analyze(
        input_type=InputType.MESSAGE_TEXT,
        text_content=target_msg,
        analysis_id="repro-1",
    )
    report_2 = await orchestrator.analyze(
        input_type=InputType.MESSAGE_TEXT,
        text_content=target_msg,
        analysis_id="repro-2",
    )

    assert report_1.risk_score == report_2.risk_score
    assert report_1.trust_score == report_2.trust_score
    assert report_1.recommended_action == report_2.recommended_action
    assert [f.finding_code for f in report_1.findings] == [f.finding_code for f in report_2.findings]
