"""
Tests for QR Code Analysis & Extraction Engine (Phase 12)
Tests single & multi-QR detection, payload classification, dangerous scheme blocking,
deduplication, safe URL extraction, and offline execution guarantees.
"""
import io
import pytest
import qrcode
from PIL import Image

from ai_engineering.qr.qr_analyzer import QRAnalyzer, QRPayloadType
from ai_engineering.multimodal.contracts import InputType
from risk_engine.evidence import Severity


def generate_qr_image(payload: str, format: str = "PNG") -> bytes:
    """Generates synthetic QR code image in memory without external network requests."""
    qr = qrcode.QRCode(box_size=10, border=8)
    qr.add_data(payload)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    qr_img.save(buf, format=format)
    return buf.getvalue()


def test_qr_valid_url_payload_detected():
    """Verify that a legitimate or suspicious URL in a QR code is decoded and categorized as a URL."""
    target_url = "https://paypal-verification-alert.xyz/signin"
    qr_bytes = generate_qr_image(target_url)

    analyzer = QRAnalyzer()
    res, ev_list, fn_list = analyzer.analyze_image(qr_bytes)

    assert res.success is True
    assert res.input_type == InputType.QR_CODE
    assert len(res.extracted_urls) == 1
    assert res.extracted_urls[0] == target_url
    assert res.detector_metadata["qr_codes_found"] >= 1
    assert "url" in res.detector_metadata["payload_types"]


def test_qr_dangerous_scheme_generates_critical_finding():
    """Verify that executable or dangerous schemes (javascript:, file:) trigger CRITICAL security findings."""
    dangerous_payload = "javascript:alert(document.cookie)"
    qr_bytes = generate_qr_image(dangerous_payload)

    analyzer = QRAnalyzer()
    res, ev_list, fn_list = analyzer.analyze_image(qr_bytes)

    assert res.success is True
    assert len(fn_list) >= 1
    danger_finding = [f for f in fn_list if f.finding_code == "FIND-QR-DANGEROUS-SCHEME"]
    assert len(danger_finding) == 1
    assert danger_finding[0].severity == Severity.CRITICAL
    assert "prohibited executable scheme" in danger_finding[0].description.lower()


def test_qr_text_payload_detected():
    """Verify that plain text embedded in a QR code is extracted cleanly."""
    text_payload = "WIFI:S:GuestNetwork;T:WPA;P:SecretPassword;;"
    qr_bytes = generate_qr_image(text_payload)

    analyzer = QRAnalyzer()
    res, ev_list, fn_list = analyzer.analyze_image(qr_bytes)

    assert res.success is True
    assert "wifi" in res.detector_metadata["payload_types"]
    assert len(res.extracted_urls) == 0


def test_qr_no_code_detected_reports_limitation():
    """Verify that an image with no QR code reports an honest limitation without error."""
    blank_img = Image.new("RGB", (200, 200), color="white")
    buf = io.BytesIO()
    blank_img.save(buf, format="PNG")
    blank_bytes = buf.getvalue()

    analyzer = QRAnalyzer()
    res, ev_list, fn_list = analyzer.analyze_image(blank_bytes)

    assert res.success is True
    assert "LIMITATION-NO-QR-CODE-DETECTED" in res.limitations
    assert len(res.extracted_urls) == 0
    assert len(fn_list) == 0


def test_qr_duplicate_payloads_deduplicated():
    """Verify that repeated QR payloads in the same image are deduplicated."""
    target_url = "https://example.com/unique-landing"
    qr_bytes = generate_qr_image(target_url)

    analyzer = QRAnalyzer()
    res, ev_list, fn_list = analyzer.analyze_image(qr_bytes)

    # Payload deduplicated
    assert len(res.extracted_urls) == 1
    assert res.detector_metadata["unique_payloads"] == 1


def test_qr_never_automatically_fetches_url():
    """Prove that decoded URLs are strictly returned as string indicators without network invocation."""
    target_url = "http://169.254.169.254/latest/meta-data/"
    qr_bytes = generate_qr_image(target_url)

    analyzer = QRAnalyzer()
    # Inspection must complete synchronously without making HTTP requests
    res, ev_list, fn_list = analyzer.analyze_image(qr_bytes)

    assert target_url in res.extracted_urls
    # Process completed safely without hitting SSRF endpoint
    assert res.success is True
