"""
Tests for Content-Aware Input Detection, Prohibited Binary Blocking,
and Structured Report Vocabulary in Thelix AI.
"""
import io
import time
import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from PIL import Image

from app.main import app
from app.database.session import Base, get_db
from app.config import settings
from app.models.entities import Scan, RiskAssessment, FindingRecord, EvidenceRecord, ScanStatus
from app.services.input_detector import (
    detect_and_validate_input_type,
    sniff_content_type,
    sanitize_target_for_display,
    ProhibitedFileFormatException,
    InputType,
    PROHIBITED_BINARY_SIGNATURES,
)
from risk_engine.report_builder import VerdictCategory, SecurityReport, ReportBuilder
from risk_engine.evidence import Evidence, Finding, ActionVerdict, RiskLevel
from risk_engine.coverage import CoverageAssessment

TEST_JWT_SECRET = "super-secret-jwt-key-for-api-integration-tests"
settings.SUPABASE_JWT_SECRET = TEST_JWT_SECRET

TEST_DB_URL = "sqlite:///:memory:"
test_engine = create_engine(
    TEST_DB_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
Base.metadata.create_all(bind=test_engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


def make_auth_headers(user_id: str) -> dict:
    payload = {
        "sub": user_id,
        "aud": "authenticated",
        "role": "authenticated",
        "email": f"{user_id}@thelix.ai",
        "email_verified": True,
        "exp": int(time.time()) + 3600,
    }
    token = jwt.encode(payload, TEST_JWT_SECRET, algorithm="HS256")
    return {"Authorization": f"Bearer {token}"}


def test_sniff_valid_image_formats():
    """Verify magic byte detection for valid image formats."""
    png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
    assert sniff_content_type(png_bytes) == InputType.SCREENSHOT

    jpeg_bytes = b"\xff\xd8\xff\xe0\x00\x10JFIF"
    assert sniff_content_type(jpeg_bytes) == InputType.SCREENSHOT

    webp_bytes = b"RIFF\x1a\x00\x00\x00WEBPVP8 "
    assert sniff_content_type(webp_bytes) == InputType.SCREENSHOT

    bmp_bytes = b"BM\x36\x00\x00\x00\x00\x00\x00\x00\x36\x00\x00\x00"
    assert sniff_content_type(bmp_bytes) == InputType.SCREENSHOT


def test_sniff_valid_pdf_format():
    """Verify magic byte detection for PDF files."""
    pdf_bytes = b"%PDF-1.7\r\n1 0 obj\r\n<<\r\n/Type /Catalog"
    assert sniff_content_type(pdf_bytes) == InputType.DOCUMENT_PDF


def test_sniff_valid_plain_text():
    """Verify plain text detection for clean UTF-8 text."""
    text_bytes = b"Hello, this is a plain text alert regarding your account security."
    assert sniff_content_type(text_bytes) == InputType.DOCUMENT_TEXT

    # When user specifies message context
    detected, _ = detect_and_validate_input_type(content_bytes=text_bytes, declared_type="message")
    assert detected == InputType.MESSAGE_TEXT


def test_prohibited_binary_signatures_blocked():
    """Verify that all dangerous binary formats are immediately blocked."""
    # Windows PE executable (MZ)
    with pytest.raises(ProhibitedFileFormatException) as exc_info:
        sniff_content_type(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00")
    assert "Windows PE Executable" in exc_info.value.message

    # Linux ELF executable
    with pytest.raises(ProhibitedFileFormatException) as exc_info:
        sniff_content_type(b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00")
    assert "Linux ELF" in exc_info.value.message

    # ZIP / Office Archive
    with pytest.raises(ProhibitedFileFormatException) as exc_info:
        sniff_content_type(b"PK\x03\x04\x14\x00\x00\x00\x08\x00")
    assert "ZIP" in exc_info.value.message

    # RAR archive
    with pytest.raises(ProhibitedFileFormatException) as exc_info:
        sniff_content_type(b"Rar!\x1a\x07\x00\xcf\x90\x73")
    assert "RAR Archive" in exc_info.value.message

    # 7z archive
    with pytest.raises(ProhibitedFileFormatException) as exc_info:
        sniff_content_type(b"7z\xbc\xaf\x27\x1c\x00\x04")
    assert "7-Zip" in exc_info.value.message

    # Shell script
    with pytest.raises(ProhibitedFileFormatException) as exc_info:
        sniff_content_type(b"#!/bin/bash\nrm -rf /")
    assert "shell script" in exc_info.value.message.lower()


def test_discrepancy_reconciliation():
    """
    Verify that if a user declares input_type='screenshot' but uploads a PDF,
    the pipeline detects the actual format and reconciles to DOCUMENT_PDF.
    """
    pdf_bytes = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
    detected_type, meta = detect_and_validate_input_type(
        content_bytes=pdf_bytes,
        declared_type="screenshot",
        filename="suspicious_statement.pdf",
    )
    assert detected_type == InputType.DOCUMENT_PDF
    assert meta["discrepancy_resolved"] is True
    assert meta["declared_type"] == "screenshot"


def test_qr_declaration_preserved_for_valid_image():
    """
    Verify that if user explicitly requests 'qr' and provides a PNG image,
    the input type is classified as QR_CODE.
    """
    png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
    detected_type, meta = detect_and_validate_input_type(
        content_bytes=png_bytes,
        declared_type="qr",
        filename="qr_code.png",
    )
    assert detected_type == InputType.QR_CODE


def test_sanitize_target_for_display():
    """Verify that credentials and query secrets are masked in display targets."""
    # Mask password in URL userinfo
    clean = sanitize_target_for_display("https://admin:SuperSecret123@secure.bank.com/dashboard")
    assert "SuperSecret123" not in clean
    assert "admin:[REDACTED]@secure.bank.com" in clean

    # Mask token and key query params
    clean_query = sanitize_target_for_display("https://api.gateway.com/verify?token=eyJh12345&state=ok&key=xyz789")
    assert "eyJh12345" not in clean_query
    assert "xyz789" not in clean_query
    assert "token=[REDACTED]" in clean_query
    assert "key=[REDACTED]" in clean_query
    assert "state=ok" in clean_query


def test_report_builder_verdict_categories():
    """Verify that SecurityReport populates user-facing outcome categories and advice."""
    coverage = CoverageAssessment(
        planned_checks=["url_syntax", "reputation", "heuristics", "tls"],
        completed_checks=["url_syntax", "reputation", "heuristics", "tls"],
        failed_checks=[],
        skipped_checks=[],
        coverage_ratio=1.0,
        limitations=[],
    )

    # 1. Clean report -> LIKELY_SAFE
    report_safe = ReportBuilder.build(
        scan_id="scan-safe",
        target_url="https://legit-site.com",
        normalized_url="https://legit-site.com",
        scan_status="completed",
        risk_score=10,
        trust_score=90,
        risk_level=RiskLevel.LOW,
        confidence=0.95,
        coverage=coverage,
        action=ActionVerdict.ALLOW,
        summary="Safe site",
        findings=[],
        evidence=[],
        recommendations=["Stay vigilant"],
        engine_versions={"risk_engine": "1.0.0"},
    )
    assert report_safe.verdict_category == VerdictCategory.LIKELY_SAFE
    d_safe = report_safe.to_dict()
    assert d_safe["verdict_category"] == "LIKELY_SAFE"
    assert "likely safe" in d_safe["verdict_label"].lower()
    assert len(d_safe["next_steps"]) > 0

    # 2. High risk phishing report -> PHISHING_OR_SCAM
    phish_finding = Finding(
        finding_code="HOMOGLYPH_ATTACK",
        title="Homoglyph Domain Impersonation",
        description="Punycode spoofing legitimate bank",
        severity=RiskLevel.CRITICAL,
        confidence=0.99,
        source_engine="url_intelligence",
        source_version="1.0.0",
    )
    report_phish = ReportBuilder.build(
        scan_id="scan-phish",
        target_url="https://xn--b-eha.com",
        normalized_url="https://xn--b-eha.com",
        scan_status="completed",
        risk_score=90,
        trust_score=10,
        risk_level=RiskLevel.CRITICAL,
        confidence=0.99,
        coverage=coverage,
        action=ActionVerdict.BLOCK,
        summary="Phishing site",
        findings=[phish_finding],
        evidence=[],
        recommendations=["Do not visit"],
        engine_versions={"risk_engine": "1.0.0"},
    )
    assert report_phish.verdict_category == VerdictCategory.PHISHING_OR_SCAM
    d_phish = report_phish.to_dict()
    assert d_phish["verdict_category"] == "PHISHING_OR_SCAM"
    assert "phishing" in d_phish["verdict_label"].lower()

    # 3. Malware finding -> MALWARE_INDICATORS_DETECTED
    malware_finding = Finding(
        finding_code="MALWARE_PAYLOAD_URL",
        title="Known Malware Distribution URL",
        description="URL serves malicious executable",
        severity=RiskLevel.CRITICAL,
        confidence=0.95,
        source_engine="threat_intel",
        source_version="1.0.0",
    )
    report_malware = ReportBuilder.build(
        scan_id="scan-malware",
        target_url="https://bad-payload.com",
        normalized_url="https://bad-payload.com",
        scan_status="completed",
        risk_score=95,
        trust_score=5,
        risk_level=RiskLevel.CRITICAL,
        confidence=0.95,
        coverage=coverage,
        action=ActionVerdict.BLOCK,
        summary="Malware URL",
        findings=[malware_finding],
        evidence=[],
        recommendations=["Quarantine"],
        engine_versions={"risk_engine": "1.0.0"},
    )
    assert report_malware.verdict_category == VerdictCategory.MALWARE_INDICATORS_DETECTED
    d_malware = report_malware.to_dict()
    assert d_malware["verdict_category"] == "MALWARE_INDICATORS_DETECTED"
    assert "malware" in d_malware["verdict_label"].lower()


def test_api_rejection_of_prohibited_binary_upload():
    """Verify API rejects dangerous binary upload with HTTP 400 at /v1/scans/multimodal."""
    app.dependency_overrides[get_db] = override_get_db
    user_id = "test_user_binary"
    headers = make_auth_headers(user_id)
    # Windows executable header
    exe_payload = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00"

    response = client.post(
        "/v1/scans/multimodal",
        headers=headers,
        files={"file": ("malicious.exe", io.BytesIO(exe_payload), "application/x-msdownload")},
        data={"input_type": "screenshot"},
    )
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert "Unsupported input" in detail
    assert "Windows PE Executable" in detail


def test_api_get_scan_report_includes_structured_vocabulary():
    """Verify that /v1/scans/{id}/report response contains all new outcome fields."""
    app.dependency_overrides[get_db] = override_get_db
    db = TestingSessionLocal()
    user_id = "user_report_test"
    scan_id = "scan-report-vocab-1"
    headers = make_auth_headers(user_id)

    # Seed completed scan with assessment and finding
    scan = Scan(
        id=scan_id,
        user_id=user_id,
        input_type="url",
        raw_target="https://phishing-site.example.com",
        normalized_target="https://phishing-site.example.com",
        status=ScanStatus.COMPLETED.value,
    )
    assessment = RiskAssessment(
        scan_id=scan_id,
        risk_score=85,
        trust_score=15,
        risk_level="HIGH",
        confidence=0.92,
        coverage_ratio=0.88,
        recommended_action="BLOCK",
        summary="Phishing indicators detected.",
        explanation="The site matches known credential phishing heuristics.",
    )
    finding = FindingRecord(
        scan_id=scan_id,
        finding_code="HOMOGLYPH_ATTACK",
        title="Homoglyph Domain Spoofing",
        description="Punycode deceptive lookalike",
        severity="HIGH",
        confidence=0.95,
        source_engine="url_intel",
        source_version="1.0.0",
    )
    evidence = EvidenceRecord(
        scan_id=scan_id,
        indicator_type="DOMAIN_REPUTATION",
        indicator_value_or_reference="phishing-site.example.com",
        source_engine="url_intel",
        source_version="1.0.0",
        reliability=0.90,
        confidence=0.90,
    )
    db.add(scan)
    db.add(assessment)
    db.add(finding)
    db.add(evidence)
    db.commit()
    db.close()

    resp = client.get(f"/v1/scans/{scan_id}/report", headers=headers)
    assert resp.status_code == 200
    data = resp.json()

    # Assert new fields are populated
    assert data["verdict_category"] == "PHISHING_OR_SCAM"
    assert "Phishing / Scam" in data["verdict_label"]
    assert "The site matches known credential phishing heuristics." in data["why_this_result"]
    assert len(data["what_we_checked"]) >= 1
    assert len(data["what_we_could_not_check"]) >= 1
    assert len(data["next_steps"]) >= 1
    # Assert existing fields are preserved
    assert data["scan_id"] == scan_id
    assert data["status"] == "COMPLETED"
    assert data["assessment"]["risk_score"] == 85
    assert len(data["findings"]) == 1
