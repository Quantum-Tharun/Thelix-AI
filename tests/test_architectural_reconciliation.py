"""
Phase 2 — Architectural Reconciliation & Backend Integrity Tests
Covers Workstream A & Workstream B:
1. Unified authoritative risk engine execution across all endpoints (/v1/scans and /v1/ai/*).
2. End-to-end database persistence for /v1/ai analysis (scans, tasks, evidence, findings, assessments, audit events).
3. Identity enforcement and impersonation prevention (rejects client-supplied forged user_id).
4. Service-role token boundaries (accepts valid service tokens on /v1/ai/*, strictly rejects on user endpoints).
5. Cross-user isolation and anti-enumeration (404 Not Found).
6. Exception sanitization on /v1/ai/* error paths (no stack traces or internal secrets leaked).
"""
import time
import base64
import uuid
import pytest
import jwt
from unittest.mock import patch
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from PIL import Image
import io

from app.main import app
from app.database.session import Base, get_db
from app.config import settings
from app.models.entities import Scan, Artifact, EvidenceRecord, FindingRecord, RiskAssessment, AuditEvent

TEST_JWT_SECRET = "super-secret-jwt-key-for-api-integration-tests"
settings.SUPABASE_JWT_SECRET = TEST_JWT_SECRET
settings.ENVIRONMENT = "production"

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


@pytest.fixture(autouse=True)
def setup_reconciliation_test_context():
    """Ensure database override and JWT secret are set for each test in this module."""
    settings.SUPABASE_JWT_SECRET = TEST_JWT_SECRET
    settings.ENVIRONMENT = "production"
    app.dependency_overrides[get_db] = override_get_db
    yield
    app.dependency_overrides[get_db] = override_get_db


client = TestClient(app)


def make_user_token(user_id: str) -> str:
    payload = {
        "sub": user_id,
        "aud": "authenticated",
        "role": "authenticated",
        "email": f"{user_id}@thelix.ai",
        "exp": int(time.time()) + 3600,
    }
    return jwt.encode(payload, TEST_JWT_SECRET, algorithm="HS256")


def make_png_base64() -> str:
    img = Image.new("RGB", (64, 64), color=(255, 0, 0))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("utf-8")


# ==============================================================================
# Workstream A — Authoritative Execution & Relational Persistence
# ==============================================================================

def test_ai_analyze_url_authoritative_persistence():
    """Verify that /v1/ai/analyze-url executes the authoritative pipeline and persists entities."""
    headers = {"X-Service-Token": settings.INTERNAL_SERVICE_TOKEN}
    payload = {
        "user_id": "service_client_1",
        "url": "https://paypal-security-update.xyz/login",
        "source": "api_test",
        "locale": "en-US",
    }

    resp = client.post("/v1/ai/analyze-url", json=payload, headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert 0 <= data["trust_score"] <= 100
    assert 0 <= data["risk_score"] <= 100
    assert data["trust_score"] + data["risk_score"] == 100
    assert data["threat_level"] in ("Low", "Medium", "High", "Critical")
    assert isinstance(data["reasons"], list)
    assert isinstance(data["recommendations"], list)
    assert "model_versions" in data

    # Verify relational persistence in the database
    db = TestingSessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.user_id == "service_client_1").order_by(Scan.created_at.desc()).first()
        assert scan is not None
        assert scan.input_type == "url"
        assert scan.raw_target == "https://paypal-security-update.xyz/login"
        assert scan.status in ("COMPLETED", "PARTIAL")

        # Verify assessment persisted
        assert scan.assessment is not None
        assert scan.assessment.trust_score == data["trust_score"]
        assert scan.assessment.risk_score == data["risk_score"]

        # Verify evidence and tasks persisted
        assert len(scan.evidence) > 0
        assert len(scan.tasks) > 0
    finally:
        db.close()


def test_ai_analyze_url_user_identity_enforced():
    """Verify that an authenticated user can submit /v1/ai/analyze-url matching their own identity."""
    token = make_user_token("user_alice_reconcile")
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "user_id": "user_alice_reconcile",
        "url": "https://legit-portal.org",
        "source": "mobile_app",
    }

    resp = client.post("/v1/ai/analyze-url", json=payload, headers=headers)
    assert resp.status_code == 200

    db = TestingSessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.user_id == "user_alice_reconcile").first()
        assert scan is not None
        # User Alice can view her scan via canonical client route
        get_resp = client.get(f"/v1/scans/{scan.id}", headers=headers)
        assert get_resp.status_code == 200
    finally:
        db.close()


def test_ai_analyze_url_forged_user_id_rejected():
    """Verify that a user CANNOT forge another user_id in /v1/ai/* request body (Anti-Impersonation)."""
    alice_token = make_user_token("user_alice_reconcile")
    headers = {"Authorization": f"Bearer {alice_token}"}
    forged_payload = {
        "user_id": "user_bob_target",  # Forged identity
        "url": "https://malicious-lure.xyz",
        "source": "spoofed_call",
    }

    resp = client.post("/v1/ai/analyze-url", json=forged_payload, headers=headers)
    assert resp.status_code == 403
    assert "Forbidden" in resp.json()["detail"] or "another user" in resp.json()["detail"]


def test_ai_analyze_screenshot_authoritative_persistence():
    """Verify that /v1/ai/analyze-screenshot runs MultimodalOrchestrator and persists artifacts."""
    headers = {"X-Service-Token": settings.INTERNAL_SERVICE_TOKEN}
    payload = {
        "user_id": "service_screen_user",
        "image_base64": make_png_base64(),
        "source": "WhatsApp",
    }

    resp = client.post("/v1/ai/analyze-screenshot", json=payload, headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "trust_score" in data
    assert "risk_score" in data
    assert "threat_level" in data

    db = TestingSessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.user_id == "service_screen_user").order_by(Scan.created_at.desc()).first()
        assert scan is not None
        assert scan.input_type == "screenshot"
        assert len(scan.artifacts) > 0
        assert scan.artifacts[0].artifact_type == "screenshot"
    finally:
        db.close()


def test_ai_analyze_qr_authoritative_persistence():
    """Verify that /v1/ai/analyze-qr runs MultimodalOrchestrator and persists QR scan."""
    headers = {"X-Service-Token": settings.INTERNAL_SERVICE_TOKEN}
    payload = {
        "user_id": "service_qr_user",
        "image_base64": make_png_base64(),
    }

    resp = client.post("/v1/ai/analyze-qr", json=payload, headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "trust_score" in data
    assert "threat_level" in data

    db = TestingSessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.user_id == "service_qr_user").order_by(Scan.created_at.desc()).first()
        assert scan is not None
        assert scan.input_type == "qr"
    finally:
        db.close()


# ==============================================================================
# Workstream A — Authentication & Authorization Boundaries
# ==============================================================================

def test_unauthenticated_requests_rejected():
    """Verify all /v1/ai/* routes reject unauthenticated requests."""
    payload = {"user_id": "anon", "url": "https://example.com"}
    assert client.post("/v1/ai/analyze-url", json=payload).status_code == 401
    assert client.post("/v1/ai/analyze-screenshot", json={"user_id": "anon", "image_base64": "abc", "source": "s"}).status_code == 401
    assert client.post("/v1/ai/analyze-qr", json={"user_id": "anon", "image_base64": "abc"}).status_code == 401


def test_invalid_jwt_rejected():
    """Verify malformed or forged JWT is rejected."""
    bad_headers = {"Authorization": "Bearer not.a.valid.jwt.signature"}
    payload = {"user_id": "hacker", "url": "https://example.com"}
    resp = client.post("/v1/ai/analyze-url", json=payload, headers=bad_headers)
    assert resp.status_code == 401


def test_service_role_rejected_on_user_endpoints():
    """Verify service role credentials are prohibited on client-facing /v1/scans routes."""
    headers = {"X-Service-Token": settings.INTERNAL_SERVICE_TOKEN}
    assert client.get("/v1/scans", headers=headers).status_code == 403
    assert client.post("/v1/scans", json={"target": "https://example.com"}, headers=headers).status_code == 403
    assert client.get("/v1/scans/some-id", headers=headers).status_code == 403


def test_cross_user_isolation_anti_enumeration():
    """Verify User B cannot access, delete, or feedback User A's scans (404 Not Found)."""
    alice_token = make_user_token("alice_owner")
    bob_token = make_user_token("bob_attacker")
    h_alice = {"Authorization": f"Bearer {alice_token}"}
    h_bob = {"Authorization": f"Bearer {bob_token}"}

    # Alice creates a scan
    create_resp = client.post(
        "/v1/scans",
        json={"target": "https://alice-private-portal.com", "enable_sandbox": False},
        headers=h_alice,
    )
    assert create_resp.status_code == 201
    alice_scan_id = create_resp.json()["scan_id"]

    # Bob attempts to retrieve Alice's scan
    get_resp = client.get(f"/v1/scans/{alice_scan_id}", headers=h_bob)
    assert get_resp.status_code == 404

    # Bob attempts to view report
    rep_resp = client.get(f"/v1/scans/{alice_scan_id}/report", headers=h_bob)
    assert rep_resp.status_code == 404

    # Bob attempts to delete Alice's scan
    del_resp = client.delete(f"/v1/scans/{alice_scan_id}", headers=h_bob)
    assert del_resp.status_code == 404

    # Bob attempts to submit feedback on Alice's scan
    fb_resp = client.post(f"/v1/scans/{alice_scan_id}/feedback", json={"rating": "helpful"}, headers=h_bob)
    assert fb_resp.status_code == 404

    # Verify Alice's scan still intact
    confirm_resp = client.get(f"/v1/scans/{alice_scan_id}", headers=h_alice)
    assert confirm_resp.status_code == 200


def test_ai_error_sanitization():
    """Verify that unhandled internal exceptions in /v1/ai/* do not leak sensitive error details."""
    headers = {"X-Service-Token": settings.INTERNAL_SERVICE_TOKEN}
    payload = {"user_id": "test_err_user", "url": "https://crash-test.com", "source": "test"}

    with patch("app.services.orchestrator_service.OrchestratorService.execute_url_scan", side_effect=RuntimeError("SecretDatabasePassword=super_secret_12345")):
        resp = client.post("/v1/ai/analyze-url", json=payload, headers=headers)
        assert resp.status_code == 500
        # Assert exception message with secret is NOT leaked to consumer
        detail = resp.json().get("detail", "")
        assert "SecretDatabasePassword" not in detail
        assert "super_secret_12345" not in detail
        assert "AI analysis failed" in detail or "failed" in detail.lower()
