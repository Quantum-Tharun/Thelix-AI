"""
Phase 20 — Controlled Pilot Execution & Real-World Detection Validation Tests
Covers Stages B through E:
- Stage B: Global emergency shutdown kill switch (503 on scan submissions & uploads; read endpoints preserved).
           Immediate blocking of removed pilot users across all scan creation and upload routes.
           Cross-user scan isolation.
- Stage C: Feedback authorization, cross-user feedback modification rejection, and feedback idempotency.
- Stage D: Privacy-preserving operational telemetry endpoint (/v1/maintenance/metrics).
- Stage E: Ground-truth adjudication workflow, split isolation enforcement, and benchmark leakage prevention.
"""
import io
import time
import uuid
import tempfile
import os
from unittest.mock import patch
import pytest
import jwt
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.database.session import Base, get_db
from app.config import settings
from app.models.entities import Scan, ScanFeedback, ScanStatus
from ai_engineering.evaluation.adjudication import (
    AdjudicationManager,
    PilotReviewCase,
    DatasetLeakageError,
    InvalidReviewError,
)

TEST_JWT_SECRET = "super-secret-jwt-key-for-phase20-pilot-execution"
test_engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
Base.metadata.create_all(bind=test_engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(autouse=True)
def setup_phase20_context():
    app.dependency_overrides[get_db] = override_get_db
    settings.SUPABASE_JWT_SECRET = TEST_JWT_SECRET
    yield


client = TestClient(app)


def make_jwt(payload: dict, secret: str = TEST_JWT_SECRET) -> str:
    return jwt.encode(payload, secret, algorithm="HS256")


def make_pilot_token(user_id: str, email: str = "pilot.tester@thelix.ai", email_verified: bool = True) -> str:
    payload = {
        "sub": user_id,
        "aud": "authenticated",
        "role": "authenticated",
        "email": email,
        "email_verified": email_verified,
        "exp": int(time.time()) + 3600,
    }
    return make_jwt(payload)


# ==============================================================================
# Stage B — Emergency Shutdown & Pilot Access Validation
# ==============================================================================

def test_emergency_shutdown_blocks_all_scan_creation_and_uploads():
    """Verify that EMERGENCY_SHUTDOWN=True halts new scans and uploads with 503, preserving read routes."""
    token = make_pilot_token(user_id="user-shutdown-test", email="allowed.user@thelix.ai")
    headers = {"Authorization": f"Bearer {token}"}

    with patch.object(settings, "EMERGENCY_SHUTDOWN", True), \
         patch.object(settings, "PILOT_MODE_ENABLED", True), \
         patch.object(settings, "PILOT_ALLOWED_EMAILS", "allowed.user@thelix.ai"):

        # 1. POST /v1/scans blocked with 503
        resp_url = client.post(
            "/v1/scans",
            json={"target": "https://example.com", "input_type": "url"},
            headers=headers,
        )
        assert resp_url.status_code == 503
        assert "emergency shutdown" in resp_url.json()["detail"].lower()

        # 2. POST /v1/scans/multimodal blocked with 503
        resp_mm = client.post(
            "/v1/scans/multimodal",
            data={"input_type": "text", "text_content": "Suspicious email test"},
            headers=headers,
        )
        assert resp_mm.status_code == 503
        assert "emergency shutdown" in resp_mm.json()["detail"].lower()

        # 3. POST /v1/scans/uploads blocked with 503
        dummy_file = io.BytesIO(b"fake screenshot content")
        resp_upload = client.post(
            "/v1/scans/uploads",
            files={"file": ("screenshot.png", dummy_file, "image/png")},
            data={"artifact_type": "screenshot"},
            headers=headers,
        )
        assert resp_upload.status_code == 503
        assert "emergency shutdown" in resp_upload.json()["detail"].lower()

        # 4. Read operations remain accessible
        resp_health = client.get("/health")
        assert resp_health.status_code == 200


def test_removing_enrolled_pilot_user_immediately_blocks_all_routes():
    """Verify that removing an enrolled user from PILOT_ALLOWED_EMAILS blocks them immediately on all write routes."""
    token = make_pilot_token(user_id="revoked-user-id", email="revoked.tester@thelix.ai")
    headers = {"Authorization": f"Bearer {token}"}

    with patch.object(settings, "PILOT_MODE_ENABLED", True), \
         patch.object(settings, "PILOT_ALLOWED_EMAILS", "active.tester@thelix.ai"):  # User not in allowlist

        # URL scan blocked (403)
        assert client.post(
            "/v1/scans",
            json={"target": "https://example.com", "input_type": "url"},
            headers=headers,
        ).status_code == 403

        # Multimodal scan blocked (403)
        assert client.post(
            "/v1/scans/multimodal",
            data={"input_type": "text", "text_content": "test"},
            headers=headers,
        ).status_code == 403

        # Artifact upload blocked (403)
        dummy_file = io.BytesIO(b"content")
        assert client.post(
            "/v1/scans/uploads",
            files={"file": ("file.png", dummy_file, "image/png")},
            data={"artifact_type": "screenshot"},
            headers=headers,
        ).status_code == 403


def test_cross_user_scan_isolation():
    """Verify User A cannot retrieve or view scans belonging to User B (404 Not Found)."""
    db = TestingSessionLocal()
    scan_id = str(uuid.uuid4())
    scan_user_b = Scan(
        id=scan_id,
        user_id="user-b",
        status=ScanStatus.COMPLETED.value,
        input_type="url",
        raw_target="https://private-target.com",
        normalized_target="https://private-target.com",
    )
    db.add(scan_user_b)
    db.commit()
    db.close()

    # User A tries to view User B's scan
    token_a = make_pilot_token(user_id="user-a")
    resp = client.get(f"/v1/scans/{scan_id}", headers={"Authorization": f"Bearer {token_a}"})
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Scan not found"


# ==============================================================================
# Stage C — Feedback Authorization & Idempotency
# ==============================================================================

def test_feedback_cross_user_tampering_rejected():
    """Verify User A cannot submit feedback on User B's scan."""
    db = TestingSessionLocal()
    scan_id = str(uuid.uuid4())
    scan_user_b = Scan(
        id=scan_id,
        user_id="user-b",
        status=ScanStatus.COMPLETED.value,
        input_type="url",
        raw_target="https://feedback-test.com",
        normalized_target="https://feedback-test.com",
    )
    db.add(scan_user_b)
    db.commit()
    db.close()

    token_a = make_pilot_token(user_id="user-a")
    resp = client.post(
        f"/v1/scans/{scan_id}/feedback",
        json={"rating": "negative", "comments": "Unauthorized feedback attempt"},
        headers={"Authorization": f"Bearer {token_a}"},
    )
    assert resp.status_code == 404


def test_feedback_submission_is_idempotent():
    """Verify duplicate feedback updates the existing record without creating unbounded rows."""
    db = TestingSessionLocal()
    user_id = f"feedback-user-{uuid.uuid4().hex[:6]}"
    scan_id = str(uuid.uuid4())
    scan = Scan(
        id=scan_id,
        user_id=user_id,
        status=ScanStatus.COMPLETED.value,
        input_type="url",
        raw_target="https://idempotent-test.com",
        normalized_target="https://idempotent-test.com",
    )
    db.add(scan)
    db.commit()

    token = make_pilot_token(user_id=user_id)
    headers = {"Authorization": f"Bearer {token}"}

    # First submission
    resp1 = client.post(
        f"/v1/scans/{scan_id}/feedback",
        json={"rating": "positive", "comments": "First comment"},
        headers=headers,
    )
    assert resp1.status_code == 201

    # Second submission on same scan by same user
    resp2 = client.post(
        f"/v1/scans/{scan_id}/feedback",
        json={"rating": "negative", "comments": "Updated comment"},
        headers=headers,
    )
    assert resp2.status_code == 201

    # Verify only ONE feedback record exists in database for this scan and user
    feedback_rows = db.query(ScanFeedback).filter(
        ScanFeedback.scan_id == scan_id,
        ScanFeedback.user_id == user_id,
    ).all()
    assert len(feedback_rows) == 1
    assert feedback_rows[0].rating == "negative"
    assert feedback_rows[0].comments == "Updated comment"
    db.close()


# ==============================================================================
# Stage D — Operational Telemetry Endpoint
# ==============================================================================

def test_operational_metrics_endpoint_access_and_privacy():
    """Verify /v1/maintenance/metrics is restricted to service_role and exposes no private targets."""
    # 1. Unauthenticated or user token rejected with 403
    user_token = make_pilot_token(user_id="user-metric-tester")
    resp_user = client.get("/v1/maintenance/metrics", headers={"Authorization": f"Bearer {user_token}"})
    assert resp_user.status_code == 403

    # 2. Service role token accepted via X-Service-Token
    service_headers = {"X-Service-Token": settings.INTERNAL_SERVICE_TOKEN}
    resp_service = client.get("/v1/maintenance/metrics", headers=service_headers)
    assert resp_service.status_code == 200
    data = resp_service.json()

    assert data["status"] == "operational"
    assert "scans_by_input_type" in data
    assert "scans_by_status" in data
    assert "assessments_by_verdict" in data
    assert "feedback_by_rating" in data
    assert "reconciled_timeout_events" in data

    # 3. Privacy check: Ensure response text contains no URLs, tokens, or emails
    raw_text = resp_service.text.lower()
    assert "http://" not in raw_text
    assert "https://" not in raw_text
    assert "@" not in raw_text
    assert "password" not in raw_text


# ==============================================================================
# Stage E — Ground-Truth Adjudication & Leakage Prevention
# ==============================================================================

def test_adjudication_rejects_eval_or_holdout_split_assignment():
    """Verify that pilot findings can ONLY be assigned to 'tuning' and never 'holdout' or 'eval'."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = os.path.join(tmpdir, "adjudication_test.json")
        mgr = AdjudicationManager(log_path=log_file)

        # Attempt to assign to holdout -> must raise DatasetLeakageError
        with pytest.raises(DatasetLeakageError):
            mgr.review_case(
                case_id="case-leak-01",
                modality="url",
                original_score=85,
                original_verdict="BLOCK",
                sanitized_evidence_codes=["BRAND_IMPERSONATION"],
                reviewer_label="MALICIOUS",
                review_rationale="Verified impersonation page mimicking bank login",
                reviewer_id="security-analyst-1",
                split_assignment="holdout",
            )

        # Attempt to assign to eval -> must raise DatasetLeakageError
        with pytest.raises(DatasetLeakageError):
            mgr.review_case(
                case_id="case-leak-02",
                modality="url",
                original_score=85,
                original_verdict="BLOCK",
                sanitized_evidence_codes=["BRAND_IMPERSONATION"],
                reviewer_label="MALICIOUS",
                review_rationale="Verified impersonation page mimicking bank login",
                reviewer_id="security-analyst-1",
                split_assignment="eval",
            )


def test_adjudication_promotes_only_verified_tuning_cases():
    """Verify that decisive reviewed cases are recorded and correctly assigned to tuning."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = os.path.join(tmpdir, "adjudication_valid.json")
        mgr = AdjudicationManager(log_path=log_file)

        case = mgr.review_case(
            case_id="case-pilot-01",
            modality="url",
            original_score=95,
            original_verdict="BLOCK",
            sanitized_evidence_codes=["LOOKALIKE_DOMAIN", "CREDENTIAL_HARVEST"],
            reviewer_label="MALICIOUS",
            review_rationale="Confirmed lookalike domain targeting employee SSO portal",
            reviewer_id="lead-reviewer",
            split_assignment="tuning",
        )

        assert case.is_promoted_to_dataset is True
        assert case.split_assignment == "tuning"
        assert case.reviewer_label == "MALICIOUS"

        # Unresolved case should NOT be promoted to dataset
        unresolved_case = mgr.review_case(
            case_id="case-pilot-02",
            modality="screenshot",
            original_score=45,
            original_verdict="INCONCLUSIVE",
            sanitized_evidence_codes=["LOW_CONFIDENCE"],
            reviewer_label="UNRESOLVED",
            review_rationale="Insufficient context in screenshot; unable to determine malicious intent",
            reviewer_id="lead-reviewer",
            split_assignment=None,
        )

        assert unresolved_case.is_promoted_to_dataset is False
        assert unresolved_case.split_assignment is None

        summary = mgr.get_summary_metrics()
        assert summary["total_reviewed"] == 2
        assert summary["promoted_to_tuning_dataset"] == 1
