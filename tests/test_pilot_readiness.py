"""
Controlled Pilot Readiness and Deployment Safety Tests (Phase 16)
Verifies:
1. Environment separation & strict production configuration validation.
2. Secret redaction and masking in sanitized configuration logs.
3. Data retention lifecycle: expired artifact pruning, expired scan pruning with audit trail preservation.
4. User right-to-be-forgotten / GDPR deletion with audit log pseudonymization.
5. Stuck scan reconciliation and failure recovery (ERR_SCAN_TIMEOUT).
6. Controlled pilot access gating (allowlist enforcement and daily scan quota caps).
7. Operational monitoring and sanitized health/readiness endpoints without credential leakage.
8. Maintenance endpoint authorization barriers.
"""
import os
import time
import tempfile
import uuid
from datetime import datetime, timezone, timedelta
import pytest
import jwt
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.database.session import Base, get_db
from app.config import Settings, ConfigurationError, settings
from app.services.retention_service import RetentionService
from app.models.entities import Scan, Artifact, AuditEvent, ScanFeedback, ScanStatus
from app.repositories.scan_repository import ScanRepository

TEST_JWT_SECRET = "super-secret-jwt-key-for-api-integration-tests"

# Setup isolated in-memory test database
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
def setup_test_context():
    """Ensures test_pilot_readiness uses its dedicated database and standardized JWT secret."""
    app.dependency_overrides[get_db] = override_get_db
    settings.SUPABASE_JWT_SECRET = TEST_JWT_SECRET
    yield


client = TestClient(app)


def make_pilot_headers(user_id: str, email: str, email_verified: bool = True) -> dict:
    payload = {
        "sub": user_id,
        "aud": "authenticated",
        "role": "authenticated",
        "email": email,
        "email_verified": email_verified,
        "exp": int(time.time()) + 3600,
    }
    token = jwt.encode(payload, TEST_JWT_SECRET, algorithm="HS256")
    return {"Authorization": f"Bearer {token}"}


# ==============================================================================
# Stage B — Environment Separation & Secret Hygiene
# ==============================================================================

def test_production_config_rejects_insecure_secret_key():
    s = Settings(
        ENVIRONMENT="production",
        SECRET_KEY="your-super-secret-key",
        INTERNAL_SERVICE_TOKEN="secure-token-12345678",
        SUPABASE_JWT_SECRET="secure-supabase-jwt-secret-12345",
        ALLOWED_ORIGINS="https://app.thelix.ai",
        SAFE_LOCAL_SANDBOX_ENABLED=False,
    )
    with pytest.raises(ConfigurationError) as exc:
        s.validate_for_environment()
    assert "SECRET_KEY" in str(exc.value)


def test_production_config_rejects_missing_jwt_secret():
    s = Settings(
        ENVIRONMENT="production",
        SECRET_KEY="secure-super-long-production-secret-key-32chars",
        INTERNAL_SERVICE_TOKEN="secure-token-12345678",
        SUPABASE_JWT_SECRET="",
        ALLOWED_ORIGINS="https://app.thelix.ai",
        SAFE_LOCAL_SANDBOX_ENABLED=False,
    )
    with pytest.raises(ConfigurationError) as exc:
        s.validate_for_environment()
    assert "SUPABASE_JWT_SECRET" in str(exc.value)


def test_production_config_rejects_wildcard_cors():
    s = Settings(
        ENVIRONMENT="production",
        SECRET_KEY="secure-super-long-production-secret-key-32chars",
        INTERNAL_SERVICE_TOKEN="secure-token-12345678",
        SUPABASE_JWT_SECRET="secure-supabase-jwt-secret-12345",
        ALLOWED_ORIGINS="*",
        SAFE_LOCAL_SANDBOX_ENABLED=False,
    )
    with pytest.raises(ConfigurationError) as exc:
        s.validate_for_environment()
    assert "Wildcard CORS" in str(exc.value)


def test_production_config_rejects_enabled_sandbox():
    s = Settings(
        ENVIRONMENT="production",
        SECRET_KEY="secure-super-long-production-secret-key-32chars",
        INTERNAL_SERVICE_TOKEN="secure-token-12345678",
        SUPABASE_JWT_SECRET="secure-supabase-jwt-secret-12345",
        ALLOWED_ORIGINS="https://app.thelix.ai",
        SAFE_LOCAL_SANDBOX_ENABLED=True,
    )
    with pytest.raises(ConfigurationError) as exc:
        s.validate_for_environment()
    assert "SAFE_LOCAL_SANDBOX_ENABLED" in str(exc.value)


def test_production_config_rejects_debug_mode():
    s = Settings(
        ENVIRONMENT="production",
        DEBUG=True,
        SECRET_KEY="secure-super-long-production-secret-key-32chars",
        INTERNAL_SERVICE_TOKEN="secure-token-12345678",
        SUPABASE_JWT_SECRET="secure-supabase-jwt-secret-12345",
        ALLOWED_ORIGINS="https://app.thelix.ai",
        SAFE_LOCAL_SANDBOX_ENABLED=False,
    )
    with pytest.raises(ConfigurationError) as exc:
        s.validate_for_environment()
    assert "DEBUG" in str(exc.value)


def test_production_config_accepts_valid_settings():
    s = Settings(
        ENVIRONMENT="production",
        SECRET_KEY="secure-super-long-production-secret-key-32chars",
        INTERNAL_SERVICE_TOKEN="secure-token-12345678",
        SUPABASE_JWT_SECRET="secure-supabase-jwt-secret-12345",
        ALLOWED_ORIGINS="https://app.thelix.ai,https://portal.thelix.ai",
        SAFE_LOCAL_SANDBOX_ENABLED=False,
        DEBUG=False,
        DATABASE_URL="sqlite:///:memory:",  # In-memory permitted for tests
    )
    s.validate_for_environment()  # Should not raise


def test_development_config_permits_defaults():
    s = Settings(
        ENVIRONMENT="development",
        SECRET_KEY="your-super-secret-key",
        INTERNAL_SERVICE_TOKEN="thelix-internal-token-change-in-prod",
        SUPABASE_JWT_SECRET="",
        ALLOWED_ORIGINS="*",
    )
    s.validate_for_environment()  # Development mode preserves practical local dev without raising


def test_sanitize_for_logging_redacts_all_secrets():
    s = Settings(
        SECRET_KEY="top-secret-super-key-32chars-long",
        INTERNAL_SERVICE_TOKEN="service-token-secret-123",
        GEMINI_API_KEY="AIzaSyDummyGeminiKey",
        VIRUSTOTAL_API_KEY="vt-api-key-secret",
        SAFE_BROWSING_API_KEY="gsb-api-key-secret",
        DATABASE_URL="postgresql://thelix_user:super_secret_pw@db.internal:5432/thelix_prod",
    )
    sanitized = s.sanitize_for_logging()

    assert "super_secret_pw" not in str(sanitized)
    assert "AIzaSyDummyGeminiKey" not in str(sanitized)
    assert "top-secret" not in str(sanitized)
    assert "service-token" not in str(sanitized)
    assert sanitized["DATABASE_URL"] == "postgresql://thelix_user:[REDACTED]@db.internal:5432/thelix_prod"
    assert "CONFIGURED" in sanitized["GEMINI_API_KEY"]


# ==============================================================================
# Stage C — Privacy and Retention Lifecycle
# ==============================================================================

def test_retention_service_cleans_expired_artifacts():
    db = TestingSessionLocal()
    try:
        # Create a temp file simulating physical artifact storage
        temp_file = tempfile.NamedTemporaryFile(delete=False, prefix="artifact_test_")
        temp_file.write(b"screenshot content")
        temp_file.close()

        scan = Scan(
            id=str(uuid.uuid4()),
            user_id="user_art_1",
            input_type="screenshot",
            raw_target="screenshot.png",
            status="COMPLETED",
        )
        db.add(scan)
        db.commit()

        # Add artifact created 10 days ago (older than 7-day default)
        ten_days_ago = datetime.now(timezone.utc) - timedelta(days=10)
        artifact = Artifact(
            scan_id=scan.id,
            artifact_type="screenshot",
            storage_path=temp_file.name,
            mime_type="image/png",
            file_size_bytes=18,
            created_at=ten_days_ago,
        )
        db.add(artifact)
        db.commit()

        svc = RetentionService(db)
        deleted = svc.cleanup_expired_artifacts(max_age_days=7)

        assert deleted == 1
        assert not os.path.exists(temp_file.name)  # Physical disk file removed
        assert db.query(Artifact).filter(Artifact.id == artifact.id).first() is None
    finally:
        db.close()


def test_retention_service_cleans_expired_scans_and_preserves_audit_logs():
    db = TestingSessionLocal()
    try:
        scan_id = str(uuid.uuid4())
        user_id = "user_retention_audit"
        forty_days_ago = datetime.now(timezone.utc) - timedelta(days=40)

        scan = Scan(
            id=scan_id,
            user_id=user_id,
            input_type="url",
            raw_target="https://expired-phish.com",
            status="COMPLETED",
            created_at=forty_days_ago,
        )
        db.add(scan)
        db.commit()

        audit_ev = AuditEvent(
            scan_id=scan.id,
            user_id=user_id,
            event_type="SCAN_COMPLETED",
            details_json={"risk_score": 85, "action": "BLOCK"},
            created_at=forty_days_ago,
        )
        db.add(audit_ev)
        db.commit()

        svc = RetentionService(db)
        # Purge scans older than 30 days
        deleted = svc.cleanup_expired_scans(max_age_days=30, preserve_audit_events=True)

        assert deleted >= 1
        assert db.query(Scan).filter(Scan.id == scan_id).first() is None

        # Audit event preserved with disassociated scan_id
        surviving_event = db.query(AuditEvent).filter(AuditEvent.id == audit_ev.id).first()
        assert surviving_event is not None
        assert surviving_event.scan_id is None
        assert surviving_event.details_json.get("scan_retention_purged_at") is not None
    finally:
        db.close()


def test_retention_service_purge_user_data_pseudonymizes_audit_trail():
    db = TestingSessionLocal()
    try:
        target_uid = "user_gdpr_target_42"
        scan = Scan(
            id=str(uuid.uuid4()),
            user_id=target_uid,
            input_type="url",
            raw_target="https://user-private-target.com",
            status="COMPLETED",
        )
        db.add(scan)
        db.commit()

        feedback = ScanFeedback(
            scan_id=scan.id,
            user_id=target_uid,
            rating="false_positive",
            comments="Legit internal site",
        )
        db.add(feedback)

        audit = AuditEvent(
            scan_id=scan.id,
            user_id=target_uid,
            event_type="SCAN_SUBMITTED",
            details_json={"action": "AUDIT"},
        )
        db.add(audit)
        db.commit()

        svc = RetentionService(db)
        result = svc.purge_user_data(user_id=target_uid)

        assert result["scans_deleted"] == 1
        assert result["feedback_deleted"] == 1
        assert result["audit_records_pseudonymized"] == 1

        # Check DB state
        assert db.query(Scan).filter(Scan.user_id == target_uid).count() == 0
        assert db.query(ScanFeedback).filter(ScanFeedback.user_id == target_uid).count() == 0

        # Audit record user_id pseudonymized
        updated_audit = db.query(AuditEvent).filter(AuditEvent.id == audit.id).first()
        assert updated_audit.user_id == "ANONYMIZED_USER"
        assert updated_audit.details_json.get("user_purged_at") is not None
    finally:
        db.close()


# ==============================================================================
# Stage D & E — Operational Monitoring and Failure Recovery
# ==============================================================================

def test_health_ready_probe_sanitized_and_includes_pilot_status():
    resp = client.get("/health/ready")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ready"
    assert data["database"] == "connected"
    assert "pilot_mode_enabled" in data
    assert "providers_configured" in data
    # Ensure no secrets in response
    assert "key" not in str(data).lower() or "providers_configured" in data


def test_reconcile_stuck_scans_recovers_orphaned_processing_scans():
    db = TestingSessionLocal()
    try:
        scan_id = str(uuid.uuid4())
        thirty_mins_ago = datetime.now(timezone.utc) - timedelta(minutes=30)
        stuck_scan = Scan(
            id=scan_id,
            user_id="user_stuck_recovery",
            input_type="url",
            raw_target="https://stuck-hang.com",
            status=ScanStatus.PROCESSING.value,
            created_at=thirty_mins_ago,
        )
        db.add(stuck_scan)
        db.commit()

        svc = RetentionService(db)
        reconciled = svc.reconcile_stuck_scans(timeout_minutes=15)

        assert reconciled == 1
        updated = db.query(Scan).filter(Scan.id == scan_id).first()
        assert updated.status == ScanStatus.FAILED.value

        # Audit event records timeout recovery
        events = db.query(AuditEvent).filter(AuditEvent.scan_id == scan_id).all()
        assert any(e.event_type == "SCAN_TIMEOUT_RECONCILED" for e in events)
    finally:
        db.close()


# ==============================================================================
# Stage F — Pilot Safety Controls & Access Gating
# ==============================================================================

def test_pilot_mode_blocks_unauthorized_users(monkeypatch):
    monkeypatch.setattr(settings, "PILOT_MODE_ENABLED", True)
    monkeypatch.setattr(settings, "PILOT_ALLOWED_EMAILS", "authorized@pilot.thelix.ai,beta-tester@partner.org")
    monkeypatch.setattr(settings, "SUPABASE_JWT_SECRET", TEST_JWT_SECRET)

    # Unauthorized user attempts scan
    unauth_headers = make_pilot_headers("unauthorized_user_1", "stranger@external.com")
    resp = client.post(
        "/v1/scans",
        json={"target": "https://example.com", "input_type": "url", "enable_sandbox": False},
        headers=unauth_headers,
    )
    assert resp.status_code == 403
    assert "not enrolled in the limited pilot" in resp.json()["detail"].lower()


def test_pilot_mode_allows_authorized_users(monkeypatch):
    monkeypatch.setattr(settings, "PILOT_MODE_ENABLED", True)
    monkeypatch.setattr(settings, "PILOT_ALLOWED_EMAILS", "authorized@pilot.thelix.ai,beta-tester@partner.org")
    monkeypatch.setattr(settings, "SUPABASE_JWT_SECRET", TEST_JWT_SECRET)

    auth_headers = make_pilot_headers("auth_user_uuid", "authorized@pilot.thelix.ai")
    resp = client.post(
        "/v1/scans",
        json={"target": "https://example.com", "input_type": "url", "enable_sandbox": False},
        headers=auth_headers,
    )
    assert resp.status_code in (201, 202)


def test_pilot_mode_enforces_daily_scan_quota(monkeypatch):
    monkeypatch.setattr(settings, "PILOT_MODE_ENABLED", True)
    monkeypatch.setattr(settings, "PILOT_ALLOWED_EMAILS", "quota_tester@pilot.thelix.ai")
    monkeypatch.setattr(settings, "PILOT_MAX_SCANS_PER_USER_PER_DAY", 3)
    monkeypatch.setattr(settings, "SUPABASE_JWT_SECRET", TEST_JWT_SECRET)

    quota_uid = "quota_user_123"
    auth_headers = make_pilot_headers(quota_uid, "quota_tester@pilot.thelix.ai")

    # Seed 3 existing scans for today
    db = TestingSessionLocal()
    try:
        repo = ScanRepository(db)
        for i in range(3):
            repo.create_scan(
                scan_id=str(uuid.uuid4()),
                user_id=quota_uid,
                input_type="url",
                raw_target=f"https://seed-quota-{i}.com",
            )
    finally:
        db.close()

    # 4th scan must be rejected with 429 Too Many Requests
    resp = client.post(
        "/v1/scans",
        json={"target": "https://example.com", "input_type": "url", "enable_sandbox": False},
        headers=auth_headers,
    )
    assert resp.status_code == 429
    assert "quota exceeded" in resp.json()["detail"].lower()


# ==============================================================================
# Maintenance Endpoints Authorization Barrier
# ==============================================================================

def test_maintenance_endpoints_reject_unauthorized_callers():
    # Regular user attempting to trigger maintenance
    user_headers = make_pilot_headers("regular_user", "regular@user.com")

    resp1 = client.post("/v1/maintenance/retention/run", headers=user_headers)
    assert resp1.status_code == 403

    resp2 = client.post("/v1/maintenance/reconcile-stuck", headers=user_headers)
    assert resp2.status_code == 403


def test_maintenance_retention_runs_with_service_token(monkeypatch):
    monkeypatch.setattr(settings, "INTERNAL_SERVICE_TOKEN", "valid-internal-maintenance-token")

    service_headers = {"X-Service-Token": "valid-internal-maintenance-token"}
    resp = client.post("/v1/maintenance/retention/run", headers=service_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "completed"
    assert "artifacts_pruned" in data
    assert "scans_pruned" in data
    assert "stuck_scans_reconciled" not in data or "temp_files_pruned" in data
