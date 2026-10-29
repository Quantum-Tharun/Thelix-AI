"""
End-to-End API Integration Tests
Tests client-facing scan endpoints, authentication, authorization, ownership enforcement,
feedback, artifact upload, and backward-compatible /v1/ai routes.
"""
import time
import jwt
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.database.session import Base, get_db
from app.config import settings

TEST_JWT_SECRET = "super-secret-jwt-key-for-api-integration-tests"
settings.SUPABASE_JWT_SECRET = TEST_JWT_SECRET
settings.ENVIRONMENT = "production"

# Use in-memory SQLite database with StaticPool for test isolation
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
    """Generate authenticated headers containing a valid Supabase JWT."""
    payload = {
        "sub": user_id,
        "aud": "authenticated",
        "role": "authenticated",
        "email": f"{user_id}@thelix.ai",
        "exp": int(time.time()) + 3600,
    }
    token = jwt.encode(payload, TEST_JWT_SECRET, algorithm="HS256")
    return {"Authorization": f"Bearer {token}"}


def test_health_endpoint():
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["service"] == "Thelix AI Backend"


def test_create_and_retrieve_url_scan_sync():
    # Submit URL scan with valid Supabase Auth JWT
    user_id = "test-user-uuid-1"
    headers = make_auth_headers(user_id)
    payload = {
        "target": "https://www.example.org",
        "input_type": "url",
        "context": "Received in a normal email",
        "enable_sandbox": False,
        "sync": True,
    }

    create_resp = client.post("/v1/scans", json=payload, headers=headers)
    assert create_resp.status_code == 201
    created = create_resp.json()
    assert "scan_id" in created
    scan_id = created["scan_id"]
    assert created["status"] in ("completed", "partial")

    # Get scan status
    get_resp = client.get(f"/v1/scans/{scan_id}", headers=headers)
    assert get_resp.status_code == 200
    scan_data = get_resp.json()
    assert scan_data["scan_id"] == scan_id
    assert scan_data["user_id"] == user_id

    # Get scan report
    rep_resp = client.get(f"/v1/scans/{scan_id}/report", headers=headers)
    assert rep_resp.status_code == 200
    report_data = rep_resp.json()
    assert "assessment" in report_data
    assert report_data["assessment"]["trust_score"] == 100
    assert report_data["assessment"]["recommended_action"] == "allow"

    # Get scan audit events
    events_resp = client.get(f"/v1/scans/{scan_id}/events", headers=headers)
    assert events_resp.status_code == 200
    events = events_resp.json()
    assert len(events) >= 2
    event_types = [e["event_type"] for e in events]
    assert "SCAN_QUEUED" in event_types

    # Submit feedback
    fb_resp = client.post(
        f"/v1/scans/{scan_id}/feedback",
        json={"rating": "helpful", "comments": "Accurate safe assessment"},
        headers=headers,
    )
    assert fb_resp.status_code == 201
    assert fb_resp.json()["status"] == "recorded"


def test_create_async_scan_returns_202():
    user_id = "test-user-async-1"
    headers = make_auth_headers(user_id)
    payload = {
        "target": "https://async-target.com",
        "input_type": "url",
        "enable_sandbox": True,
        "sync": False,
    }

    create_resp = client.post("/v1/scans", json=payload, headers=headers)
    assert create_resp.status_code == 202
    created = create_resp.json()
    assert "scan_id" in created
    scan_id = created["scan_id"]
    assert created["status"].upper() in ("QUEUED", "IN_PROGRESS", "COMPLETED", "PARTIAL")

    # FastAPI TestClient runs background tasks before returning; verify scan state transitioned in DB
    get_resp = client.get(f"/v1/scans/{scan_id}", headers=headers)
    assert get_resp.status_code == 200
    assert get_resp.json()["status"].upper() in ("COMPLETED", "PARTIAL", "QUEUED")



def test_list_user_scans_isolation():
    user_a = "user-alice-list-uuid"
    user_b = "user-bob-list-uuid"
    headers_a = make_auth_headers(user_a)
    headers_b = make_auth_headers(user_b)

    # User A creates a scan
    client.post(
        "/v1/scans",
        json={"target": "https://alice-listing.com", "input_type": "url", "enable_sandbox": False, "sync": True},
        headers=headers_a,
    )

    # User A listing contains the scan
    res_a = client.get("/v1/scans", headers=headers_a)
    assert res_a.status_code == 200
    scans_a = res_a.json()
    assert len(scans_a) >= 1
    assert all(s["user_id"] == user_a for s in scans_a)

    # User B listing does NOT contain User A's scans
    res_b = client.get("/v1/scans", headers=headers_b)
    assert res_b.status_code == 200
    scans_b = res_b.json()
    assert not any(s["user_id"] == user_a for s in scans_b)


def test_cross_user_scan_access_forbidden():
    # User Alice creates scan
    h_alice = make_auth_headers("user-uuid-alice")
    resp = client.post(
        "/v1/scans",
        json={"target": "https://alice-private-site.com", "input_type": "url", "enable_sandbox": False, "sync": True},
        headers=h_alice,
    )
    scan_id = resp.json()["scan_id"]

    # User Bob attempts to access User Alice's scan
    h_bob = make_auth_headers("user-uuid-bob")
    forbidden_resp = client.get(f"/v1/scans/{scan_id}", headers=h_bob)
    assert forbidden_resp.status_code == 404


def test_unauthenticated_request_rejected():
    resp = client.get("/v1/scans")
    assert resp.status_code == 401


def test_service_token_rejected_on_user_facing_routes():
    # Attempting to access or create scans with internal service token must be rejected with 403 Forbidden
    service_headers = {"X-Service-Token": settings.INTERNAL_SERVICE_TOKEN}
    resp = client.get("/v1/scans", headers=service_headers)
    assert resp.status_code == 403
    assert "prohibited on user-facing endpoints" in resp.json()["detail"]

    create_resp = client.post(
        "/v1/scans",
        json={"target": "https://service-bypass-attempt.com", "input_type": "url"},
        headers=service_headers,
    )
    assert create_resp.status_code == 403
    assert "prohibited on user-facing endpoints" in create_resp.json()["detail"]



def test_malformed_url_rejection():
    headers = make_auth_headers("user-uuid-malformed-tester")
    resp = client.post(
        "/v1/scans",
        json={"target": "javascript:alert(1)", "input_type": "url", "enable_sandbox": False, "sync": True},
        headers=headers,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["status"] == "rejected"
    assert data["report"]["risk_score"] == 100
    assert data["report"]["recommended_action"] == "block"


def test_upload_artifact():
    headers = make_auth_headers("user-uuid-uploader")
    files = {"file": ("screenshot.png", b"\x89PNG\r\n\x1a\nfake-image-bytes", "image/png")}
    data = {"artifact_type": "screenshot"}

    resp = client.post("/v1/scans/uploads", files=files, data=data, headers=headers)
    assert resp.status_code == 201
    res = resp.json()
    assert res["status"] == "staged"
    assert "artifact_id" in res
    assert "file_hash" in res


def test_delete_scan():
    headers = make_auth_headers("user-uuid-deleter")
    resp = client.post(
        "/v1/scans",
        json={"target": "https://delete-me.org", "input_type": "url", "enable_sandbox": False, "sync": True},
        headers=headers,
    )
    scan_id = resp.json()["scan_id"]

    # Delete
    del_resp = client.delete(f"/v1/scans/{scan_id}", headers=headers)
    assert del_resp.status_code == 204

    # Verify deleted
    get_resp = client.get(f"/v1/scans/{scan_id}", headers=headers)
    assert get_resp.status_code == 404


def test_backward_compatibility_v1_ai_analyze_url():
    # Test existing /v1/ai/analyze-url route expected by Flutter frontend
    payload = {
        "user_id": "legacy_user_1",
        "url": "https://example.com",
        "source": "SMS",
        "locale": "en-US",
    }
    # 1. Unauthenticated request is rejected with 401
    unauth_resp = client.post("/v1/ai/analyze-url", json=payload)
    assert unauth_resp.status_code == 401

    # 2. Authenticated with internal service token succeeds
    service_headers = {"X-Service-Token": settings.INTERNAL_SERVICE_TOKEN}
    resp = client.post("/v1/ai/analyze-url", json=payload, headers=service_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "trust_score" in data
    assert "risk_score" in data
    assert "threat_level" in data
    assert "model_versions" in data


