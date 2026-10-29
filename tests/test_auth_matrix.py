"""
Tests for Comprehensive Authentication & Authorization Matrix (Phase 13)
Verifies:
1. Missing token rejection (401 Unauthorized) across all user-facing endpoints.
2. Service-role token rejection (403 Forbidden) on user-facing endpoints.
3. Cross-user object isolation (404 Not Found, preventing ID enumeration).
4. Modification protections (cannot delete or submit feedback on other user's scans).
5. Internal service role authorization on /v1/ai/* routes.
"""
import time
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import jwt

from app.main import app
from app.database.session import Base, get_db
from app.config import settings

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


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


def make_user_token(user_id: str) -> str:
    payload = {
        "sub": user_id,
        "aud": "authenticated",
        "role": "authenticated",
        "exp": int(time.time()) + 3600,
    }
    return jwt.encode(payload, TEST_JWT_SECRET, algorithm="HS256")


def make_service_role_token() -> str:
    payload = {
        "sub": "service_role",
        "aud": "service_role",
        "role": "service_role",
        "exp": int(time.time()) + 3600,
    }
    return jwt.encode(payload, TEST_JWT_SECRET, algorithm="HS256")


@pytest.fixture
def alice_scan():
    """Seeds a scan owned by Alice in the isolated test DB."""
    h_alice = {"Authorization": f"Bearer {make_user_token('alice_uuid')}"}
    res = client.post(
        "/v1/scans?sync=true",
        json={"target": "https://alice-private-work.com", "input_type": "url", "enable_sandbox": False},
        headers=h_alice,
    )
    assert res.status_code == 201
    return res.json()["scan_id"]


def test_auth_matrix_unauthenticated_requests_rejected(alice_scan):
    """Verify that every protected user-facing endpoint rejects unauthenticated requests with 401."""
    endpoints = [
        ("POST", "/v1/scans", {"json": {"target": "https://example.com"}}),
        ("GET", "/v1/scans", {}),
        ("GET", f"/v1/scans/{alice_scan}", {}),
        ("GET", f"/v1/scans/{alice_scan}/report", {}),
        ("GET", f"/v1/scans/{alice_scan}/events", {}),
        ("DELETE", f"/v1/scans/{alice_scan}", {}),
        ("POST", f"/v1/scans/{alice_scan}/feedback", {"json": {"rating": "helpful"}}),
        ("POST", "/v1/scans/uploads", {"data": {"artifact_type": "screenshot"}}),
        ("POST", "/v1/scans/multimodal", {"data": {"input_type": "message", "text_content": "test"}}),
    ]

    for method, path, kwargs in endpoints:
        res = client.request(method, path, **kwargs)
        assert res.status_code == 401, f"{method} {path} did not return 401 when unauthenticated"


def test_auth_matrix_service_role_token_rejected_on_user_facing_routes(alice_scan):
    """Verify that service-role tokens cannot impersonate end-users or access user routes (403 Forbidden)."""
    h_service = {"Authorization": f"Bearer {make_service_role_token()}"}
    h_service_header = {"X-Service-Token": settings.INTERNAL_SERVICE_TOKEN}

    # Test Bearer service_role JWT
    endpoints = [
        ("POST", "/v1/scans", {"json": {"target": "https://example.com"}}),
        ("GET", "/v1/scans", {}),
        ("GET", f"/v1/scans/{alice_scan}", {}),
        ("POST", "/v1/scans/multimodal", {"data": {"input_type": "message", "text_content": "test"}}),
    ]

    for method, path, kwargs in endpoints:
        res = client.request(method, path, headers=h_service, **kwargs)
        assert res.status_code == 403, f"{method} {path} allowed service_role JWT"

    # Test X-Service-Token header rejected on user routes
    res = client.get("/v1/scans", headers=h_service_header)
    assert res.status_code == 403


def test_auth_matrix_cross_user_access_returns_404(alice_scan):
    """Verify that Bob cannot access, inspect, or modify Alice's scan (404 Not Found to prevent enumeration)."""
    h_bob = {"Authorization": f"Bearer {make_user_token('bob_attacker_uuid')}"}

    # 1. Inspect status
    res = client.get(f"/v1/scans/{alice_scan}", headers=h_bob)
    assert res.status_code == 404

    # 2. Inspect report
    res = client.get(f"/v1/scans/{alice_scan}/report", headers=h_bob)
    assert res.status_code == 404

    # 3. Inspect audit events
    res = client.get(f"/v1/scans/{alice_scan}/events", headers=h_bob)
    assert res.status_code == 404

    # 4. Submit feedback on Alice's scan
    res = client.post(
        f"/v1/scans/{alice_scan}/feedback",
        json={"rating": "false_positive", "comments": "tampering"},
        headers=h_bob,
    )
    assert res.status_code == 404

    # 5. Delete Alice's scan
    res = client.delete(f"/v1/scans/{alice_scan}", headers=h_bob)
    assert res.status_code == 404

    # Confirm Alice's scan still exists and was not deleted by Bob
    h_alice = {"Authorization": f"Bearer {make_user_token('alice_uuid')}"}
    res_alice = client.get(f"/v1/scans/{alice_scan}", headers=h_alice)
    assert res_alice.status_code == 200


def test_internal_ai_gateway_service_role_authorized():
    """Verify that /v1/ai/* routes accept valid service role tokens."""
    h_service = {"X-Service-Token": settings.INTERNAL_SERVICE_TOKEN}
    payload = {
        "user_id": "service_caller",
        "url": "https://service-check.com",
        "source": "api_test",
    }

    res = client.post("/v1/ai/analyze-url", json=payload, headers=h_service)
    assert res.status_code == 200
    assert "trust_score" in res.json()
    assert "threat_level" in res.json()

    # Invalid service token rejected
    bad_service = {"X-Service-Token": "invalid-token"}
    res_bad = client.post("/v1/ai/analyze-url", json=payload, headers=bad_service)
    assert res_bad.status_code == 401
