"""
Tests for API Security, Reliability, and Operational Readiness (Phase 13)
Verifies:
1. Liveness and deep readiness probes (/health, /health/live, /health/ready).
2. Database outage detection in /health/ready (503 Service Unavailable).
3. Standard security headers on all responses (nosniff, DENY, XSS, Request-ID).
4. Sliding-window rate limiting (429 Too Many Requests with Retry-After).
5. Input limits on target URLs (4096 character max).
6. Input limits on multimodal text content (500k character max).
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


def make_auth_headers(user_id: str = "rel_user_1") -> dict:
    payload = {
        "sub": user_id,
        "aud": "authenticated",
        "role": "authenticated",
        "exp": int(time.time()) + 3600,
    }
    token = jwt.encode(payload, TEST_JWT_SECRET, algorithm="HS256")
    return {"Authorization": f"Bearer {token}"}


def test_liveness_health_probes():
    """Verify liveness probe responds with 200 OK and service metadata."""
    res1 = client.get("/health")
    assert res1.status_code == 200
    assert res1.json()["status"] == "ok"
    assert res1.json()["service"] == "Thelix AI Backend"

    res2 = client.get("/health/live")
    assert res2.status_code == 200
    assert res2.json()["status"] == "ok"


def test_deep_readiness_probe_healthy():
    """Verify deep readiness probe actively validates DB connection and returns component versions."""
    res = client.get("/health/ready")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ready"
    assert data["database"] == "connected"
    assert "policy_version" in data
    assert "engine_versions" in data


def test_readiness_probe_fails_when_db_down():
    """Verify /health/ready returns 503 when the database probe fails."""
    def broken_db():
        class MockBrokenSession:
            def execute(self, *args, **kwargs):
                raise ConnectionError("Simulated database unreachable")
        yield MockBrokenSession()

    app.dependency_overrides[get_db] = broken_db
    try:
        res = client.get("/health/ready")
        assert res.status_code == 503
        assert "unreachable" in res.json()["detail"].lower()
    finally:
        app.dependency_overrides[get_db] = override_get_db


def test_security_headers_present_on_all_responses():
    """Verify that every HTTP response contains nosniff, DENY, and X-Request-ID."""
    res = client.get("/health")
    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert res.headers.get("X-Frame-Options") == "DENY"
    assert res.headers.get("X-XSS-Protection") == "1; mode=block"
    assert "X-Request-ID" in res.headers
    assert "X-Process-Time" in res.headers


def test_rate_limiter_enforces_threshold_and_returns_429():
    """Verify sliding-window rate limiter returns 429 when client exceeds limit."""
    # Temporarily set tight rate limit for test client
    original_limit = settings.RATE_LIMIT_PER_MINUTE
    settings.RATE_LIMIT_PER_MINUTE = 5
    settings.RATE_LIMIT_ENABLED = True

    try:
        headers = make_auth_headers("user_rate_limited_tester")
        # Submit requests up to the limit
        for _ in range(5):
            res = client.get("/v1/scans", headers=headers)
            assert res.status_code == 200

        # Next request must be throttled with 429
        throttled_res = client.get("/v1/scans", headers=headers)
        assert throttled_res.status_code == 429
        assert "Rate limit exceeded" in throttled_res.json()["detail"]
        assert "Retry-After" in throttled_res.headers
        assert int(throttled_res.headers["Retry-After"]) >= 1

        # Health checks must NOT be throttled
        health_res = client.get("/health")
        assert health_res.status_code == 200
    finally:
        settings.RATE_LIMIT_PER_MINUTE = original_limit


def test_oversized_target_url_rejected_with_422():
    """Verify that targets exceeding MAX_TARGET_LENGTH (4096 chars) are rejected with 422."""
    headers = make_auth_headers("user_input_limiter")
    huge_url = "https://example.com/search?q=" + ("A" * 4100)

    res = client.post(
        "/v1/scans",
        json={"target": huge_url, "input_type": "url", "sync": True},
        headers=headers,
    )
    assert res.status_code == 422


def test_oversized_text_content_rejected_with_413():
    """Verify that text messages exceeding MAX_TEXT_CONTENT_LENGTH (500k) are rejected with 413."""
    headers = make_auth_headers("user_text_limiter")
    huge_text = "Urgent: " + ("B" * 500_010)

    res = client.post(
        "/v1/scans/multimodal",
        data={"input_type": "message", "text_content": huge_text},
        headers=headers,
    )
    assert res.status_code == 413
    assert "exceeds maximum limit" in res.json()["detail"].lower()
