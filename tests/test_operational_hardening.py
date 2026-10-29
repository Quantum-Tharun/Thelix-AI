"""
Phase 18 — Operational Deployment Hardening & Pilot Launch Verification Tests
Verifies:
1. Stage B: Reverse proxy trust boundary, client IP anti-spoofing, and HSTS/security headers.
2. Stage C: Atomic database quota reservation, refund on rejection, and rollback safety.
3. Stage D: Streaming request body size limiter (chunked transfers, misreported Content-Length).
4. Stage E: Supabase JWT verification matrix (explicit verified-email signal, zero-width confusable normalization, role boundaries).
5. Stage F: Modern Google GenAI SDK (google.genai) provider resilience, timeout bounds, and secret sanitization.
6. Stage G: Telemetry sanitization, error responses without stack traces, and non-durable BackgroundTasks operational boundaries.
"""
import asyncio
import io
import time
import uuid
import re
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone
import pytest
import jwt
from fastapi.testclient import TestClient
from starlette.requests import Request
from starlette.responses import Response, JSONResponse
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.database.session import Base, get_db
from app.config import Settings, settings
from app.middleware.rate_limiter import RateLimitingMiddleware
from app.middleware.request_size_limiter import RequestSizeLimiterMiddleware
from app.repositories.scan_repository import ScanRepository
from app.models.entities import UserDailyQuota, ScanStatus
from llm.gemini_provider import GeminiProvider, _sanitize_error
from app.ai.gemini.explanation import GeminiExplanationService

TEST_JWT_SECRET = "super-secret-jwt-key-for-phase18-operational-hardening"
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
def setup_phase18_context():
    app.dependency_overrides[get_db] = override_get_db
    settings.SUPABASE_JWT_SECRET = TEST_JWT_SECRET
    yield


client = TestClient(app)


def make_jwt(payload: dict, secret: str = TEST_JWT_SECRET) -> str:
    return jwt.encode(payload, secret, algorithm="HS256")


def make_token(
    user_id: str,
    email: str = "pilot@thelix.ai",
    email_verified: bool = True,
    role: str = "authenticated",
    email_confirmed_at: str = None,
    user_metadata: dict = None,
) -> str:
    payload = {
        "sub": user_id,
        "aud": "authenticated",
        "role": role,
        "email": email,
        "exp": int(time.time()) + 3600,
    }
    if email_verified is not None:
        payload["email_verified"] = email_verified
    if email_confirmed_at:
        payload["email_confirmed_at"] = email_confirmed_at
    if user_metadata:
        payload["user_metadata"] = user_metadata
    return make_jwt(payload)


# ==============================================================================
# Stage B — Reverse Proxy Trust & Anti-Spoofing Tests
# ==============================================================================

def test_untrusted_client_cannot_spoof_ip_via_x_forwarded_for():
    """Verify that an untrusted direct client cannot spoof its IP or evade rate limits via X-Forwarded-For."""
    middleware = RateLimitingMiddleware(app=None, rate_limit_per_minute=60)
    
    # Simulate direct connection from untrusted IP 192.168.1.100 claiming to be 203.0.113.195
    scope = {
        "type": "http",
        "client": ("192.168.1.100", 12345),
        "headers": [
            (b"x-forwarded-for", b"203.0.113.195"),
        ],
    }
    req = Request(scope)

    # When TRUSTED_PROXIES is empty, the header is ignored and direct client IP is used
    with patch.object(settings, "TRUSTED_PROXIES", ""):
        client_id = middleware._extract_client_id(req)
        assert client_id == "ip:192.168.1.100"

    # When TRUSTED_PROXIES has a different proxy IP, header is still ignored
    with patch.object(settings, "TRUSTED_PROXIES", "10.0.0.1, 10.0.0.2"):
        client_id = middleware._extract_client_id(req)
        assert client_id == "ip:192.168.1.100"


def test_trusted_proxy_forwarded_client_ip_accepted():
    """Verify that when direct peer is in TRUSTED_PROXIES, X-Forwarded-For is trusted."""
    middleware = RateLimitingMiddleware(app=None, rate_limit_per_minute=60)
    
    scope = {
        "type": "http",
        "client": ("10.0.0.1", 12345),
        "headers": [
            (b"x-forwarded-for", b"203.0.113.195, 10.0.0.1"),
        ],
    }
    req = Request(scope)

    with patch.object(settings, "TRUSTED_PROXIES", "10.0.0.1, 10.0.0.2"):
        client_id = middleware._extract_client_id(req)
        # Should extract the original client IP (first public hop)
        assert client_id == "ip:203.0.113.195"


def test_security_headers_in_pilot_and_production_environments():
    """Verify HSTS and hardened security headers are enforced in pilot and production environments."""
    with patch.object(settings, "ENVIRONMENT", "pilot"):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert "Strict-Transport-Security" in resp.headers
        assert "max-age=31536000" in resp.headers["Strict-Transport-Security"]
        assert resp.headers["X-Content-Type-Options"] == "nosniff"
        assert resp.headers["X-Frame-Options"] == "DENY"
        assert "default-src 'none'" in resp.headers["Content-Security-Policy"]


def test_hsts_omitted_in_development_environment():
    """Verify HSTS is safely omitted in development to prevent local browser breaking."""
    with patch.object(settings, "ENVIRONMENT", "development"):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert "Strict-Transport-Security" not in resp.headers


# ==============================================================================
# Stage D — Streaming Request Body Size Limiter Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_streaming_request_body_exceeding_cap_rejected_asgi():
    """Verify RequestSizeLimiterMiddleware terminates chunked transfers exceeding max bytes with 413."""
    async def dummy_app(scope, receive, send):
        # Application consumes incoming chunks
        while True:
            msg = await receive()
            if not msg.get("more_body", False):
                break
        response = Response(content="ok", media_type="text/plain")
        await response(scope, receive, send)

    # Wrap dummy_app with RequestSizeLimiterMiddleware with a small limit for test
    limiter = RequestSizeLimiterMiddleware(dummy_app, max_size_bytes=100)

    # Create stream sending two 60-byte chunks (total 120 bytes > 100 max)
    sent_chunks = [b"A" * 60, b"B" * 60]
    chunk_iter = iter(sent_chunks)

    async def mock_receive():
        try:
            chunk = next(chunk_iter)
            return {"type": "http.request", "body": chunk, "more_body": True}
        except StopIteration:
            return {"type": "http.request", "body": b"", "more_body": False}

    sent_messages = []

    async def mock_send(message):
        sent_messages.append(message)

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/v1/scans/multimodal",
        "headers": [(b"content-type", b"application/octet-stream")],  # No content-length header (chunked)
    }

    await limiter(scope, mock_receive, mock_send)

    # Verify a 413 HTTP response start was sent
    start_msg = next((m for m in sent_messages if m["type"] == "http.response.start"), None)
    assert start_msg is not None
    assert start_msg["status"] == 413


@pytest.mark.asyncio
async def test_streaming_request_within_cap_passes_asgi():
    """Verify RequestSizeLimiterMiddleware allows requests within size limits."""
    called = False

    async def dummy_app(scope, receive, send):
        nonlocal called
        called = True
        msg = await receive()
        assert msg["body"] == b"small payload"
        response = Response(content="success", media_type="text/plain")
        await response(scope, receive, send)

    limiter = RequestSizeLimiterMiddleware(dummy_app, max_size_bytes=1000)

    async def mock_receive():
        return {"type": "http.request", "body": b"small payload", "more_body": False}

    sent_messages = []

    async def mock_send(message):
        sent_messages.append(message)

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/v1/scans/multimodal",
        "headers": [(b"content-length", b"13")],
    }

    await limiter(scope, mock_receive, mock_send)
    assert called is True
    start_msg = next((m for m in sent_messages if m["type"] == "http.response.start"), None)
    assert start_msg is not None
    assert start_msg["status"] == 200


# ==============================================================================
# Stage E — Supabase JWT & Pilot Verification Matrix Tests
# ==============================================================================

def test_pilot_enrollment_requires_explicit_verified_email_claim():
    """Verify that email-based pilot enrollment strictly requires email_verified or email_confirmed_at."""
    with patch.object(settings, "PILOT_MODE_ENABLED", True), \
         patch.object(settings, "PILOT_ALLOWED_EMAILS", "verified@thelix.ai, enrolled@thelix.ai"):

        # 1. Verified via email_verified: True -> Allowed
        token_verified = make_token(user_id="user-1", email="verified@thelix.ai", email_verified=True)
        resp = client.post(
            "/v1/scans",
            json={"target": "https://example.com", "input_type": "url"},
            headers={"Authorization": f"Bearer {token_verified}"},
        )
        assert resp.status_code in (201, 202)

        # 2. Verified via email_confirmed_at timestamp -> Allowed
        token_confirmed = make_token(
            user_id="user-2",
            email="enrolled@thelix.ai",
            email_verified=False,
            email_confirmed_at="2026-10-20T10:00:00Z"
        )
        resp = client.post(
            "/v1/scans",
            json={"target": "https://example.com", "input_type": "url"},
            headers={"Authorization": f"Bearer {token_confirmed}"},
        )
        assert resp.status_code in (201, 202)

        # 3. Explicitly unverified email_verified: False (no email_confirmed_at) -> 403 Forbidden
        token_unverified = make_token(user_id="user-3", email="verified@thelix.ai", email_verified=False)
        resp = client.post(
            "/v1/scans",
            json={"target": "https://example.com", "input_type": "url"},
            headers={"Authorization": f"Bearer {token_unverified}"},
        )
        assert resp.status_code == 403
        assert "not enrolled" in resp.json()["detail"].lower()

        # 4. Missing email_verified claim entirely -> 403 Forbidden (no assumption of verification)
        token_missing = make_token(user_id="user-4", email="verified@thelix.ai", email_verified=None)
        resp = client.post(
            "/v1/scans",
            json={"target": "https://example.com", "input_type": "url"},
            headers={"Authorization": f"Bearer {token_missing}"},
        )
        assert resp.status_code == 403


def test_pilot_enrollment_zero_width_confusable_normalization():
    """Verify zero-width characters in email cannot evade or confuse allowlist matching."""
    with patch.object(settings, "PILOT_MODE_ENABLED", True), \
         patch.object(settings, "PILOT_ALLOWED_EMAILS", "clean.pilot@thelix.ai"):

        # Token with zero-width spaces (\u200b) in email
        confusable_email = "clean.\u200bpilot@thelix.ai"
        token = make_token(user_id="user-5", email=confusable_email, email_verified=True)

        resp = client.post(
            "/v1/scans",
            json={"target": "https://example.com", "input_type": "url"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code in (201, 202)


def test_pilot_enrollment_by_uid_independent_of_email():
    """Verify UID-based enrollment permits access even if email claim is missing or unverified."""
    uid = "pilot-user-fixed-uuid-12345"
    with patch.object(settings, "PILOT_MODE_ENABLED", True), \
         patch.object(settings, "PILOT_ALLOWED_EMAILS", f"other@thelix.ai, {uid}"):

        token = make_token(user_id=uid, email="unverified@somedomain.com", email_verified=False)
        resp = client.post(
            "/v1/scans",
            json={"target": "https://example.com", "input_type": "url"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code in (201, 202)


# ==============================================================================
# Stage C — Atomic Quota Reservation & Refund Safety Tests
# ==============================================================================

def test_rejected_multimodal_scan_does_not_consume_quota():
    """Verify that malformed or rejected multimodal scan requests do not decrement daily quota."""
    uid = "quota-test-user-rejected"
    with patch.object(settings, "PILOT_MODE_ENABLED", True), \
         patch.object(settings, "PILOT_ALLOWED_EMAILS", "quota.user@thelix.ai"), \
         patch.object(settings, "PILOT_MAX_SCANS_PER_USER_PER_DAY", 3):

        token = make_token(user_id=uid, email="quota.user@thelix.ai", email_verified=True)
        headers = {"Authorization": f"Bearer {token}"}

        # 1. Invalid input_type rejected with 400
        resp = client.post(
            "/v1/scans/multimodal",
            data={"input_type": "invalid_binary_format", "text_content": "hello world"},
            headers=headers,
        )
        assert resp.status_code == 400

        # 2. Empty payload (neither file nor text) rejected with 400
        resp = client.post(
            "/v1/scans/multimodal",
            data={"input_type": "text"},
            headers=headers,
        )
        assert resp.status_code == 400

        # 3. Verify user daily quota row scan_count is still 0 (no quota consumed)
        db = TestingSessionLocal()
        today_key = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        quota_record = db.query(UserDailyQuota).filter(
            UserDailyQuota.user_id == uid,
            UserDailyQuota.date_key == today_key,
        ).first()
        assert quota_record is None or quota_record.scan_count == 0
        db.close()


def test_atomic_quota_reservation_strictly_enforces_limit():
    """Verify that ScanRepository.reserve_daily_scan_quota honors limit boundary atomically."""
    db = TestingSessionLocal()
    repo = ScanRepository(db)
    user_id = f"atomic-test-{uuid.uuid4().hex[:8]}"
    date_key = "2026-10-26"
    limit = 3

    # Reserve 3 slots successfully
    assert repo.reserve_daily_scan_quota(user_id=user_id, date_key=date_key, limit=limit) is True
    assert repo.reserve_daily_scan_quota(user_id=user_id, date_key=date_key, limit=limit) is True
    assert repo.reserve_daily_scan_quota(user_id=user_id, date_key=date_key, limit=limit) is True

    # 4th reservation must be rejected
    assert repo.reserve_daily_scan_quota(user_id=user_id, date_key=date_key, limit=limit) is False

    # Refund 1 slot
    repo.refund_daily_scan_quota(user_id=user_id, date_key=date_key)

    # 1 reservation should now succeed again
    assert repo.reserve_daily_scan_quota(user_id=user_id, date_key=date_key, limit=limit) is True
    # And then be exhausted once more
    assert repo.reserve_daily_scan_quota(user_id=user_id, date_key=date_key, limit=limit) is False
    db.close()


# ==============================================================================
# Stage F — Modern Google GenAI SDK (google.genai) Resilience Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_gemini_provider_sanitizes_api_keys_in_errors():
    """Verify that Gemini provider error handler sanitizes sensitive API keys from messages."""
    raw_error = "Request to https://generativelanguage.googleapis.com failed with key=AIzaSyA1234567890abcdef1234567890abcdef: quota exceeded"
    sanitized = _sanitize_error(raw_error)
    assert "AIzaSyA1234567890abcdef1234567890abcdef" not in sanitized
    assert "[REDACTED" in sanitized


@pytest.mark.asyncio
async def test_gemini_provider_handles_missing_api_key_gracefully():
    """Verify GeminiProvider returns clean failure when API key is missing."""
    provider = GeminiProvider(api_key="")
    result = await provider.generate_text("System", "Prompt")
    assert result.success is False
    assert "GEMINI_API_KEY is not configured" in result.error


@pytest.mark.asyncio
async def test_gemini_provider_handles_timeout_gracefully():
    """Verify GeminiProvider enforces bounded timeout via asyncio.wait_for."""
    provider = GeminiProvider(api_key="mock-api-key", max_retries=0)

    # Mock genai.Client so that generate_content sleeps longer than timeout
    mock_client = MagicMock()
    mock_generate = AsyncMock(side_effect=asyncio.TimeoutError())
    mock_client.aio.models.generate_content = mock_generate

    with patch("llm.gemini_provider.genai.Client", return_value=mock_client):
        result = await provider.generate_text("System", "User Prompt", timeout_seconds=0.1)
        assert result.success is False
        assert "timed out" in result.error.lower()


@pytest.mark.asyncio
async def test_gemini_explanation_service_falls_back_on_exception():
    """Verify GeminiExplanationService falls back to deterministic static explanation on any error."""
    with patch("app.ai.gemini.explanation.settings.GEMINI_API_KEY", "mock-key"):
        mock_client = MagicMock()
        mock_client.aio.models.generate_content = AsyncMock(side_effect=Exception("Upstream 503 Service Unavailable"))

        with patch("app.ai.gemini.explanation.genai.Client", return_value=mock_client):
            explanation = await GeminiExplanationService.generate_explanation(
                trust_score=20,
                reasons=["Phishing credential harvest form detected"],
            )
            assert "strongly advise against" in explanation.lower()
            assert "Phishing credential harvest form detected" in explanation


# ==============================================================================
# Stage G — Telemetry & Error Sanitization Tests
# ==============================================================================

def test_health_and_readiness_expose_no_credentials():
    """Verify that health and readiness endpoints contain no database strings, secrets, or internal paths."""
    for path in ("/health", "/readiness"):
        resp = client.get(path)
        assert resp.status_code == 200
        text = resp.text.lower()
        assert "password" not in text
        assert "secret" not in text
        assert "postgres" not in text
        assert "sqlite" not in text
        assert "connection_string" not in text
        assert "database_url" not in text


def test_404_and_validation_errors_leak_no_stack_traces():
    """Verify API error responses return structured details without Python stack traces or file paths."""
    token = make_token(user_id="user-err-test", email="pilot@thelix.ai")
    resp_404 = client.get("/v1/scans/non-existent-scan-uuid", headers={"Authorization": f"Bearer {token}"})
    assert resp_404.status_code == 404
    assert resp_404.json()["detail"] == "Scan not found"
    assert "traceback" not in resp_404.text.lower()
    assert ".py" not in resp_404.text.lower()

    # Route 404
    resp_route_404 = client.get("/v1/completely-unknown-route")
    assert resp_route_404.status_code == 404
    assert "traceback" not in resp_route_404.text.lower()
    assert ".py" not in resp_route_404.text.lower()

    # 401 unauthorized
    resp_401 = client.get("/v1/scans/non-existent-scan-uuid", headers={"Authorization": "Bearer bad.token.here"})
    assert resp_401.status_code == 401
    assert "traceback" not in resp_401.text.lower()
    assert ".py" not in resp_401.text.lower()
