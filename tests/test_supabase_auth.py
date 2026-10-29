"""
Supabase Authentication & JWT Verification Unit Tests
Tests token validation, signature checks, claim extraction, expiry enforcement,
and derivation of user identity strictly from verified token claims.
"""
import pytest
import time
import jwt
from fastapi import HTTPException

from app.auth.supabase import SupabaseAuthVerifier, get_current_user_id
from app.config import settings

TEST_JWT_SECRET = "super-secret-jwt-key-for-supabase-testing-32chars"


@pytest.fixture(autouse=True)
def setup_supabase_secret(monkeypatch):
    """Ensure tests run against a known JWT secret."""
    monkeypatch.setattr(settings, "SUPABASE_JWT_SECRET", TEST_JWT_SECRET)
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")


def test_valid_supabase_jwt():
    payload = {
        "sub": "b2f6b8a1-1234-4567-89ab-cdef01234567",
        "aud": "authenticated",
        "role": "authenticated",
        "email": "user@supabase.test",
        "exp": int(time.time()) + 3600,
    }
    token = jwt.encode(payload, TEST_JWT_SECRET, algorithm="HS256")
    claims = SupabaseAuthVerifier.verify_token(token)

    assert claims["sub"] == "b2f6b8a1-1234-4567-89ab-cdef01234567"
    assert claims["aud"] == "authenticated"
    assert claims["email"] == "user@supabase.test"


def test_expired_supabase_jwt():
    payload = {
        "sub": "user_expired_id",
        "aud": "authenticated",
        "exp": int(time.time()) - 3600,  # Expired 1 hour ago
    }
    token = jwt.encode(payload, TEST_JWT_SECRET, algorithm="HS256")

    with pytest.raises(HTTPException) as exc_info:
        SupabaseAuthVerifier.verify_token(token)

    assert exc_info.value.status_code == 401
    assert "expired" in exc_info.value.detail.lower()


def test_invalid_signature_supabase_jwt():
    payload = {
        "sub": "user_tampered_id",
        "aud": "authenticated",
        "exp": int(time.time()) + 3600,
    }
    # Signed with wrong secret (32+ bytes to meet RFC 7518 length recommendation)
    token = jwt.encode(payload, "wrong-secret-key-attacker-32bytes-long", algorithm="HS256")

    with pytest.raises(HTTPException) as exc_info:
        SupabaseAuthVerifier.verify_token(token)

    assert exc_info.value.status_code == 401
    assert "invalid token" in exc_info.value.detail.lower()


def test_invalid_audience_rejected():
    payload = {
        "sub": "user_id",
        "aud": "wrong_audience_attacker",
        "exp": int(time.time()) + 3600,
    }
    token = jwt.encode(payload, TEST_JWT_SECRET, algorithm="HS256")

    with pytest.raises(HTTPException) as exc_info:
        SupabaseAuthVerifier.verify_token(token)

    assert exc_info.value.status_code == 401
    assert "audience" in exc_info.value.detail.lower()


def test_missing_sub_rejected():
    payload = {
        "aud": "authenticated",
        "exp": int(time.time()) + 3600,
    }
    token = jwt.encode(payload, TEST_JWT_SECRET, algorithm="HS256")

    with pytest.raises(HTTPException) as exc_info:
        SupabaseAuthVerifier.verify_token(token)

    assert exc_info.value.status_code == 401
    assert "sub" in exc_info.value.detail.lower()


@pytest.mark.asyncio
async def test_get_current_user_id_dependency():
    user_uuid = "99999999-4444-4444-4444-111111111111"
    payload = {
        "sub": user_uuid,
        "aud": "authenticated",
        "exp": int(time.time()) + 3600,
    }
    token = jwt.encode(payload, TEST_JWT_SECRET, algorithm="HS256")
    resolved_id = await get_current_user_id(authorization=f"Bearer {token}")

    assert resolved_id == user_uuid


@pytest.mark.asyncio
async def test_user_facing_endpoint_rejects_service_credentials(monkeypatch):
    monkeypatch.setattr(settings, "SUPABASE_SERVICE_ROLE_KEY", "valid-service-role-key-999")
    from app.auth.supabase import get_authenticated_user_id

    # Must reject service token on user-facing endpoints with 403 Forbidden
    with pytest.raises(HTTPException) as exc_info:
        await get_authenticated_user_id(x_service_token="valid-service-role-key-999")

    assert exc_info.value.status_code == 403
    assert "prohibited on user-facing endpoints" in exc_info.value.detail


@pytest.mark.asyncio
async def test_service_role_authentication(monkeypatch):
    monkeypatch.setattr(settings, "SUPABASE_SERVICE_ROLE_KEY", "valid-service-role-key-999")
    from app.auth.supabase import get_service_or_user_id

    resolved_id = await get_service_or_user_id(x_service_token="valid-service-role-key-999")
    assert resolved_id == "service_role"

