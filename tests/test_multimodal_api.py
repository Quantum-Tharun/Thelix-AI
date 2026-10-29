"""
Tests for Multimodal API Endpoints (Phase 12)
Tests authenticated submission of multimodal content, file uploads, text messages,
input validation, 413 oversized handling, and user ownership enforcement.
"""
import time
import io
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

# Respect or standardize test JWT secret
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


def make_auth_headers(user_id: str) -> dict:
    payload = {
        "sub": user_id,
        "aud": "authenticated",
        "role": "authenticated",
        "email": f"{user_id}@thelix.ai",
        "exp": int(time.time()) + 3600,
    }
    token = jwt.encode(payload, TEST_JWT_SECRET, algorithm="HS256")
    return {"Authorization": f"Bearer {token}"}


def create_test_png(w: int = 100, h: int = 100) -> bytes:
    img = Image.new("RGB", (w, h), color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def test_multimodal_api_requires_authentication():
    """Verify that unauthenticated requests to /v1/scans/multimodal return 401 Unauthorized."""
    resp = client.post("/v1/scans/multimodal", data={"input_type": "message", "text_content": "test"})
    assert resp.status_code == 401


def test_multimodal_api_valid_text_message():
    """Verify that authenticated submission of text content returns 201 Created with structured report."""
    headers = make_auth_headers("user_multi_1")
    scam_text = "URGENT: Enter your password and 6-digit OTP code to restore your account."

    resp = client.post(
        "/v1/scans/multimodal",
        headers=headers,
        data={
            "input_type": "message",
            "text_content": scam_text,
        },
    )

    assert resp.status_code == 201
    data = resp.json()
    assert "scan_id" in data
    assert "report" in data
    report = data["report"]
    assert report["input_type"] == "message"
    assert report["risk_score"] >= 60  # Credential lure floor
    assert report["recommended_action"] in ("warn", "block")


def test_multimodal_api_valid_file_upload():
    """Verify that authenticated file upload returns 201 Created with report."""
    headers = make_auth_headers("user_multi_2")
    png_bytes = create_test_png()

    resp = client.post(
        "/v1/scans/multimodal",
        headers=headers,
        data={"input_type": "screenshot"},
        files={"file": ("screenshot.png", png_bytes, "image/png")},
    )

    assert resp.status_code == 201
    data = resp.json()
    assert "scan_id" in data
    assert data["report"]["input_type"] == "screenshot"


def test_multimodal_api_unsupported_input_type_rejected():
    """Verify that invalid input_type returns 400 Bad Request."""
    headers = make_auth_headers("user_multi_3")
    resp = client.post(
        "/v1/scans/multimodal",
        headers=headers,
        data={"input_type": "invalid_modality_type", "text_content": "hello"},
    )
    assert resp.status_code == 400
    assert "unsupported input_type" in resp.json()["detail"].lower()


def test_multimodal_api_missing_payload_rejected():
    """Verify that missing both file and text_content returns 400 Bad Request."""
    headers = make_auth_headers("user_multi_4")
    resp = client.post(
        "/v1/scans/multimodal",
        headers=headers,
        data={"input_type": "message"},
    )
    assert resp.status_code == 400
    assert "either a file upload or text_content must be provided" in resp.json()["detail"].lower()


def test_multimodal_api_oversized_file_rejected():
    """Verify that files exceeding the size limit return 413 Payload Too Large."""
    headers = make_auth_headers("user_multi_5")
    # Simulate oversized content > 10MB
    oversized_bytes = b"0" * (10 * 1024 * 1024 + 10)

    resp = client.post(
        "/v1/scans/multimodal",
        headers=headers,
        data={"input_type": "screenshot"},
        files={"file": ("huge.png", oversized_bytes, "image/png")},
    )

    assert resp.status_code == 413
    assert "exceeds maximum limit" in resp.json()["detail"].lower()
