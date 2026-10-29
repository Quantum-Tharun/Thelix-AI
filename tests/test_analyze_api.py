"""
Comprehensive Integration Tests for Canonical POST /v1/analyze & GET /v1/analyze/{analysis_id}
Validates:
1. Primary user-facing analyze endpoint auto-detects input type (URL, message, screenshot, QR, PDF).
2. Default synchronous return (HTTP 200) without requiring sync=true or engine selection.
3. Opt-in asynchronous enqueuing (HTTP 202) when prefer_async=true.
4. Input validation (mutual exclusion, prohibited executable blocking, 10MB/500k-char size limits).
5. Authentication and tenant isolation (HTTP 401 unauthenticated, 403 service-role token rejection, 404 cross-tenant).
6. Deterministic risk engine verdicts and safe credential redaction.
"""
import io
import time
import base64
import pytest
import jwt
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from PIL import Image

from app.main import app
from app.database.session import Base, get_db
from app.config import settings
from app.models.entities import Scan

TEST_JWT_SECRET = "super-secret-jwt-key-for-api-integration-tests"

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
def setup_analyze_test_context():
    old_secret = settings.SUPABASE_JWT_SECRET
    old_env = settings.ENVIRONMENT
    settings.SUPABASE_JWT_SECRET = TEST_JWT_SECRET
    settings.ENVIRONMENT = "production"
    app.dependency_overrides[get_db] = override_get_db
    yield
    settings.SUPABASE_JWT_SECRET = old_secret
    settings.ENVIRONMENT = old_env


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


def make_test_png_bytes(color=(0, 255, 0)) -> bytes:
    img = Image.new("RGB", (64, 64), color=color)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


# ==============================================================================
# 1. Synchronous URL Analysis Tests
# ==============================================================================

def test_analyze_safe_url_synchronous_success():
    """Verify clean URL auto-detection and immediate HTTP 200 structured report."""
    headers = make_auth_headers("user-analyze-url-safe")
    resp = client.post(
        "/v1/analyze",
        data={"content": "https://www.example.org/about"},
        headers=headers,
    )
    assert resp.status_code == 200
    report = resp.json()

    assert "analysis_id" in report
    assert "scan_id" in report
    assert report["input_type"] == "url"
    assert report["status"] == "COMPLETED"
    assert report["risk_score"] == 0
    assert report["trust_score"] == 100
    assert report["recommended_action"] == "allow"
    assert report["verdict_category"] == "LIKELY_SAFE"
    assert "findings" in report
    assert "what_we_checked" in report
    assert "what_we_could_not_check" in report
    assert "next_steps" in report
    assert len(report["next_steps"]) > 0


def test_analyze_phishing_url_synchronous():
    """Verify deceptive URL triggers deterministic risk score and clear findings."""
    headers = make_auth_headers("user-analyze-url-phish")
    suspicious_url = "http://login.paypal.com.verify-account-security-update.tk/signin"
    resp = client.post(
        "/v1/analyze",
        data={"content": suspicious_url},
        headers=headers,
    )
    assert resp.status_code == 200
    report = resp.json()

    assert report["status"] == "COMPLETED"
    assert report["risk_score"] >= 60
    assert report["recommended_action"] in ("warn", "block")
    assert report["verdict_category"] in ("PHISHING_OR_SCAM", "SUSPICIOUS")
    assert len(report["findings"]) > 0


# ==============================================================================
# 2. Text Message Analysis Tests
# ==============================================================================

def test_analyze_scam_message_text_synchronous():
    """Verify message text with credential lures auto-detects as message and flags risk."""
    headers = make_auth_headers("user-analyze-msg-scam")
    scam_msg = (
        "URGENT: Your Chase banking account has been locked due to suspicious activity. "
        "Please enter your password and submit your one-time password OTP immediately to unlock."
    )
    resp = client.post(
        "/v1/analyze",
        data={"content": scam_msg},
        headers=headers,
    )
    assert resp.status_code == 200
    report = resp.json()

    assert report["input_type"] == "message"
    assert report["status"] == "COMPLETED"
    assert report["risk_score"] >= 60
    assert report["recommended_action"] in ("warn", "block")
    assert any("CREDENTIAL" in f["finding_code"] for f in report["findings"])


def test_analyze_clean_message_text_synchronous():
    """Verify benign text message auto-detects as message and produces clean verdict."""
    headers = make_auth_headers("user-analyze-msg-clean")
    clean_msg = "Hey Sarah, are we still meeting in the second floor conference room at 3 PM?"
    resp = client.post(
        "/v1/analyze",
        data={"content": clean_msg},
        headers=headers,
    )
    assert resp.status_code == 200
    report = resp.json()

    assert report["input_type"] == "message"
    assert report["status"] == "COMPLETED"
    assert report["risk_score"] == 0
    assert report["trust_score"] == 100
    assert report["recommended_action"] == "allow"
    assert report["verdict_category"] == "LIKELY_SAFE"


# ==============================================================================
# 3. Multimodal File Analysis Tests (Screenshot, PDF)
# ==============================================================================

def test_analyze_screenshot_image_file_synchronous():
    """Verify image upload auto-detects as screenshot via magic bytes and returns report."""
    headers = make_auth_headers("user-analyze-screenshot")
    png_bytes = make_test_png_bytes()

    files = {"file": ("screenshot.png", png_bytes, "image/png")}
    resp = client.post("/v1/analyze", files=files, headers=headers)

    assert resp.status_code == 200
    report = resp.json()

    assert report["input_type"] == "screenshot"
    assert report["status"] in ("COMPLETED", "PARTIAL")
    assert "findings" in report
    assert "what_we_checked" in report


def test_analyze_pdf_document_file_synchronous():
    """Verify PDF upload auto-detects as PDF via %PDF- magic bytes and runs analysis."""
    headers = make_auth_headers("user-analyze-pdf")
    pdf_bytes = b"%PDF-1.4\n1 0 obj\n<<\n>>\nendobj\ntrailer\n<<\n>>\n%%EOF"

    files = {"file": ("invoice.pdf", pdf_bytes, "application/pdf")}
    resp = client.post("/v1/analyze", files=files, headers=headers)

    assert resp.status_code == 200
    report = resp.json()

    assert report["input_type"] == "pdf"
    assert report["status"] in ("COMPLETED", "PARTIAL")


# ==============================================================================
# 4. Asynchronous Opt-in & Status Retrieval
# ==============================================================================

def test_analyze_asynchronous_opt_in_202():
    """Verify prefer_async=true enqueues task in durable outbox and returns HTTP 202."""
    headers = make_auth_headers("user-analyze-async")
    resp = client.post(
        "/v1/analyze",
        data={"content": "https://async-worker-test.com", "prefer_async": "true"},
        headers=headers,
    )
    assert resp.status_code == 202
    data = resp.json()

    assert "analysis_id" in data
    assert "scan_id" in data
    assert data["status"] == "QUEUED"
    assert f"/v1/analyze/{data['analysis_id']}" in data["report_url"]


def test_get_analysis_report_by_id():
    """Verify GET /v1/analyze/{analysis_id} returns the completed report."""
    headers = make_auth_headers("user-analyze-get")
    # 1. Run synchronous scan
    resp = client.post(
        "/v1/analyze",
        data={"content": "https://www.google.com"},
        headers=headers,
    )
    assert resp.status_code == 200
    analysis_id = resp.json()["analysis_id"]

    # 2. Retrieve via GET
    get_resp = client.get(f"/v1/analyze/{analysis_id}", headers=headers)
    assert get_resp.status_code == 200
    retrieved = get_resp.json()

    assert retrieved["analysis_id"] == analysis_id
    assert retrieved["status"] == "COMPLETED"
    assert retrieved["trust_score"] == 100


# ==============================================================================
# 5. Input Validation & Prohibited Binary Blocking
# ==============================================================================

def test_analyze_rejects_conflicting_inputs():
    """Verify error 400 when both content and file are simultaneously provided."""
    headers = make_auth_headers("user-analyze-conflict")
    files = {"file": ("test.png", make_test_png_bytes(), "image/png")}
    data = {"content": "https://example.com"}

    resp = client.post("/v1/analyze", files=files, data=data, headers=headers)
    assert resp.status_code == 400
    assert "Cannot accept both 'content' and 'file'" in resp.json()["detail"]


def test_analyze_rejects_missing_inputs():
    """Verify error 400 when neither content nor file is provided."""
    headers = make_auth_headers("user-analyze-missing")
    resp = client.post("/v1/analyze", data={}, headers=headers)
    assert resp.status_code == 400
    assert "Either 'content'" in resp.json()["detail"]


def test_analyze_rejects_prohibited_pe_executable():
    """Verify Windows PE executable (.exe) is rejected with clear 400 before execution."""
    headers = make_auth_headers("user-analyze-exe")
    exe_bytes = b"MZ\x90\x00\x03\x00\x00\x00"  # PE magic bytes

    files = {"file": ("malware.exe", exe_bytes, "application/x-dosexec")}
    resp = client.post("/v1/analyze", files=files, headers=headers)

    assert resp.status_code == 400
    assert "Unsupported input" in resp.json()["detail"]
    assert "Windows PE Executable" in resp.json()["detail"]


def test_analyze_rejects_prohibited_elf_executable():
    """Verify Linux ELF executable is rejected with clear 400."""
    headers = make_auth_headers("user-analyze-elf")
    elf_bytes = b"\x7fELF\x02\x01\x01\x00"

    files = {"file": ("payload.bin", elf_bytes, "application/octet-stream")}
    resp = client.post("/v1/analyze", files=files, headers=headers)

    assert resp.status_code == 400
    assert "Linux ELF Executable" in resp.json()["detail"]


def test_analyze_rejects_prohibited_zip_archive():
    """Verify ZIP archive is rejected with clear 400."""
    headers = make_auth_headers("user-analyze-zip")
    zip_bytes = b"PK\x03\x04\x14\x00\x00\x00"

    files = {"file": ("archive.zip", zip_bytes, "application/zip")}
    resp = client.post("/v1/analyze", files=files, headers=headers)

    assert resp.status_code == 400
    assert "ZIP" in resp.json()["detail"]


def test_analyze_rejects_empty_file():
    """Verify 0-byte file upload returns 400 Bad Request."""
    headers = make_auth_headers("user-analyze-empty")
    files = {"file": ("empty.png", b"", "image/png")}

    resp = client.post("/v1/analyze", files=files, headers=headers)
    assert resp.status_code == 400
    assert "empty" in resp.json()["detail"].lower()


# ==============================================================================
# 6. Size Limits Enforcement
# ==============================================================================

def test_analyze_enforces_text_size_limit():
    """Verify text exceeding 500k characters is rejected with HTTP 413."""
    headers = make_auth_headers("user-analyze-oversized-text")
    oversized_text = "A" * 500_001

    resp = client.post("/v1/analyze", data={"content": oversized_text}, headers=headers)
    assert resp.status_code == 413
    assert "500,000 characters" in resp.json()["detail"]


def test_analyze_enforces_file_size_limit():
    """Verify file exceeding 10MB limit is rejected with HTTP 413."""
    headers = make_auth_headers("user-analyze-oversized-file")
    # 10MB + 1 byte
    oversized_bytes = b"A" * (10 * 1024 * 1024 + 1)

    files = {"file": ("large.txt", oversized_bytes, "text/plain")}
    resp = client.post("/v1/analyze", files=files, headers=headers)
    assert resp.status_code == 413
    assert "10MB" in resp.json()["detail"]


# ==============================================================================
# 7. Authentication, Tenant Boundaries & Privacy
# ==============================================================================

def test_analyze_unauthenticated_request_rejected():
    """Verify unauthenticated request to POST /v1/analyze returns HTTP 401."""
    resp = client.post("/v1/analyze", data={"content": "https://example.com"})
    assert resp.status_code == 401


def test_analyze_service_token_rejected_on_user_route():
    """Verify internal service token cannot be used to bypass user authentication on /v1/analyze."""
    service_headers = {"X-Service-Token": settings.INTERNAL_SERVICE_TOKEN}
    resp = client.post("/v1/analyze", data={"content": "https://example.com"}, headers=service_headers)
    assert resp.status_code == 403
    assert "prohibited on user-facing endpoints" in resp.json()["detail"]


def test_analyze_cross_tenant_isolation_anti_enumeration():
    """Verify User B cannot access User A's analysis report (strict 404 anti-enumeration)."""
    h_alice = make_auth_headers("alice-uuid-analyze")
    h_bob = make_auth_headers("bob-uuid-analyze")

    # Alice creates an analysis
    resp = client.post("/v1/analyze", data={"content": "https://alices-private-site.com"}, headers=h_alice)
    assert resp.status_code == 200
    analysis_id = resp.json()["analysis_id"]

    # Bob attempts to access Alice's analysis
    bob_resp = client.get(f"/v1/analyze/{analysis_id}", headers=h_bob)
    assert bob_resp.status_code == 404
    assert "not found" in bob_resp.json()["detail"].lower()


def test_analyze_redacts_credentials_in_target_summary():
    """Verify passwords in URLs are strictly redacted from reports and logs."""
    headers = make_auth_headers("user-analyze-redact")
    sensitive_url = "https://admin:SuperSecretP@ssword123@internal-vault.corp.net/dashboard?token=secret123456"

    resp = client.post("/v1/analyze", data={"content": sensitive_url}, headers=headers)
    assert resp.status_code == 200
    report = resp.json()

    summary = report["target_summary"]
    assert "SuperSecretP@ssword123" not in summary
    assert "secret123456" not in summary
    assert "[REDACTED]" in summary
