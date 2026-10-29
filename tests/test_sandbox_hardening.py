"""
Tests for Sandbox Security and Isolation Hardening (Phase 10)
Tests process environment scrubbing, ephemeral profile lifecycle,
subresource SSRF interception, resource limits, DNS rebinding mitigation,
worker crash/timeout recovery, and fail-closed policies.
"""
import pytest
import os
import shutil
import socket
from unittest.mock import patch, MagicMock

from sandbox.isolation import EnvironmentScrubber, EphemeralProfileManager, SubresourceInterceptor
from sandbox.browser_worker import BrowserWorker
from sandbox.controller import SandboxController
from sandbox.resource_limits import ResourceLimits
from sandbox.network_policy import NetworkPolicy
from sandbox.target_validator import TargetValidator
from risk_engine.evidence import Severity, ActionVerdict
from risk_engine.exceptions import EngineTimeoutException, TargetProhibitedException
from app.config import settings


def test_environment_scrubber_removes_application_secrets():
    """Verify that sensitive environment variables containing keys/tokens/passwords are stripped."""
    mock_env = {
        "PATH": "C:\\Windows\\System32;C:\\Python",
        "SYSTEMROOT": "C:\\Windows",
        "TEMP": "C:\\Temp",
        "DATABASE_URL": "postgresql://postgres:supersecretpassword@localhost:5432/thelix",
        "SUPABASE_SERVICE_ROLE_KEY": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.super-secret-service-key",
        "GEMINI_API_KEY": "AIzaSySecretApiKey12345",
        "VIRUSTOTAL_API_KEY": "vt-private-api-key-9999",
        "INTERNAL_SERVICE_TOKEN": "thelix-internal-token-change-in-prod",
    }

    with patch.dict(os.environ, mock_env, clear=True):
        scrubbed = EnvironmentScrubber.get_scrubbed_env()

    # Safe system variables preserved
    assert "PATH" in scrubbed
    assert "SYSTEMROOT" in scrubbed
    assert "TEMP" in scrubbed

    # All sensitive application credentials stripped
    assert "DATABASE_URL" not in scrubbed
    assert "SUPABASE_SERVICE_ROLE_KEY" not in scrubbed
    assert "GEMINI_API_KEY" not in scrubbed
    assert "VIRUSTOTAL_API_KEY" not in scrubbed
    assert "INTERNAL_SERVICE_TOKEN" not in scrubbed


def test_ephemeral_profile_manager_allocates_and_cleans_up():
    """Verify that EphemeralProfileManager creates a temporary directory and guarantees deletion on exit."""
    created_dir = None
    with EphemeralProfileManager(prefix="test_profile_") as temp_dir:
        created_dir = temp_dir
        assert os.path.exists(created_dir)
        # Create a test file inside to simulate browser cache/cookies
        test_file = os.path.join(created_dir, "cookie.txt")
        with open(test_file, "w") as f:
            f.write("mock-session-data")
        assert os.path.exists(test_file)

    # After exit, directory must be completely removed
    assert not os.path.exists(created_dir)


def test_ephemeral_profile_manager_cleans_up_on_exception():
    """Verify that EphemeralProfileManager deletes temporary directory even when an exception is raised."""
    created_dir = None
    try:
        with EphemeralProfileManager(prefix="test_exc_profile_") as temp_dir:
            created_dir = temp_dir
            assert os.path.exists(created_dir)
            raise RuntimeError("Simulated worker crash")
    except RuntimeError:
        pass

    assert not os.path.exists(created_dir)


def test_subresource_interceptor_blocks_private_destinations():
    """Verify that SubresourceInterceptor blocks internal, link-local, loopback, and metadata subresource URLs."""
    prohibited_subresources = [
        "http://127.0.0.1:8000/internal-script.js",
        "http://localhost/admin.css",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1/auth.png",
        "http://192.168.1.1/router",
        "http://metadata.google.internal/computeMetadata/v1/",
        "file:///etc/passwd",
        "ftp://internal-server.local/file.txt",
    ]

    for sub_url in prohibited_subresources:
        allowed, reason = SubresourceInterceptor.validate_subresource(sub_url)
        assert not allowed
        assert reason is not None


def test_subresource_interceptor_allows_safe_external_and_data_urls():
    """Verify that SubresourceInterceptor permits legitimate public assets and memory data/blob schemes."""
    safe_subresources = [
        "https://cdn.example.com/styles.css",
        "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js",
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAUA...",
        "blob:https://example.com/7b3f9b2d-1234-4567-89ab-cdef01234567",
        "about:blank",
    ]

    with patch("sandbox.network_policy.NetworkPolicy.validate_resolved_ips", return_value=(True, ["93.184.216.34"], None)):
        for sub_url in safe_subresources:
            allowed, reason = SubresourceInterceptor.validate_subresource(sub_url)
            assert allowed, f"Failed for {sub_url}: {reason}"
            assert reason is None


def test_dns_rebinding_defense_multi_homed_prohibited_ip():
    """Verify that if a hostname resolves to both a public and a private IP (DNS rebinding / multi-homing), it is blocked."""
    mock_addr_info = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),  # Public IP
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)),      # Loopback IP
    ]

    with patch("socket.getaddrinfo", return_value=mock_addr_info):
        allowed, resolved_ips, reason = NetworkPolicy.validate_resolved_ips("rebind-attack.example.com")

    assert not allowed
    assert "127.0.0.1" in resolved_ips
    assert "prohibited" in reason.lower() or "loopback" in reason.lower()


def test_ipv6_variants_blocked():
    """Verify that IPv6 loopback, link-local, IPv4-mapped, and cloud metadata are strictly blocked."""
    ipv6_test_cases = [
        ("::1", "loopback"),
        ("::ffff:127.0.0.1", "loopback"),
        ("::ffff:192.168.1.1", "private"),
        ("fd00:ec2::254", "metadata"),
        ("fe80::1", "link-local"),
    ]

    for ip_str, expected_keyword in ipv6_test_cases:
        allowed, reason = NetworkPolicy.is_ip_allowed(ip_str)
        assert not allowed, f"Expected {ip_str} to be blocked"
        assert expected_keyword in reason.lower() or "prohibited" in reason.lower()


@pytest.mark.asyncio
async def test_browser_worker_intercepts_embedded_ssrf_subresources():
    """Verify that BrowserWorker flags HTML containing embedded SSRF subresources."""
    malicious_html = (
        "<html><head><title>Test Phishing</title>"
        "<script src='http://169.254.169.254/latest/meta-data/credentials'></script>"
        "<img src='http://127.0.0.1:8000/probe_localhost'>"
        "</head><body><form><input type='password'></form></body></html>"
    )

    worker = BrowserWorker()

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"Content-Type": "text/html"}
    mock_resp.is_redirect = False
    mock_resp.content = malicious_html.encode("utf-8")

    with patch("sandbox.target_validator.TargetValidator.validate_target", return_value=(True, None, ["93.184.216.34"])):
        with patch("httpx.AsyncClient.get", return_value=mock_resp):
            data = await worker.inspect("https://example-phish.com/landing")

    assert "blocked_subresources" in data
    assert len(data["blocked_subresources"]) >= 2
    blocked_urls = [s["url"] for s in data["blocked_subresources"]]
    assert "http://169.254.169.254/latest/meta-data/credentials" in blocked_urls
    assert "http://127.0.0.1:8000/probe_localhost" in blocked_urls


@pytest.mark.asyncio
async def test_sandbox_controller_generates_finding_for_blocked_subresource(monkeypatch):
    """Verify that SandboxController translates intercepted SSRF subresources into security findings."""
    monkeypatch.setattr(settings, "SAFE_LOCAL_SANDBOX_ENABLED", True)

    malicious_html = (
        "<html><head><title>Victim Page</title>"
        "<img src='http://169.254.169.254/latest/meta-data/'>"
        "</head><body><h1>Welcome</h1></body></html>"
    )

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"Content-Type": "text/html"}
    mock_resp.is_redirect = False
    mock_resp.content = malicious_html.encode("utf-8")

    controller = SandboxController()
    with patch("sandbox.target_validator.TargetValidator.validate_target", return_value=(True, None, ["93.184.216.34"])):
        with patch("httpx.AsyncClient.get", return_value=mock_resp):
            ev_list, fn_list, meta = await controller.inspect_target("https://subresource-tester.com")

    assert meta["completed"] is True
    sub_findings = [f for f in fn_list if f.finding_code == "FIND-NET-SUBRESOURCE-BLOCKED"]
    assert len(sub_findings) >= 1
    assert sub_findings[0].severity == Severity.HIGH
    assert "prohibited subresource" in sub_findings[0].description.lower()


@pytest.mark.asyncio
async def test_sandbox_controller_handles_worker_timeout(monkeypatch):
    """Verify that SandboxController handles worker timeouts cleanly without crashing."""
    monkeypatch.setattr(settings, "SAFE_LOCAL_SANDBOX_ENABLED", True)

    controller = SandboxController()
    with patch.object(controller.worker, "inspect", side_effect=EngineTimeoutException("Inspection timed out after 10s", engine_name="sandbox_worker", timeout_seconds=10)):
        ev_list, fn_list, meta = await controller.inspect_target("https://slow-responding-host.com")

    assert meta["completed"] is False
    assert meta["timeout"] is True
    assert "timed out" in meta["error"].lower()
    assert len(ev_list) == 0


@pytest.mark.asyncio
async def test_sandbox_controller_handles_worker_crash(monkeypatch):
    """Verify that SandboxController handles unexpected worker crashes without crashing backend."""
    monkeypatch.setattr(settings, "SAFE_LOCAL_SANDBOX_ENABLED", True)

    controller = SandboxController()
    with patch.object(controller.worker, "inspect", side_effect=RuntimeError("Chromium renderer died with SIGSEGV")):
        ev_list, fn_list, meta = await controller.inspect_target("https://crash-triggering-host.com")

    assert meta["completed"] is False
    assert meta["error"] == "Chromium renderer died with SIGSEGV"


@pytest.mark.asyncio
async def test_resource_limits_truncates_oversized_body():
    """Verify that response bodies exceeding max_body_bytes are truncated."""
    limits = ResourceLimits(max_body_bytes=500)
    worker = BrowserWorker(limits=limits)

    oversized_html = ("A" * 5000).encode("utf-8")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"Content-Type": "text/html"}
    mock_resp.is_redirect = False
    mock_resp.content = oversized_html

    with patch("sandbox.target_validator.TargetValidator.validate_target", return_value=(True, None, ["93.184.216.34"])):
        with patch("httpx.AsyncClient.get", return_value=mock_resp):
            data = await worker.inspect("https://oversized-payload.com")

    assert data["body_bytes_read"] == 500


