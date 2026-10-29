"""
Sandbox Security and Isolation Tests
Tests SSRF defenses, IP classification, cloud metadata protection, and redirect validation.
"""
import pytest
from sandbox.network_policy import NetworkPolicy
from sandbox.target_validator import TargetValidator
from sandbox.redirect_validator import RedirectValidator
from sandbox.controller import SandboxController
from risk_engine.evidence import ActionVerdict, Severity


def test_network_policy_blocks_localhost():
    allowed, reason = NetworkPolicy.is_ip_allowed("127.0.0.1")
    assert not allowed
    assert "loopback" in reason.lower()

    allowed6, reason6 = NetworkPolicy.is_ip_allowed("::1")
    assert not allowed6
    assert "loopback" in reason6.lower()


def test_network_policy_blocks_rfc1918_private_ips():
    private_ips = ["10.0.0.1", "172.16.0.5", "192.168.1.100", "192.168.0.1"]
    for ip in private_ips:
        allowed, reason = NetworkPolicy.is_ip_allowed(ip)
        assert not allowed
        assert "private" in reason.lower()


def test_network_policy_blocks_cloud_metadata():
    metadata_ips = ["169.254.169.254", "fd00:ec2::254", "100.100.100.200"]
    for ip in metadata_ips:
        allowed, reason = NetworkPolicy.is_ip_allowed(ip)
        assert not allowed
        assert "metadata" in reason.lower() or "link-local" in reason.lower() or "prohibited" in reason.lower()


def test_network_policy_blocks_link_local():
    allowed, reason = NetworkPolicy.is_ip_allowed("169.254.1.1")
    assert not allowed
    assert "link-local" in reason.lower()


def test_network_policy_blocks_ipv4_mapped_ipv6():
    # ::ffff:127.0.0.1 (IPv4 mapped loopback)
    allowed, reason = NetworkPolicy.is_ip_allowed("::ffff:127.0.0.1")
    assert not allowed
    assert "loopback" in reason.lower()


def test_target_validator_blocks_internal_hosts():
    for bad_url in [
        "http://localhost:8080",
        "http://127.0.0.1:8000/api",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
    ]:
        valid, reason, _ = TargetValidator.validate_target(bad_url)
        assert not valid
        assert reason is not None


def test_redirect_validator_blocks_pivoting_to_prohibited_targets():
    # Attempting to redirect from external domain to localhost
    is_allowed, resolved_url, err = RedirectValidator.validate_redirect(
        current_url="https://external-example.com/login",
        redirect_target="http://127.0.0.1:8000/admin",
        hop_count=1,
    )
    assert not is_allowed
    assert "blocked" in err.lower() or "loopback" in err.lower()


def test_redirect_validator_enforces_hop_limit():
    is_allowed, _, err = RedirectValidator.validate_redirect(
        current_url="https://external-example.com/step1",
        redirect_target="/step2",
        hop_count=5,  # Exceeds limit of 5
    )
    assert not is_allowed
    assert "exceeded" in err.lower()


@pytest.mark.asyncio
async def test_sandbox_controller_blocks_ssrf_without_crashing():
    controller = SandboxController()
    ev, fn, meta = await controller.inspect_target("http://169.254.169.254/latest/meta-data/")

    assert meta["blocked"] is True
    assert meta["completed"] is False
    assert len(fn) > 0
    assert fn[0].severity == Severity.CRITICAL
    assert fn[0].finding_code == "FIND-NET-TARGET-PROHIBITED"



@pytest.mark.asyncio
async def test_sandbox_fail_closed_when_disabled(monkeypatch):
    """Verify that when SAFE_LOCAL_SANDBOX_ENABLED is False, live inspection fails closed cleanly."""
    from app.config import settings
    monkeypatch.setattr(settings, "SAFE_LOCAL_SANDBOX_ENABLED", False)

    controller = SandboxController()
    ev, fn, meta = await controller.inspect_target("https://example.com")

    assert meta["disabled_by_policy"] is True
    assert meta["completed"] is False
    assert "disabled" in meta["error"].lower()
    assert len(ev) == 0
    assert len(fn) == 0


def test_dns_validation_blocks_internal_cloud_hostnames():
    """Verify that hostnames pointing to cloud metadata or internal domains are blocked before network socket creation."""
    for host in ["metadata.google.internal", "instance-data", "corp.internal"]:
        allowed, ips, reason = NetworkPolicy.validate_resolved_ips(host)
        assert not allowed
        assert "internal" in reason.lower() or "failed" in reason.lower()

