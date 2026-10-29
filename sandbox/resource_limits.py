"""
Sandbox Resource Limits
Configures resource thresholds, execution timeouts, and inspection bounds.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class ResourceLimits:
    """
    Limits applied to sandbox inspection tasks.
    """
    timeout_seconds: float = 10.0
    max_redirect_hops: int = 5
    max_body_bytes: int = 5 * 1024 * 1024  # 5 MB
    max_network_requests: int = 30
    viewport_width: int = 1280
    viewport_height: int = 800
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36 ThelixSecurityScanner/1.0"
    )
