"""
Sandbox Target Validator
Validates target URLs before dispatching to isolated inspection environments.
Checks scheme, port, DNS resolution, and destination IP policy.
"""
from typing import Tuple, Optional, List
from urllib.parse import urlsplit

from sandbox.network_policy import NetworkPolicy, PERMITTED_PORTS
from risk_engine.exceptions import TargetProhibitedException, UnsupportedSchemeException, MalformedURLException


class TargetValidator:
    """
    Validates that a URL is legally inspectable under security boundaries.
    """

    @classmethod
    def validate_target(cls, url: str) -> Tuple[bool, Optional[str], List[str]]:
        """
        Validates target URL before opening network sockets.
        Returns (is_valid, error_reason, resolved_ips).
        """
        try:
            parsed = urlsplit(url)
        except Exception as e:
            return False, f"Malformed URL: {str(e)}", []

        scheme = parsed.scheme.lower() if parsed.scheme else ""
        if scheme not in {"http", "https"}:
            return False, f"Scheme '{scheme}' is prohibited. Only HTTP and HTTPS are permitted for sandbox inspection.", []

        host = parsed.hostname
        if not host:
            return False, "Target URL missing valid hostname", []

        # Port validation
        port = parsed.port
        if port is not None and port not in PERMITTED_PORTS:
            return False, f"Port {port} is not in permitted inspection ports {sorted(list(PERMITTED_PORTS))}", []

        # DNS resolution and IP policy check
        allowed, resolved_ips, reason = NetworkPolicy.validate_resolved_ips(host)
        if not allowed:
            return False, reason, resolved_ips

        return True, None, resolved_ips
