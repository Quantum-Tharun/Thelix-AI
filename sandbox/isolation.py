"""
Sandbox Isolation and Hardening Layer
Enforces operating-system-level process environment scrubbing, disposable browser profiles,
and subresource SSRF request inspection.
"""
import os
import shutil
import tempfile
import logging
from typing import Dict, Optional, Tuple, Set
from urllib.parse import urlsplit

from sandbox.network_policy import NetworkPolicy, PERMITTED_PORTS
from sandbox.target_validator import TargetValidator

logger = logging.getLogger("thelix.sandbox_isolation")


class EnvironmentScrubber:
    """
    Scrubs process environment variables to prevent application secrets, API keys,
    and database credentials from leaking to child browser/worker processes.
    """
    # Safe system-level environment variables strictly required for process execution
    SAFE_SYSTEM_VARS: Set[str] = {
        # Windows
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "COMMONPROGRAMFILES",
        "COMMONPROGRAMFILES(X86)",
        # POSIX
        "PATH",
        "HOME",
        "USER",
        "SHELL",
        "TMPDIR",
        "LANG",
        "LC_ALL",
    }

    # Sensitive keywords that must NEVER exist in child process environments
    SENSITIVE_PATTERNS = {
        "KEY",
        "SECRET",
        "TOKEN",
        "PASSWORD",
        "PASSWD",
        "DATABASE",
        "DB_",
        "SUPABASE",
        "GEMINI",
        "VIRUSTOTAL",
        "AUTH",
        "CREDENTIAL",
    }

    @classmethod
    def get_scrubbed_env(cls) -> Dict[str, str]:
        """
        Builds a minimal, sanitized environment dictionary for child browser processes.
        Explicitly removes all application-level secrets.
        """
        scrubbed: Dict[str, str] = {}
        for k, v in os.environ.items():
            k_upper = k.upper()
            # Must match system whitelist
            if k_upper in cls.SAFE_SYSTEM_VARS or k_upper == "PATH":
                # Must NOT contain any sensitive credential pattern
                if not any(pattern in k_upper for pattern in cls.SENSITIVE_PATTERNS):
                    scrubbed[k] = v
                else:
                    logger.warning(f"Redacted sensitive environment variable from child worker: {k}")
        return scrubbed


class EphemeralProfileManager:
    """
    Context manager that allocates an isolated temporary directory for browser state
    and guarantees complete deletion upon worker termination or failure.
    """
    def __init__(self, prefix: str = "thelix_sandbox_profile_"):
        self.prefix = prefix
        self.temp_dir: Optional[str] = None

    def __enter__(self) -> str:
        self.temp_dir = tempfile.mkdtemp(prefix=self.prefix)
        logger.debug(f"Allocated disposable sandbox profile directory: {self.temp_dir}")
        return self.temp_dir

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir, ignore_errors=True)
                logger.debug(f"Cleaned up disposable sandbox profile directory: {self.temp_dir}")
            except Exception as e:
                logger.warning(f"Failed to cleanly delete disposable profile {self.temp_dir}: {e}")


class SubresourceInterceptor:
    """
    Inspects subresource requests (scripts, images, stylesheets, fetch/XHR, iframes)
    triggered by inspected webpages to prevent SSRF against internal infrastructure.
    """
    ALLOWED_SCHEMES: Set[str] = {"http", "https", "data", "blob", "about"}

    @classmethod
    def validate_subresource(cls, subresource_url: str) -> Tuple[bool, Optional[str]]:
        """
        Validates if a subresource request is safe to fetch or must be blocked.
        Returns (is_allowed, denial_reason).
        """
        if not subresource_url or not isinstance(subresource_url, str):
            return False, "Empty or invalid subresource URL"

        clean_url = subresource_url.strip()

        # Data and blob URLs are client-memory only (safe from network SSRF)
        if clean_url.startswith("data:") or clean_url.startswith("blob:") or clean_url.startswith("about:"):
            return True, None

        try:
            parsed = urlsplit(clean_url)
        except Exception as e:
            return False, f"Malformed subresource URL: {str(e)}"

        scheme = (parsed.scheme or "").lower()
        if scheme not in cls.ALLOWED_SCHEMES:
            return False, f"Prohibited subresource scheme '{scheme}'"

        host = parsed.hostname
        if not host:
            return False, "Subresource URL missing valid hostname"

        # Check port
        port = parsed.port
        if port is not None and port not in PERMITTED_PORTS:
            return False, f"Subresource port {port} is prohibited"

        # Validate destination IP address against SSRF rules
        allowed, resolved_ips, reason = NetworkPolicy.validate_resolved_ips(host)
        if not allowed:
            return False, f"Prohibited subresource destination (SSRF defense): {reason}"

        return True, None
