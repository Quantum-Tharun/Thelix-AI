"""
Input Validator
Strict validation for submitted URLs and scan requests.
Enforces protocol, hostname, character encoding, length limits, and security constraints.
"""
import re
from urllib.parse import urlsplit, unquote
from typing import Dict, Any, Optional

from risk_engine.exceptions import (
    ValidationError,
    MalformedURLException,
    UnsupportedSchemeException,
)

# Supported protocols
ALLOWED_SCHEMES = {"http", "https"}

# Length constraints
MAX_URL_LENGTH = 4096
MAX_HOST_LENGTH = 253
MAX_PATH_LENGTH = 2048

# Regex patterns
IPV4_REGEX = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
CONTROL_CHARS_REGEX = re.compile(r"[\x00-\x1f\x7f-\x9f]")


class InputValidator:
    """
    Validates submitted URLs before any normalization, inspection, or processing.
    """

    @classmethod
    def validate_url(cls, raw_url: Any) -> Dict[str, Any]:
        """
        Validates URL string against structural and security constraints.
        Returns a dict with basic parsed parts or raises a ValidationError.
        """
        if not isinstance(raw_url, str):
            raise ValidationError(
                f"URL must be a string, got {type(raw_url).__name__}",
                code="INVALID_TYPE",
                details={"provided_type": type(raw_url).__name__}
            )

        trimmed = raw_url.strip()
        if not trimmed:
            raise ValidationError("URL cannot be empty or whitespace only", code="EMPTY_INPUT")

        if len(trimmed) > MAX_URL_LENGTH:
            raise ValidationError(
                f"URL length ({len(trimmed)}) exceeds maximum allowed ({MAX_URL_LENGTH})",
                code="EXCESSIVE_LENGTH",
                details={"length": len(trimmed), "max_length": MAX_URL_LENGTH}
            )

        # Check for raw null bytes and unprintable control characters
        if "\x00" in trimmed or "%00" in trimmed.lower():
            raise MalformedURLException("URL contains forbidden null byte characters", details={"url": trimmed[:100]})

        if CONTROL_CHARS_REGEX.search(trimmed):
            raise MalformedURLException("URL contains invalid control characters", details={"url": trimmed[:100]})

        # Parse with urlsplit
        try:
            parsed = urlsplit(trimmed)
        except ValueError as e:
            raise MalformedURLException(f"Failed to parse URL: {str(e)}", details={"error": str(e)})

        # Validate scheme
        scheme = parsed.scheme.lower() if parsed.scheme else ""
        if not scheme:
            raise UnsupportedSchemeException(
                "URL missing protocol scheme (must be http:// or https://)",
                details={"raw_url": trimmed[:100]}
            )

        if scheme not in ALLOWED_SCHEMES:
            raise UnsupportedSchemeException(
                f"Protocol scheme '{scheme}' is not permitted. Only HTTP and HTTPS are supported.",
                details={"scheme": scheme}
            )

        # Validate hostname presence
        hostname = parsed.hostname
        if not hostname:
            raise MalformedURLException("URL must contain a valid hostname", details={"raw_url": trimmed[:100]})

        if len(hostname) > MAX_HOST_LENGTH:
            raise MalformedURLException(
                f"Hostname exceeds maximum length of {MAX_HOST_LENGTH} characters",
                details={"hostname_length": len(hostname)}
            )

        # Validate port if specified
        port = None
        if parsed.port is not None:
            if not (1 <= parsed.port <= 65535):
                raise MalformedURLException(f"Invalid port number: {parsed.port}", details={"port": parsed.port})
            port = parsed.port

        # Check path length
        if len(parsed.path) > MAX_PATH_LENGTH:
            raise MalformedURLException(
                f"URL path exceeds maximum length of {MAX_PATH_LENGTH}",
                details={"path_length": len(parsed.path)}
            )

        return {
            "raw_url": trimmed,
            "scheme": scheme,
            "netloc": parsed.netloc,
            "hostname": hostname,
            "port": port,
            "path": parsed.path or "/",
            "query": parsed.query,
            "fragment": parsed.fragment,
            "username": parsed.username,
            "password": parsed.password,
        }
