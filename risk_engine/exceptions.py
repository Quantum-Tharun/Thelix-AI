"""
Risk Engine Exceptions
Typed exceptions for input validation, URL normalization, reputation, and policy decisions.
"""

class RiskEngineException(Exception):
    """Base exception for all Risk Engine operations."""
    def __init__(self, message: str, code: str = "ENGINE_ERROR", details: dict = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = details or {}


class ValidationError(RiskEngineException):
    """Raised when scan input fails structural or security validation."""
    def __init__(self, message: str, code: str = "VALIDATION_ERROR", details: dict = None):
        super().__init__(message, code=code, details=details)


class MalformedURLException(ValidationError):
    """Raised when a URL is syntactically malformed or unparseable."""
    def __init__(self, message: str, details: dict = None):
        super().__init__(message, code="MALFORMED_URL", details=details)


class UnsupportedSchemeException(ValidationError):
    """Raised when a URL uses an unsupported or prohibited protocol."""
    def __init__(self, message: str, details: dict = None):
        super().__init__(message, code="UNSUPPORTED_SCHEME", details=details)


class TargetProhibitedException(RiskEngineException):
    """Raised when a destination violates network or safety policy (e.g. loopback, RFC1918, cloud metadata)."""
    def __init__(self, message: str, details: dict = None):
        super().__init__(message, code="TARGET_PROHIBITED", details=details)


class ProviderUnavailableException(RiskEngineException):
    """Raised when an external threat intel or reputation provider fails or times out."""
    def __init__(self, message: str, provider_name: str, details: dict = None):
        details = details or {}
        details["provider"] = provider_name
        super().__init__(message, code="PROVIDER_UNAVAILABLE", details=details)


class EngineTimeoutException(RiskEngineException):
    """Raised when an engine task exceeds its allotted timeout."""
    def __init__(self, message: str, engine_name: str, timeout_seconds: float):
        super().__init__(
            message,
            code="ENGINE_TIMEOUT",
            details={"engine": engine_name, "timeout_seconds": timeout_seconds}
        )


class PolicyViolationException(RiskEngineException):
    """Raised when an operation violates active risk engine policy."""
    def __init__(self, message: str, policy_rule: str, details: dict = None):
        details = details or {}
        details["policy_rule"] = policy_rule
        super().__init__(message, code="POLICY_VIOLATION", details=details)
