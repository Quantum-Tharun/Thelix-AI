"""
Sandbox Redirect Validator
Validates redirect hops during dynamic web inspection.
Guarantees that redirects do not pivot into internal networks or exceed hop limits.
"""
from typing import Tuple, Optional, List
from urllib.parse import urljoin, urlsplit

from sandbox.target_validator import TargetValidator

MAX_REDIRECT_HOPS = 5


class RedirectValidator:
    """
    Validates redirect targets in real time.
    """

    @classmethod
    def validate_redirect(
        cls,
        current_url: str,
        redirect_target: str,
        hop_count: int
    ) -> Tuple[bool, str, Optional[str]]:
        """
        Validates redirect destination.
        Returns (is_allowed, resolved_target_url, error_reason).
        """
        if hop_count >= MAX_REDIRECT_HOPS:
            return False, redirect_target, f"Redirect chain exceeded limit of {MAX_REDIRECT_HOPS} hops"

        # Resolve relative redirects
        resolved_url = urljoin(current_url, redirect_target)

        # Re-validate the new destination against complete TargetValidator
        is_valid, reason, _ = TargetValidator.validate_target(resolved_url)
        if not is_valid:
            return False, resolved_url, f"Redirect to '{resolved_url}' blocked by security policy: {reason}"

        return True, resolved_url, None
