"""
LLM Provider Interface
Defines the pluggable LLM provider contract.
Ensures provider independence so models (Gemini, Gemma, Mock) can be swapped seamlessly.
"""
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any

from llm.schemas import LLMResult


class LLMProvider(ABC):
    """
    Abstract interface for LLM operations.
    """
    provider_name: str = "generic"
    model_name: str = "default"

    @abstractmethod
    async def generate_text(
        self,
        system_instruction: str,
        user_prompt: str,
        timeout_seconds: float = 15.0
    ) -> LLMResult:
        """Generates text from the underlying model."""
        pass


class MockLLMProvider(LLMProvider):
    """
    Deterministic mock provider for unit testing and offline development.
    Guarantees that test suites run reliably without external API dependencies.
    Verdict-aware: adapts canned response based on trust_score/action in user_prompt.
    """
    provider_name = "mock_provider"
    model_name = "mock-model-v1"

    def __init__(self, canned_response: Optional[str] = None):
        self.canned_response = canned_response

    async def generate_text(
        self,
        system_instruction: str,
        user_prompt: str,
        timeout_seconds: float = 15.0
    ) -> LLMResult:
        import json as _json

        if self.canned_response:
            content = self.canned_response
        else:
            # Parse assessment context from user_prompt to generate a verdict-appropriate response
            trust_score = 50
            action = "warn"
            try:
                payload_start = user_prompt.find("{")
                if payload_start >= 0:
                    parsed = _json.loads(user_prompt[payload_start:])
                    trust_score = int(parsed.get("trust_score", 50))
                    action = str(parsed.get("action", "warn")).lower()
            except Exception:
                pass  # Fall through to default warning response

            if action in ("allow",) or trust_score >= 70:
                content = (
                    '{\n'
                    '  "headline": "No Threats Detected",\n'
                    f'  "plain_text_explanation": "All security checks completed without identifying known malware, phishing signatures, or suspicious indicators (Trust Score: {trust_score}/100). This destination appears safe.",\n'
                    '  "risk_factors": [],\n'
                    '  "user_guidance": "Safe to proceed. Always verify HTTPS is active when entering credentials."\n'
                    '}'
                )
            elif action in ("block",) or trust_score < 30:
                content = (
                    '{\n'
                    '  "headline": "High-Risk Content Blocked",\n'
                    f'  "plain_text_explanation": "Multiple suspicious security indicators were detected. Our risk engine flagged this destination as high-risk (Trust Score: {trust_score}/100). Do not proceed.",\n'
                    '  "risk_factors": ["Suspicious domain or URL structure", "Multiple risk flags triggered"],\n'
                    '  "user_guidance": "Do not open the link, do not enter any credentials, and delete the message immediately."\n'
                    '}'
                )
            else:
                content = (
                    '{\n'
                    '  "headline": "Suspicious Content: Proceed with Caution",\n'
                    f'  "plain_text_explanation": "This destination exhibited unusual characteristics (Trust Score: {trust_score}/100). While not confirmed malware, it matches patterns used in phishing and social engineering.",\n'
                    '  "risk_factors": ["Unusual domain structure", "Unverified trust signals"],\n'
                    '  "user_guidance": "Verify the sender before proceeding. Never share financial credentials or passwords."\n'
                    '}'
                )

        return LLMResult(
            provider=self.provider_name,
            model=self.model_name,
            success=True,
            content=content,
            latency_ms=15,
        )
