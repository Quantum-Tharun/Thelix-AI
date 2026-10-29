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
        if self.canned_response:
            content = self.canned_response
        else:
            content = (
                '{\n'
                '  "headline": "Suspicious Website Detected",\n'
                '  "plain_text_explanation": "This link contains indicators of phishing designed to mimic a trusted service. Do not enter personal credentials.",\n'
                '  "risk_factors": ["Lookalike domain structure", "Non-standard port assignment"],\n'
                '  "user_guidance": "Delete the message and avoid opening the link."\n'
                '}'
            )

        return LLMResult(
            provider=self.provider_name,
            model=self.model_name,
            success=True,
            content=content,
            latency_ms=15,
        )
