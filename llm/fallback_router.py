"""
LLM Provider Fallback Router
Sequences LLM provider calls according to online/offline policy:
Primary (Gemini) -> Fallback (Ollama Gemma) -> Deterministic Rule/Mock.
Ensures zero data leaks, structured error logs, and strict failure isolation.
"""
import logging
from typing import Optional, List, Dict, Any

from llm.provider import LLMProvider, MockLLMProvider
from llm.gemini_provider import GeminiProvider
from llm.ollama_provider import OllamaGemmaProvider
from llm.schemas import LLMResult
from app.config import settings

logger = logging.getLogger("thelix.llm_router")


class FallbackLLMRouter(LLMProvider):
    """
    Unified LLM router with automatic failover between online and offline providers.
    Policy:
    1. If online provider requested & configured (Gemini), attempt Gemini.
    2. On failure or if offline/unconfigured, attempt local Ollama Gemma if available.
    3. If all fail or unconfigured, fall back gracefully to deterministic Mock provider.
    """
    provider_name = "fallback_router"

    def __init__(
        self,
        primary_provider: Optional[LLMProvider] = None,
        secondary_provider: Optional[LLMProvider] = None,
        mock_fallback: Optional[LLMProvider] = None,
    ):
        self.primary = primary_provider
        self.secondary = secondary_provider
        self.mock = mock_fallback or MockLLMProvider()
        self.last_provider_used: Optional[str] = None
        self.model_name = "dynamic"

    @classmethod
    def from_settings(cls) -> "FallbackLLMRouter":
        """Instantiates router from application settings."""
        primary = None
        if settings.GEMINI_API_KEY:
            primary = GeminiProvider(
                api_key=settings.GEMINI_API_KEY,
                model_name=settings.GEMINI_MODEL,
                max_retries=settings.LLM_MAX_RETRIES,
            )

        secondary = OllamaGemmaProvider(
            base_url=settings.OLLAMA_BASE_URL,
            model_name=settings.GEMMA_MODEL_VERSION,
            timeout_seconds=settings.LLM_TIMEOUT_SECONDS,
        )

        return cls(primary_provider=primary, secondary_provider=secondary)

    def get_provider_status(self) -> Dict[str, Any]:
        """Returns real-time status of all configured providers."""
        gemini_ready = bool(settings.GEMINI_API_KEY)
        ollama_status = {"reachable": False, "status": "unconfigured"}
        if self.secondary and isinstance(self.secondary, OllamaGemmaProvider):
            ollama_status = self.secondary.check_availability()

        return {
            "gemini": {
                "configured": gemini_ready,
                "model": settings.GEMINI_MODEL,
                "status": "ready" if gemini_ready else "unconfigured_key",
            },
            "ollama_gemma": {
                "configured": True,
                "base_url": settings.OLLAMA_BASE_URL,
                "model": settings.GEMMA_MODEL_VERSION,
                "status": ollama_status.get("status", "unreachable"),
                "reachable": ollama_status.get("reachable", False),
            },
            "deterministic_fallback": {
                "configured": True,
                "status": "always_available",
            },
            "active_preference": settings.LLM_PROVIDER,
        }

    async def generate_text(
        self,
        system_instruction: str,
        user_prompt: str,
        timeout_seconds: float = 15.0,
    ) -> LLMResult:
        """
        Executes bounded generate_text with sequential fallback.
        """
        # Step 1: Try Primary (Gemini) if configured and preference is gemini
        if self.primary and settings.LLM_PROVIDER == "gemini":
            try:
                res = await self.primary.generate_text(
                    system_instruction=system_instruction,
                    user_prompt=user_prompt,
                    timeout_seconds=timeout_seconds,
                )
                if res.success:
                    self.last_provider_used = self.primary.provider_name
                    return res
                logger.warning(f"Primary LLM ({self.primary.provider_name}) failed: {res.error}. Falling back.")
            except Exception as e:
                logger.warning(f"Primary LLM raised unexpected exception: {e}. Falling back.")

        # Step 2: Try Secondary (Ollama Gemma)
        if self.secondary:
            try:
                res = await self.secondary.generate_text(
                    system_instruction=system_instruction,
                    user_prompt=user_prompt,
                    timeout_seconds=timeout_seconds,
                )
                if res.success:
                    self.last_provider_used = self.secondary.provider_name
                    return res
                logger.debug(f"Secondary LLM ({self.secondary.provider_name}) failed: {res.error}.")
            except Exception as e:
                logger.debug(f"Secondary LLM raised exception: {e}.")

        # Step 3: Guaranteed Deterministic Mock Fallback
        self.last_provider_used = self.mock.provider_name
        return await self.mock.generate_text(
            system_instruction=system_instruction,
            user_prompt=user_prompt,
            timeout_seconds=timeout_seconds,
        )
