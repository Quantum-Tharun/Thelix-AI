"""
Gemini LLM Provider
Integrates Google GenAI SDK (google.genai) behind the pluggable LLMProvider interface.
Applies bounded timeouts, retries, and strict schema isolation.
"""
import asyncio
import re
import time
import logging
from typing import Optional

from llm.provider import LLMProvider
from llm.schemas import LLMResult

logger = logging.getLogger("thelix.gemini_provider")

# Try importing google.genai gracefully
try:
    from google import genai
    from google.genai import types
    GENAI_AVAILABLE = True
except ImportError:
    genai = None
    types = None
    GENAI_AVAILABLE = False


def _sanitize_error(msg: str) -> str:
    """Removes sensitive API keys, credentials, or query tokens from error strings."""
    sanitized = re.sub(r"AIza[0-9A-Za-z-_]{16,}", "[REDACTED_API_KEY]", str(msg))
    sanitized = re.sub(r"(key|token|secret|password)[=:\s]+([0-9A-Za-z-_]+)", r"\1=[REDACTED]", sanitized, flags=re.IGNORECASE)
    return sanitized


class GeminiProvider(LLMProvider):
    """
    Google Gemini LLM implementation using modern google.genai SDK.
    """
    provider_name = "gemini"

    def __init__(
        self,
        api_key: Optional[str] = None,
        model_name: str = "gemini-3.5-flash-lite",
        max_retries: int = 1,
    ):
        self.api_key = api_key or ""
        self.model_name = model_name
        self.max_retries = max_retries
        self._client = None

    def _get_client(self):
        if self._client is None and GENAI_AVAILABLE and self.api_key:
            self._client = genai.Client(api_key=self.api_key)
        return self._client

    async def generate_text(
        self,
        system_instruction: str,
        user_prompt: str,
        timeout_seconds: float = 20.0
    ) -> LLMResult:
        if not GENAI_AVAILABLE:
            return LLMResult(
                provider=self.provider_name,
                model=self.model_name,
                success=False,
                error="google-genai SDK is not installed in the current environment",
            )

        if not self.api_key:
            return LLMResult(
                provider=self.provider_name,
                model=self.model_name,
                success=False,
                error="GEMINI_API_KEY is not configured",
            )

        start_time = time.time()
        attempt = 0

        while attempt <= self.max_retries:
            attempt += 1
            try:
                client = self._get_client()
                config = types.GenerateContentConfig(
                    system_instruction=system_instruction,
                    temperature=0.2,
                    max_output_tokens=1024,
                )

                # Async call using client.aio with explicit timeout
                response = await asyncio.wait_for(
                    client.aio.models.generate_content(
                        model=self.model_name,
                        contents=user_prompt,
                        config=config,
                    ),
                    timeout=timeout_seconds,
                )

                latency = int((time.time() - start_time) * 1000)
                text = response.text.strip() if response and response.text else ""

                return LLMResult(
                    provider=self.provider_name,
                    model=self.model_name,
                    success=True,
                    content=text,
                    latency_ms=latency,
                )
            except asyncio.TimeoutError:
                sanitized_err = f"Gemini API request timed out after {timeout_seconds}s"
                logger.warning(f"Gemini API attempt {attempt} failed: {sanitized_err}")
                if attempt > self.max_retries:
                    latency = int((time.time() - start_time) * 1000)
                    return LLMResult(
                        provider=self.provider_name,
                        model=self.model_name,
                        success=False,
                        error=sanitized_err,
                        latency_ms=latency,
                    )
            except Exception as e:
                sanitized_err = _sanitize_error(str(e))
                logger.warning(f"Gemini API attempt {attempt} failed: {sanitized_err}")
                if attempt > self.max_retries:
                    latency = int((time.time() - start_time) * 1000)
                    return LLMResult(
                        provider=self.provider_name,
                        model=self.model_name,
                        success=False,
                        error=sanitized_err,
                        latency_ms=latency,
                    )

    async def aclose(self) -> None:
        """Cleanly releases underlying HTTP transport and SDK client sessions."""
        if self._client is not None:
            try:
                if hasattr(self._client, "aio") and hasattr(self._client.aio, "aclose"):
                    await self._client.aio.aclose()
                elif hasattr(self._client, "close"):
                    self._client.close()
            except Exception as e:
                logger.debug(f"Error closing Gemini async client: {e}")
            finally:
                self._client = None

    def close(self) -> None:
        """Synchronously closes underlying client resources."""
        if self._client is not None:
            try:
                if hasattr(self._client, "close"):
                    self._client.close()
            except Exception as e:
                logger.debug(f"Error closing Gemini client: {e}")
            finally:
                self._client = None

