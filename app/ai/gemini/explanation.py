import asyncio
import re
import logging
from app.config import settings

logger = logging.getLogger("thelix.gemini")

try:
    from google import genai
    from google.genai import types
    GENAI_AVAILABLE = True
except ImportError:
    genai = None
    types = None
    GENAI_AVAILABLE = False


def _sanitize_error(msg: str) -> str:
    """Removes sensitive API keys or credentials from error strings."""
    sanitized = re.sub(r"AIza[0-9A-Za-z-_]{16,}", "[REDACTED_API_KEY]", str(msg))
    sanitized = re.sub(r"(key|token|secret|password)[=:\s]+([0-9A-Za-z-_]+)", r"\1=[REDACTED]", sanitized, flags=re.IGNORECASE)
    return sanitized


class GeminiExplanationService:
    """
    Online LLM for generating human-readable explanations of the Risk Engine's output.
    Uses modern Google GenAI SDK (google.genai).
    """
    _client = None

    @classmethod
    def _get_client(cls):
        if cls._client is None and GENAI_AVAILABLE and settings.GEMINI_API_KEY:
            cls._client = genai.Client(api_key=settings.GEMINI_API_KEY)
        return cls._client

    @classmethod
    async def generate_explanation(cls, trust_score: int, reasons: list[str], timeout_seconds: float = 15.0) -> str:
        """
        Generates a 1-2 sentence explanation.
        """
        if not settings.GEMINI_API_KEY or not GENAI_AVAILABLE:
            logger.warning("Gemini API key missing or google.genai SDK unavailable. Falling back to static explanation.")
            return cls._static_fallback(trust_score, reasons)

        try:
            client = cls._get_client()
            prompt = (
                f"You are a cybersecurity assistant. A risk engine computed a trust score of {trust_score}/100 "
                f"based on these threat reasons: {', '.join(reasons)}. "
                f"Explain to the user in 1-2 simple sentences why this is dangerous (if score < 50) or safe (if score > 80). "
                f"Be direct, plain-spoken, and do not use technical jargon."
            )
            config = types.GenerateContentConfig(
                temperature=0.2,
                max_output_tokens=256,
            )
            response = await asyncio.wait_for(
                client.aio.models.generate_content(
                    model=getattr(settings, "GEMINI_MODEL", "gemini-3.5-flash-lite") or "gemini-3.5-flash-lite",
                    contents=prompt,
                    config=config,
                ),
                timeout=timeout_seconds,
            )
            return response.text.strip() if response and response.text else GeminiExplanationService._static_fallback(trust_score, reasons)
        except asyncio.TimeoutError:
            logger.warning(f"Gemini explanation generation timed out after {timeout_seconds}s. Falling back to static.")
            return GeminiExplanationService._static_fallback(trust_score, reasons)
        except Exception as e:
            logger.error(f"Gemini generation failed: {_sanitize_error(str(e))}")
            return GeminiExplanationService._static_fallback(trust_score, reasons)

    @staticmethod
    def _static_fallback(trust_score: int, reasons: list[str]) -> str:
        if trust_score < 50:
            return f"We strongly advise against this action. We found multiple risk factors including '{reasons[0] if reasons else 'unknown threats'}'."
        return "No significant threats were detected. It appears safe to proceed."

    @classmethod
    async def aclose(cls) -> None:
        """Cleanly releases cached client resources."""
        if cls._client is not None:
            try:
                if hasattr(cls._client, "aio") and hasattr(cls._client.aio, "aclose"):
                    await cls._client.aio.aclose()
                elif hasattr(cls._client, "close"):
                    cls._client.close()
            except Exception as e:
                logger.debug(f"Error closing Gemini explanation service client: {e}")
            finally:
                cls._client = None

    @classmethod
    def reset_client(cls) -> None:
        """Resets cached client instance for testing and lifecycle isolation."""
        cls._client = None

