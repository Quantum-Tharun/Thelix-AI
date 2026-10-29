"""
LLM Output Validator & Prompt Injection Guardrails
Validates that model outputs conform strictly to Pydantic schemas.
Sanitizes raw text and enforces that LLMs never override deterministic verdicts.
"""
import json
import re
from typing import Dict, Any, Optional, Type, TypeVar
from pydantic import BaseModel, ValidationError

T = TypeVar("T", bound=BaseModel)

# Regex to detect prompt injection residues or dangerous tags
INJECTION_TAGS_PATTERN = re.compile(r"<\s*script[^>]*>|<\s*/\s*script\s*>|javascript:", re.IGNORECASE)
SYSTEM_OVERRIDE_PATTERNS = re.compile(
    r"(ignore\s+(all\s+)?previous\s+instructions|system\s+prompt|override\s+policy|declare\s+safe)",
    re.IGNORECASE
)


class OutputValidator:
    """
    Validates and sanitizes untrusted LLM outputs.
    """

    @classmethod
    def parse_and_validate(cls, raw_content: str, schema_class: Type[T]) -> Optional[T]:
        """
        Extracts JSON from model output and validates it against the Pydantic schema.
        Returns parsed model or None if invalid.
        """
        if not raw_content:
            return None

        # Sanitize against script tags
        sanitized = INJECTION_TAGS_PATTERN.sub("", raw_content)

        # Attempt to parse json from raw content (or markdown-wrapped json)
        json_str = cls._extract_json_block(sanitized)
        if not json_str:
            return None

        try:
            data = json.loads(json_str)
            return schema_class.model_validate(data)
        except (json.JSONDecodeError, ValidationError):
            return None

    @classmethod
    def sanitize_explanation_text(cls, text: str) -> str:
        """
        Cleans plain text explanation, removing unwanted HTML/script patterns.
        """
        if not text:
            return ""
        clean = INJECTION_TAGS_PATTERN.sub("", text)
        clean = SYSTEM_OVERRIDE_PATTERNS.sub("[redacted-phrase]", clean)
        return clean.strip()

    @staticmethod
    def _extract_json_block(text: str) -> Optional[str]:
        text = text.strip()
        # Direct JSON object
        if text.startswith("{") and text.endswith("}"):
            return text

        # Markdown ```json ... ``` wrapper
        match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if match:
            return match.group(1).strip()

        # Brute-force locate outermost braces
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            return text[start : end + 1].strip()

        return None
