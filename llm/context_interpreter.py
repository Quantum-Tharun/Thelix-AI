"""
Context Interpreter
Uses LLM to interpret user submission context, extract candidate indicators, and classify user intent.
Provides a deterministic regex fallback if the LLM is unavailable.
"""
import re
from typing import Optional

from llm.provider import LLMProvider
from llm.schemas import ContextInterpretation
from llm.output_validator import OutputValidator


class ContextInterpreter:
    """
    Extracts semantic intent and candidate security indicators from user-provided context.
    """

    SYSTEM_INSTRUCTION = (
        "You are an AI cybersecurity context analyzer for Thelix AI. "
        "Analyze the user's submission context and output ONLY valid JSON matching this schema:\n"
        "{\n"
        '  "user_intent": "string",\n'
        '  "extracted_indicators": ["url or domain"],\n'
        '  "candidate_risk_categories": ["phishing", "malware", "scam", "impersonation", "unknown"],\n'
        '  "context_summary": "string"\n'
        "}\n"
        "Do not include any other text or markdown formatting."
    )

    def __init__(self, provider: LLMProvider):
        self.provider = provider

    async def interpret(self, raw_context: str) -> ContextInterpretation:
        """
        Interprets unstructured text and returns structured ContextInterpretation.
        """
        if not raw_context or not raw_context.strip():
            return ContextInterpretation(
                user_intent="Direct URL scan",
                extracted_indicators=[],
                candidate_risk_categories=["unknown"],
                context_summary="No additional context provided",
            )

        prompt = f"User submitted context:\n'''{raw_context[:1000]}'''"
        res = await self.provider.generate_text(
            system_instruction=self.SYSTEM_INSTRUCTION,
            user_prompt=prompt,
            timeout_seconds=10.0,
        )

        if res.success and res.content:
            parsed = OutputValidator.parse_and_validate(res.content, ContextInterpretation)
            if parsed:
                return parsed

        # Deterministic regex fallback
        return self._heuristic_fallback(raw_context)

    @staticmethod
    def _heuristic_fallback(text: str) -> ContextInterpretation:
        """Extracts candidate URLs and intent via deterministic rules."""
        urls = re.findall(r"https?://[^\s<>\"']+", text)
        categories = []
        lower = text.lower()
        if "bank" in lower or "account" in lower or "verify" in lower:
            categories.append("phishing")
        if "crypto" in lower or "gift card" in lower or "winner" in lower:
            categories.append("scam")
        if not categories:
            categories.append("unknown")

        return ContextInterpretation(
            user_intent="Evaluate suspicious digital message or link",
            extracted_indicators=urls,
            candidate_risk_categories=categories,
            context_summary=text[:200].strip(),
        )
