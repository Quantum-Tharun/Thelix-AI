"""
Explanation Generator
Generates clear, human-readable explanations of deterministic findings.
Never scores the target or overrides risk engine verdicts.
"""
from typing import List, Optional
import json

from llm.provider import LLMProvider
from llm.schemas import ExplanationOutput
from llm.output_validator import OutputValidator
from risk_engine.evidence import Finding, ActionVerdict, RiskLevel


class ExplanationGenerator:
    """
    Translates technical security findings into concise, accessible guidance for end users.
    """

    SYSTEM_INSTRUCTION = (
        "You are an assistant for Thelix AI cybersecurity platform. "
        "Your sole task is to explain verified security findings to a regular user. "
        "CRITICAL RULES:\n"
        "1. You DO NOT compute scores or determine if a link is safe. The Risk Engine has already calculated this.\n"
        "2. Do not invent facts, certificates, DNS data, or external reputation.\n"
        "3. Output ONLY a valid JSON object matching this schema:\n"
        "{\n"
        '  "headline": "One-sentence headline summarizing verdict",\n'
        '  "plain_text_explanation": "2-3 plain language sentences explaining why this is dangerous or safe",\n'
        '  "risk_factors": ["simple bullet point", "simple bullet point"],\n'
        '  "user_guidance": "Direct advice for the user"\n'
        "}\n"
        "Do not include any other text."
    )

    def __init__(self, provider: LLMProvider):
        self.provider = provider

    async def generate_explanation(
        self,
        risk_score: int,
        trust_score: int,
        risk_level: RiskLevel,
        action: ActionVerdict,
        findings: List[Finding],
    ) -> ExplanationOutput:
        """
        Calls LLM to generate an explanation or falls back to static deterministic templating.
        """
        finding_summaries = [f"{f.title}: {f.description}" for f in findings]

        prompt_payload = {
            "trust_score": trust_score,
            "risk_score": risk_score,
            "risk_level": risk_level.value,
            "action": action.value,
            "verified_findings": finding_summaries,
        }

        user_prompt = f"Assessment findings:\n{json.dumps(prompt_payload, indent=2)}"

        res = await self.provider.generate_text(
            system_instruction=self.SYSTEM_INSTRUCTION,
            user_prompt=user_prompt,
            timeout_seconds=12.0,
        )

        if res.success and res.content:
            parsed = OutputValidator.parse_and_validate(res.content, ExplanationOutput)
            if parsed:
                return parsed

        # Static deterministic fallback
        return self._static_fallback(trust_score, risk_level, action, findings)

    @staticmethod
    def _static_fallback(
        trust_score: int,
        risk_level: RiskLevel,
        action: ActionVerdict,
        findings: List[Finding]
    ) -> ExplanationOutput:
        """Deterministic template when LLM is unavailable or unconfigured."""
        if action == ActionVerdict.BLOCK or risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            factor_list = [f.title for f in findings[:3]] or ["Multiple suspicious indicators detected"]
            return ExplanationOutput(
                headline="High-Risk Website: Access Blocked",
                plain_text_explanation=(
                    f"We strongly advise against opening this destination. "
                    f"Our security checks verified severe risk factors with a trust score of only {trust_score}/100."
                ),
                risk_factors=factor_list,
                user_guidance="Do not open the link, do not enter passwords, and delete the message immediately.",
            )
        elif action == ActionVerdict.WARN or risk_level == RiskLevel.MEDIUM:
            factor_list = [f.title for f in findings[:3]] or ["Unusual domain or redirect structure"]
            return ExplanationOutput(
                headline="Suspicious Website: Proceed with Caution",
                plain_text_explanation=(
                    f"This destination exhibited unusual characteristics (Trust Score: {trust_score}/100). "
                    f"While not confirmed malware, it matches patterns frequently used in phishing attacks."
                ),
                risk_factors=factor_list,
                user_guidance="Verify the sender before proceeding, and never share financial credentials.",
            )
        elif action == ActionVerdict.INCONCLUSIVE:
            return ExplanationOutput(
                headline="Analysis Inconclusive: Safety Unverified",
                plain_text_explanation=(
                    "We were unable to complete sufficient verification checks on this destination. "
                    "Safety cannot be guaranteed."
                ),
                risk_factors=["Analysis coverage insufficient"],
                user_guidance="Treat this destination as untrusted and verify through official channels.",
            )
        else:
            return ExplanationOutput(
                headline="Verified Safe: No Threats Detected",
                plain_text_explanation=(
                    f"All completed security checks passed without detecting known malware, "
                    f"phishing signatures, or suspicious indicators (Trust Score: {trust_score}/100)."
                ),
                risk_factors=[],
                user_guidance="Safe to proceed. Always ensure HTTPS is active when logging in.",
            )
