"""
LLM Data Schemas
Structured contracts for LLM inputs and outputs.
Enforces strict typing and structured JSON formats to prevent prompt injection and schema drift.
"""
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any


class ContextInterpretation(BaseModel):
    """Structured interpretation of user query and context."""
    user_intent: str = Field(description="Summary of what the user is asking to evaluate")
    extracted_indicators: List[str] = Field(default_factory=list, description="Candidate URLs, domains, or emails mentioned")
    candidate_risk_categories: List[str] = Field(default_factory=list, description="Potential threat categories: phishing, malware, scam, impersonation, none")
    context_summary: str = Field(description="Brief sanitised summary of the submission context")


class ExplanationOutput(BaseModel):
    """Structured human-readable explanation of deterministic security findings."""
    headline: str = Field(description="One-sentence headline summarizing verdict")
    plain_text_explanation: str = Field(description="Plain-language 2-3 sentence explanation without jargon")
    risk_factors: List[str] = Field(default_factory=list, description="Key confirmed threat factors explained simply")
    user_guidance: str = Field(description="Direct, clear recommendation for the user")


class LLMResult(BaseModel):
    """Result of an LLM invocation with provenance and latency."""
    provider: str
    model: str
    success: bool
    content: Optional[str] = None
    structured_data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    latency_ms: int = 0
