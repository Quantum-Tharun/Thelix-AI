"""
Scan API Request & Response Schemas
Pydantic models for client-facing scan workflows, reports, feedback, and audit events.
"""
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime


class CreateScanRequest(BaseModel):
    """Payload to initiate a security scan."""
    target: str = Field(..., min_length=1, max_length=4096, description="Target URL, payload, or indicator to scan")
    input_type: str = Field("url", max_length=50, description="Type of input: 'url', 'screenshot', 'qr', 'document'")
    context: Optional[str] = Field(None, max_length=50000, description="Optional user-provided message or threat context")
    enable_sandbox: bool = Field(True, description="Whether to perform isolated dynamic inspection if target allows")


class ScanResponse(BaseModel):
    """High-level scan status representation."""
    scan_id: str
    user_id: str
    status: str
    input_type: str
    raw_target: str
    normalized_target: Optional[str] = None
    created_at: str
    completed_at: Optional[str] = None


class FeedbackRequest(BaseModel):
    """User evaluation on assessment accuracy."""
    rating: str = Field(..., description="'helpful', 'false_positive', 'false_negative', 'inaccurate'")
    comments: Optional[str] = Field(None, description="Optional user commentary")


class AuditEventResponse(BaseModel):
    """Audit log entry for scan lifecycle transparency."""
    id: str
    scan_id: Optional[str]
    event_type: str
    details: Dict[str, Any]
    created_at: str


class FindingItem(BaseModel):
    """Structured security finding item."""
    finding_code: str = Field(..., description="Stable threat or indicator identifier.")
    title: str = Field(..., description="Concise finding headline.")
    description: str = Field(..., description="Detailed analytical explanation.")
    severity: str = Field(..., description="Finding severity level: LOW, MEDIUM, HIGH, CRITICAL.")
    confidence: float = Field(..., description="Confidence score [0.0 - 1.0].")
    source_engine: str = Field(..., description="Subsystem or engine that produced this finding.")


class AnalyzeReportResponse(BaseModel):
    """
    Standardized, authoritative Digital Trust Assessment Report.
    Provides non-technical users with clear verdicts, evidence, checks, and actionable next steps.
    """
    analysis_id: str = Field(..., description="Unique persistent identifier for this analysis.")
    scan_id: str = Field(..., description="Underlying scan record identifier.")
    status: str = Field(..., description="Analysis status (COMPLETED, PARTIAL, FAILED, INCONCLUSIVE).")
    input_type: str = Field(..., description="Detected input type (url, message, screenshot, qr, pdf, document).")
    target_summary: Optional[str] = Field(None, description="Sanitized display target or filename.")
    verdict_category: str = Field(..., description="Standardized outcome tier: LIKELY_SAFE, SUSPICIOUS, PHISHING_OR_SCAM, MALWARE_INDICATORS_DETECTED, INCONCLUSIVE, UNSUPPORTED_INPUT.")
    verdict_label: str = Field(..., description="Clear human-understandable outcome label.")
    risk_score: int = Field(..., ge=0, le=100, description="Deterministic risk index from 0 (clean) to 100 (critical threat).")
    trust_score: int = Field(..., ge=0, le=100, description="Trust score (100 - risk_score).")
    risk_level: str = Field(..., description="Categorical risk tier: LOW, MEDIUM, HIGH, CRITICAL.")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence of analytical assessment [0.0 - 1.0].")
    coverage_ratio: float = Field(..., ge=0.0, le=1.0, description="Completeness of planned security checks [0.0 - 1.0].")
    recommended_action: str = Field(..., description="Recommended policy action: ALLOW, WARN, BLOCK, INCONCLUSIVE.")
    summary: str = Field(..., description="Concise assessment summary.")
    why_this_result: str = Field(..., description="Evidence-grounded rationale explaining why this verdict was reached.")
    what_we_checked: List[Any] = Field(default_factory=list, description="Checks that actually ran and their observed signals.")
    what_we_could_not_check: List[Any] = Field(default_factory=list, description="Explicit record of checks that were omitted, disabled, or unavailable.")
    findings: List[FindingItem] = Field(default_factory=list, description="Specific threat indicators detected.")
    next_steps: List[str] = Field(default_factory=list, description="Practical, non-alarmist recommendations for the user.")
    created_at: str = Field(..., description="ISO 8601 creation timestamp.")


class AnalyzeAsyncQueuedResponse(BaseModel):
    """Asynchronous acceptance response when client specifies prefer_async=True."""
    analysis_id: str = Field(..., description="Unique persistent identifier for the queued scan.")
    scan_id: str = Field(..., description="Underlying scan identifier.")
    status: str = Field("QUEUED", description="Current lifecycle state.")
    message: str = Field(..., description="Status guidance.")
    report_url: str = Field(..., description="URL to retrieve the completed report once processing finishes.")

