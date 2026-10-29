"""
Multimodal Threat Analysis Contracts
Defines standardized data models, input types, extraction results,
and shared finding schemas for all digital threat modalities.
"""
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
import uuid

from risk_engine.evidence import Evidence, Finding, Severity, ActionVerdict, RiskLevel


class InputType(str, Enum):
    """Supported input modalities for Thelix AI threat analysis."""
    URL = "url"
    SCREENSHOT = "screenshot"
    QR_CODE = "qr"
    DOCUMENT_PDF = "pdf"
    DOCUMENT_TEXT = "text"
    MESSAGE_TEXT = "message"


class MultimodalStatus(str, Enum):
    """Processing status for multimodal extraction and analysis."""
    QUEUED = "queued"
    EXTRACTING = "extracting"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    REJECTED = "rejected"


@dataclass
class ExtractedIndicator:
    """An atomic indicator discovered within raw content (e.g. an embedded URL, phone, or credential lure)."""
    indicator_type: str                         # 'url', 'phone', 'email', 'crypto_address', 'text_phrase'
    value: str                                  # Extracted value (sanitized)
    confidence: float = 1.0                     # Detection confidence [0.0 - 1.0]
    location: Optional[Dict[str, Any]] = None   # Page number, bounding box, or character offset
    source_detector: str = ""                   # 'ocr_tesseract', 'opencv_qr', 'pypdf_extractor'


@dataclass
class MultimodalExtractionResult:
    """Standardized extraction artifact produced by modality-specific extractors."""
    input_type: InputType
    raw_hash: str                               # SHA-256 of raw file or normalized text
    extracted_text: Optional[str] = None        # Extracted human-readable text
    extracted_urls: List[str] = field(default_factory=list)
    indicators: List[ExtractedIndicator] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    detector_metadata: Dict[str, Any] = field(default_factory=dict)
    processing_time_ms: int = 0
    success: bool = True
    error_message: Optional[str] = None


@dataclass
class MultimodalAnalysisReport:
    """Unified analysis report returned by the Multimodal Orchestrator."""
    analysis_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    input_type: InputType = InputType.URL
    status: MultimodalStatus = MultimodalStatus.COMPLETED
    target_summary: str = ""
    extracted_text_preview: Optional[str] = None
    extracted_urls: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    risk_score: int = 0
    trust_score: int = 100
    risk_level: RiskLevel = RiskLevel.LOW
    confidence: float = 1.0
    coverage_ratio: float = 1.0
    recommended_action: ActionVerdict = ActionVerdict.ALLOW
    summary: str = ""
    recommendations: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    detector_versions: Dict[str, str] = field(default_factory=dict)
    inspection_type: str = "offline_multimodal_extraction_and_threat_analysis"
    score_interpretation: str = "The risk score (0-100) is an ordinal severity index, not a percentage probability of compromise."
    principal_evidence: List[Dict[str, Any]] = field(default_factory=list)
    verdict_rationale: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # User-facing outcome categories and transparent sections
    verdict_category: str = "LIKELY_SAFE"
    verdict_label: str = "Likely safe / no significant threat detected"
    why_this_result: str = ""
    what_we_checked: List[Dict[str, Any]] = field(default_factory=list)
    what_we_could_not_check: List[Dict[str, Any]] = field(default_factory=list)
    next_steps: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "analysis_id": self.analysis_id,
            "input_type": self.input_type.value,
            "status": self.status.value,
            "target_summary": self.target_summary,
            "extracted_text_preview": self.extracted_text_preview,
            "extracted_urls": self.extracted_urls,
            "risk_score": self.risk_score,
            "trust_score": self.trust_score,
            "risk_level": self.risk_level.value,
            "confidence": round(self.confidence, 4),
            "coverage_ratio": round(self.coverage_ratio, 4),
            "recommended_action": self.recommended_action.value,
            "verdict_category": self.verdict_category,
            "verdict_label": self.verdict_label,
            "why_this_result": self.why_this_result or self.summary,
            "what_we_checked": self.what_we_checked,
            "what_we_could_not_check": self.what_we_could_not_check,
            "next_steps": self.next_steps or self.recommendations,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
            "evidence": [e.to_dict() for e in self.evidence],
            "recommendations": self.recommendations,
            "limitations": self.limitations,
            "detector_versions": self.detector_versions,
            "inspection_type": self.inspection_type,
            "score_interpretation": self.score_interpretation,
            "principal_evidence": self.principal_evidence,
            "verdict_rationale": self.verdict_rationale,
            "created_at": self.created_at.isoformat(),
        }
