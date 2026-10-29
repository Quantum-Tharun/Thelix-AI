"""
AI Orchestrator Adapter
Bridges the legacy AI Gateway contracts to the authoritative OrchestratorService and RiskEngine.
Guarantees full relational persistence, audit event tracking, and unified deterministic scoring.
"""
import base64
import logging
from typing import Dict, Any, Optional, List
from sqlalchemy.orm import Session

from app.schemas.ai_contracts import (
    BaseUniformResponse,
    ScreenshotAnalysisRequest,
    URLAnalysisRequest,
    QRAnalysisRequest
)
from app.services.orchestrator_service import OrchestratorService
from app.config import settings

logger = logging.getLogger("thelix.orchestrator.adapter")


class AIOrchestrator:
    """
    Adapts legacy /v1/ai endpoint requests to the authoritative OrchestratorService.
    Eliminates parallel mock scoring engines, ensuring all risk decisions follow
    the documented Risk Engine policy and are persisted in the relational database.
    """

    @classmethod
    async def process_url(
        cls,
        request: URLAnalysisRequest,
        user_id: Optional[str] = None,
        db: Optional[Session] = None,
    ) -> BaseUniformResponse:
        effective_user = user_id or request.user_id or "service_role"
        orchestrator = OrchestratorService(db=db)

        # Execute authoritative URL scan (static heuristics + threat intel + risk engine + persistence)
        report = await orchestrator.execute_url_scan(
            target_url=request.url,
            user_id=effective_user,
            enable_sandbox=False,
        )

        threat_level = report.risk_level.value.capitalize()
        reasons = [f.title for f in report.findings] if report.findings else []
        if not reasons and report.risk_score > 0:
            reasons = [report.summary]

        evidence_dict = {
            f"{e.source_engine}:{e.indicator_type}": e.observation
            for e in report.evidence
        }
        if not evidence_dict:
            evidence_dict = {"url_threats": []}

        # Check offline status based on whether API keys are configured
        processed_offline = not bool(settings.SAFE_BROWSING_API_KEY or settings.VIRUSTOTAL_API_KEY)

        recs = getattr(report, "recommended_next_steps", None) or getattr(report, "recommendations", None)
        recommendations = recs if recs else cls._generate_recommendations(threat_level)

        return BaseUniformResponse(
            trust_score=report.trust_score,
            risk_score=report.risk_score,
            threat_level=threat_level,
            reasons=reasons,
            recommendations=recommendations,
            explanation=report.explanation or report.summary,
            evidence=evidence_dict,
            model_versions=report.engine_versions,
            processed_offline=processed_offline,
        )

    @classmethod
    async def process_screenshot(
        cls,
        request: ScreenshotAnalysisRequest,
        user_id: Optional[str] = None,
        db: Optional[Session] = None,
    ) -> BaseUniformResponse:
        effective_user = user_id or request.user_id or "service_role"
        orchestrator = OrchestratorService(db=db)

        # Clean potential data URI prefix and decode base64
        clean_b64 = request.image_base64
        if "," in clean_b64:
            clean_b64 = clean_b64.split(",", 1)[1]
        content_bytes = base64.b64decode(clean_b64)

        report = await orchestrator.execute_multimodal_scan(
            input_type="screenshot",
            user_id=effective_user,
            content_bytes=content_bytes,
            filename="screenshot.png",
        )

        threat_level = report.risk_level.value.capitalize()
        reasons = [f.title for f in report.findings] if report.findings else []
        if not reasons and report.risk_score > 0:
            reasons = [report.summary]

        evidence_dict = {
            f"{e.source_engine}:{e.indicator_type}": e.observation
            for e in report.evidence
        }
        if not evidence_dict:
            evidence_dict = {"ocr_text": report.extracted_text_preview or ""}

        return BaseUniformResponse(
            trust_score=report.trust_score,
            risk_score=report.risk_score,
            threat_level=threat_level,
            reasons=reasons,
            recommendations=report.recommendations if report.recommendations else cls._generate_recommendations(threat_level),
            explanation=report.summary,
            evidence=evidence_dict,
            model_versions=report.detector_versions,
            processed_offline=not bool(settings.SAFE_BROWSING_API_KEY or settings.VIRUSTOTAL_API_KEY),
        )

    @classmethod
    async def process_qr(
        cls,
        request: QRAnalysisRequest,
        user_id: Optional[str] = None,
        db: Optional[Session] = None,
    ) -> BaseUniformResponse:
        effective_user = user_id or request.user_id or "service_role"
        orchestrator = OrchestratorService(db=db)

        clean_b64 = request.image_base64
        if "," in clean_b64:
            clean_b64 = clean_b64.split(",", 1)[1]
        content_bytes = base64.b64decode(clean_b64)

        report = await orchestrator.execute_multimodal_scan(
            input_type="qr",
            user_id=effective_user,
            content_bytes=content_bytes,
            filename="qr_code.png",
        )

        threat_level = report.risk_level.value.capitalize()
        reasons = [f.title for f in report.findings] if report.findings else []
        if not reasons and report.risk_score > 0:
            reasons = [report.summary]

        evidence_dict = {
            f"{e.source_engine}:{e.indicator_type}": e.observation
            for e in report.evidence
        }
        if not evidence_dict:
            evidence_dict = {"decoded_url": report.target_summary or ""}

        return BaseUniformResponse(
            trust_score=report.trust_score,
            risk_score=report.risk_score,
            threat_level=threat_level,
            reasons=reasons,
            recommendations=report.recommendations if report.recommendations else cls._generate_recommendations(threat_level),
            explanation=report.summary,
            evidence=evidence_dict,
            model_versions=report.detector_versions,
            processed_offline=not bool(settings.SAFE_BROWSING_API_KEY or settings.VIRUSTOTAL_API_KEY),
        )

    @classmethod
    def _generate_recommendations(cls, threat_level: str) -> List[str]:
        if threat_level in ("High", "Critical"):
            return [
                "Do not open, visit, or enter credentials into this destination.",
                "Delete the message, email, or QR code immediately.",
                "Report this incident to your security administrator or service provider."
            ]
        elif threat_level == "Medium":
            return [
                "Review the target destination carefully for subtle brand impersonation.",
                "Do not download files or authorize financial transactions.",
                "Verify the sender through a secondary trusted channel."
            ]
        return [
            "No known security threats were identified during analysis.",
            "Always verify HTTPS certificates when entering sensitive credentials."
        ]
