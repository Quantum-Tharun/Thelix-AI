import logging
from typing import Optional
from sqlalchemy.orm import Session

from app.schemas.ai_contracts import (
    BaseUniformResponse,
    ScreenshotAnalysisRequest,
    URLAnalysisRequest,
    QRAnalysisRequest
)
from app.ai.orchestrator.orchestrator import AIOrchestrator
from app.database.session import SessionLocal

logger = logging.getLogger("thelix.gateway")


class AIGateway:
    """
    Single centralized entry point for legacy/subsystem AI calls.
    Delegates to AIOrchestrator which invokes the authoritative OrchestratorService.
    Guarantees deterministic scoring, database persistence, and audit trail consistency.
    """

    @classmethod
    async def analyze_screenshot(
        cls,
        request: ScreenshotAnalysisRequest,
        user_id: Optional[str] = None,
        db: Optional[Session] = None,
    ) -> BaseUniformResponse:
        effective_user = user_id or request.user_id or "service_role"
        logger.info(f"Gateway routing screenshot analysis for user: {effective_user}")
        close_db = False
        if db is None:
            db = SessionLocal()
            close_db = True
        try:
            return await AIOrchestrator.process_screenshot(request, user_id=effective_user, db=db)
        finally:
            if close_db:
                db.close()

    @classmethod
    async def analyze_url(
        cls,
        request: URLAnalysisRequest,
        user_id: Optional[str] = None,
        db: Optional[Session] = None,
    ) -> BaseUniformResponse:
        effective_user = user_id or request.user_id or "service_role"
        logger.info(f"Gateway routing URL analysis for user: {effective_user}")
        close_db = False
        if db is None:
            db = SessionLocal()
            close_db = True
        try:
            return await AIOrchestrator.process_url(request, user_id=effective_user, db=db)
        finally:
            if close_db:
                db.close()

    @classmethod
    async def analyze_qr(
        cls,
        request: QRAnalysisRequest,
        user_id: Optional[str] = None,
        db: Optional[Session] = None,
    ) -> BaseUniformResponse:
        effective_user = user_id or request.user_id or "service_role"
        logger.info(f"Gateway routing QR analysis for user: {effective_user}")
        close_db = False
        if db is None:
            db = SessionLocal()
            close_db = True
        try:
            return await AIOrchestrator.process_qr(request, user_id=effective_user, db=db)
        finally:
            if close_db:
                db.close()
