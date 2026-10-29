import logging
from typing import Optional
from fastapi import APIRouter, HTTPException, Depends, status
from sqlalchemy.orm import Session

from app.schemas.ai_contracts import (
    BaseUniformResponse,
    ScreenshotAnalysisRequest,
    URLAnalysisRequest,
    QRAnalysisRequest,
    DeepfakeAnalysisRequest,
    DeepfakeAnalysisResponse,
)
from app.ai.gateway.gateway import AIGateway
from app.ai.deepfake.service import DeepfakeDetectorService
from app.auth.security import get_service_or_user_id
from app.database.session import get_db

logger = logging.getLogger("thelix.api.ai")
router = APIRouter()


def resolve_effective_user(caller_id: str, requested_user_id: Optional[str]) -> str:
    """
    Enforces identity and ownership boundaries:
    - Service-role callers can specify an authorized target user_id or default to 'service_role'.
    - Authenticated end-users CANNOT specify or forge another user's ID (impersonation prevention).
    """
    if caller_id == "service_role":
        return requested_user_id.strip() if requested_user_id and requested_user_id.strip() else "service_role"

    if requested_user_id and requested_user_id.strip() and requested_user_id.strip() != caller_id:
        logger.warning(f"User impersonation attempt rejected: caller '{caller_id}' claimed '{requested_user_id}'")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Cannot execute analysis or access data for another user ID",
        )
    return caller_id


@router.post("/analyze-screenshot", response_model=BaseUniformResponse)
async def analyze_screenshot(
    request: ScreenshotAnalysisRequest,
    caller_id: str = Depends(get_service_or_user_id),
    db: Session = Depends(get_db),
):
    """
    Analyze a screenshot for potential threats (Phishing, Scam, Fake UI).
    Uses authoritative OrchestratorService and persists scan entities.
    Requires valid service token or authenticated user token.
    """
    effective_user_id = resolve_effective_user(caller_id, request.user_id)
    try:
        return await AIGateway.analyze_screenshot(request, user_id=effective_user_id, db=db)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error during screenshot analysis: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Screenshot analysis failed. Please check audit logs or scan status.",
        )


@router.post("/analyze-url", response_model=BaseUniformResponse)
async def analyze_url(
    request: URLAnalysisRequest,
    caller_id: str = Depends(get_service_or_user_id),
    db: Session = Depends(get_db),
):
    """
    Analyze a URL against Threat Intelligence and static heuristics.
    Uses authoritative OrchestratorService and persists scan entities.
    Requires valid service token or authenticated user token.
    """
    effective_user_id = resolve_effective_user(caller_id, request.user_id)
    try:
        return await AIGateway.analyze_url(request, user_id=effective_user_id, db=db)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error during URL analysis: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="URL analysis failed. Please check audit logs or scan status.",
        )


@router.post("/analyze-qr", response_model=BaseUniformResponse)
async def analyze_qr(
    request: QRAnalysisRequest,
    caller_id: str = Depends(get_service_or_user_id),
    db: Session = Depends(get_db),
):
    """
    Decode a QR code and analyze the resulting payload.
    Uses authoritative OrchestratorService and persists scan entities.
    Requires valid service token or authenticated user token.
    """
    effective_user_id = resolve_effective_user(caller_id, request.user_id)
    try:
        return await AIGateway.analyze_qr(request, user_id=effective_user_id, db=db)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error during QR analysis: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="QR analysis failed. Please check audit logs or scan status.",
        )


@router.post("/analyze-deepfake", response_model=DeepfakeAnalysisResponse)
async def analyze_deepfake(
    request: DeepfakeAnalysisRequest,
    caller_id: str = Depends(get_service_or_user_id),
    db: Session = Depends(get_db),
):
    """
    Analyze an uploaded image or video frame for synthetic manipulation / deepfake indicators.
    Enforces media bounds, reports honest prototype status when uncalibrated weights are missing,
    and returns structured probabilistic disclosures.
    """
    effective_user_id = resolve_effective_user(caller_id, request.user_id)
    try:
        return await DeepfakeDetectorService.analyze_media(request)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error during deepfake analysis: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Deepfake analysis service encountered an error.",
        )

