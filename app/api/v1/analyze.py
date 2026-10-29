"""
Canonical Analyze API Router
Primary user-facing digital trust and threat assessment endpoint.
Automatically detects input type (URL, text/message, screenshot/image, QR code, PDF/document),
extracts evidence safely, executes deterministic Risk Engine checks, and returns a clear,
explainable report directly.
"""
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form, Response
from sqlalchemy.orm import Session
from typing import Optional, List, Dict, Any, Union
from datetime import datetime, timezone
import uuid
import logging

from app.database.session import get_db
from app.auth.security import get_current_user_id, get_current_user_claims
from app.repositories.scan_repository import ScanRepository
from app.services.orchestrator_service import OrchestratorService
from app.api.v1.scans import enforce_pilot_access_and_quota, _map_assessment_to_verdict_fields
from app.services.input_detector import (
    detect_and_validate_input_type,
    ProhibitedFileFormatException,
    sanitize_target_for_display,
    InputType,
)
from risk_engine.exceptions import ValidationError
from risk_engine.report_builder import SecurityReport
from ai_engineering.multimodal.contracts import MultimodalAnalysisReport
from app.config import settings
from app.schemas.scan_schemas import (
    AnalyzeReportResponse,
    AnalyzeAsyncQueuedResponse,
    FindingItem,
)

logger = logging.getLogger("thelix.api.analyze")
router = APIRouter()

HTTP_413_CODE = getattr(status, "HTTP_413_CONTENT_TOO_LARGE", 413)


def _format_url_security_report(report: SecurityReport) -> AnalyzeReportResponse:
    """Transforms URL SecurityReport into standardized AnalyzeReportResponse."""
    findings_items = [
        FindingItem(
            finding_code=f.finding_code,
            title=f.title,
            description=f.description,
            severity=f.severity.value if hasattr(f.severity, "value") else str(f.severity),
            confidence=float(f.confidence),
            source_engine=str(f.source_engine),
        )
        for f in report.findings
    ]

    return AnalyzeReportResponse(
        analysis_id=report.scan_id,
        scan_id=report.scan_id,
        status=report.scan_status.upper(),
        input_type="url",
        target_summary=sanitize_target_for_display(report.target_url),
        verdict_category=report.verdict_category,
        verdict_label=report.verdict_label,
        risk_score=report.risk_score,
        trust_score=report.trust_score,
        risk_level=report.risk_level.value if hasattr(report.risk_level, "value") else str(report.risk_level),
        confidence=round(float(report.confidence), 4),
        coverage_ratio=round(float(report.coverage_ratio), 4),
        recommended_action=report.recommended_action.value if hasattr(report.recommended_action, "value") else str(report.recommended_action),
        summary=report.summary,
        why_this_result=report.why_this_result or report.explanation or report.summary,
        what_we_checked=report.what_we_checked,
        what_we_could_not_check=report.what_we_could_not_check,
        findings=findings_items,
        next_steps=report.next_steps or report.recommended_next_steps,
        created_at=report.created_at.isoformat() if hasattr(report.created_at, "isoformat") else str(report.created_at),
    )


def _format_multimodal_analysis_report(report: MultimodalAnalysisReport) -> AnalyzeReportResponse:
    """Transforms MultimodalAnalysisReport into standardized AnalyzeReportResponse."""
    findings_items = [
        FindingItem(
            finding_code=f.finding_code,
            title=f.title,
            description=f.description,
            severity=f.severity.value if hasattr(f.severity, "value") else str(f.severity),
            confidence=float(f.confidence),
            source_engine=str(f.source_engine),
        )
        for f in report.findings
    ]

    status_str = report.status.value.upper() if hasattr(report.status, "value") else str(report.status).upper()
    input_type_str = report.input_type.value if hasattr(report.input_type, "value") else str(report.input_type)

    return AnalyzeReportResponse(
        analysis_id=report.analysis_id,
        scan_id=report.analysis_id,
        status=status_str,
        input_type=input_type_str,
        target_summary=sanitize_target_for_display(report.target_summary or input_type_str),
        verdict_category=report.verdict_category,
        verdict_label=report.verdict_label,
        risk_score=report.risk_score,
        trust_score=report.trust_score,
        risk_level=report.risk_level.value if hasattr(report.risk_level, "value") else str(report.risk_level),
        confidence=round(float(report.confidence), 4),
        coverage_ratio=round(float(report.coverage_ratio), 4),
        recommended_action=report.recommended_action.value if hasattr(report.recommended_action, "value") else str(report.recommended_action),
        summary=report.summary,
        why_this_result=report.why_this_result or report.summary,
        what_we_checked=report.what_we_checked,
        what_we_could_not_check=report.what_we_could_not_check,
        findings=findings_items,
        next_steps=report.next_steps or report.recommendations,
        created_at=report.created_at.isoformat() if hasattr(report.created_at, "isoformat") else str(report.created_at),
    )


@router.post(
    "",
    status_code=status.HTTP_200_OK,
    response_model=Union[AnalyzeReportResponse, AnalyzeAsyncQueuedResponse],
    summary="Primary Digital Trust & Security Assessment",
    description="""
    Submit content (URL, message text, screenshot/image, QR code, or supported document) for comprehensive threat analysis.
    
    - **Automatic Input Detection**: Automatically distinguishes URLs from text messages and sniffs image/PDF magic bytes.
    - **Synchronous Default**: Returns the complete, evidence-grounded Security Report directly (HTTP 200).
    - **Opt-in Asynchronous Mode**: Set `prefer_async=true` to enqueue long-running analysis in the durable worker queue (HTTP 202).
    - **Security & Privacy**: Binary executables, scripts, and archives are strictly rejected. Passwords and credentials are redacted.
    """,
    responses={
        200: {"description": "Assessment completed synchronously. Returns authoritative Digital Trust Report.", "model": AnalyzeReportResponse},
        202: {"description": "Task enqueued for asynchronous worker execution.", "model": AnalyzeAsyncQueuedResponse},
        400: {"description": "Validation error (conflicting inputs, empty payload, or prohibited file signature)."},
        413: {"description": "Payload exceeds maximum allowed limits (10MB for files, 500k characters for text)."},
        429: {"description": "Rate limit or daily pilot quota exceeded."},
    },
)
async def analyze_target(
    response: Response,
    content: Optional[str] = Form(None, description="URL or plain text/message content to analyze."),
    file: Optional[UploadFile] = File(None, description="Screenshot, image, QR code, or supported document upload (PNG, JPEG, WEBP, BMP, PDF)."),
    context: Optional[str] = Form(None, description="Optional untrusted user-supplied context or concern (max 50,000 characters)."),
    prefer_async: bool = Form(False, description="Set to true to enqueue analysis asynchronously in durable worker queue."),
    user_id: str = Depends(get_current_user_id),
    claims: Dict[str, Any] = Depends(get_current_user_claims),
    db: Session = Depends(get_db),
):
    """
    Primary user-facing Digital Trust Assessment endpoint.
    Auto-detects input type, validates constraints, and executes safe analysis pipeline.
    """
    has_content = bool(content and content.strip())
    has_file = bool(file is not None and getattr(file, "filename", None))

    # 1. Mutual Exclusion Validation: exactly one of content or file must be provided
    if has_content and has_file:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot accept both 'content' and 'file' simultaneously. Please provide exactly one input.",
        )
    if not has_content and not has_file:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either 'content' (URL/message) or 'file' (image/document) must be provided for analysis.",
        )

    # 2. Size Limit Enforcement
    if has_content and len(content) > 500_000:
        raise HTTPException(
            status_code=HTTP_413_CODE,
            detail="Text content exceeds maximum limit of 500,000 characters.",
        )

    content_bytes: Optional[bytes] = None
    filename: Optional[str] = None

    if has_file:
        max_file_size = 10 * 1024 * 1024  # 10 MB limit
        content_bytes = await file.read(max_file_size + 1)
        if len(content_bytes) > max_file_size:
            raise HTTPException(
                status_code=HTTP_413_CODE,
                detail="Uploaded file exceeds maximum limit of 10MB.",
            )
        if len(content_bytes) == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded file is empty (0 bytes received).",
            )
        filename = file.filename

    if context and len(context) > 50_000:
        raise HTTPException(
            status_code=HTTP_413_CODE,
            detail="User context exceeds maximum limit of 50,000 characters.",
        )

    # 3. Content-aware Input Sniffing, Magic Bytes & Extension Verification
    try:
        detected_type, detection_meta = detect_and_validate_input_type(
            content_bytes=content_bytes,
            text_content=content if has_content else None,
            filename=filename,
        )
        effective_input_type = detected_type.value
    except ProhibitedFileFormatException as pfe:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported input: {pfe.message}",
        )
    except ValidationError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Input validation error: {ve.message}",
        )
    except Exception as e:
        if isinstance(e, HTTPException):
            raise
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Input validation error: {str(e)}",
        )

    # 4. Pilot Program Authorization & Atomic Quota Reservation
    enforce_pilot_access_and_quota(claims, user_id, db, check_quota=False)

    if settings.PILOT_MODE_ENABLED:
        repo = ScanRepository(db)
        today_key = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        reserved = repo.reserve_daily_scan_quota(
            user_id=user_id,
            date_key=today_key,
            limit=settings.PILOT_MAX_SCANS_PER_USER_PER_DAY,
        )
        if not reserved:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Daily pilot scan quota exceeded (maximum {settings.PILOT_MAX_SCANS_PER_USER_PER_DAY} scans per day).",
            )

    # 5. Execution Path: Asynchronous Worker vs Synchronous Inline
    scan_id = str(uuid.uuid4())

    if prefer_async:
        repo = ScanRepository(db)
        raw_target = filename or (content[:200] if content else effective_input_type)
        try:
            repo.create_scan_with_outbox_task(
                scan_id=scan_id,
                user_id=user_id,
                input_type=effective_input_type,
                raw_target=raw_target,
                payload_dict={
                    "target_url": content if effective_input_type == "url" else None,
                    "text_content": content if effective_input_type != "url" else None,
                    "user_id": user_id,
                    "context": context,
                    "enable_sandbox": True,
                    "filename": filename,
                },
            )
        except Exception as e:
            logger.error(f"Failed to enqueue durable outbox task for scan {scan_id}: {e}", exc_info=True)
            if settings.PILOT_MODE_ENABLED:
                today_key = datetime.now(timezone.utc).strftime("%Y-%m-%d")
                repo.refund_daily_scan_quota(user_id=user_id, date_key=today_key, scan_id=scan_id)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to enqueue analysis task in durable queue.",
            )

        response.status_code = status.HTTP_202_ACCEPTED
        return AnalyzeAsyncQueuedResponse(
            analysis_id=scan_id,
            scan_id=scan_id,
            status="QUEUED",
            message="Analysis task queued for asynchronous processing. Retrieve status or report at /v1/analyze/{analysis_id}.",
            report_url=f"/v1/analyze/{scan_id}",
        )

    # Synchronous Execution Path
    orchestrator = OrchestratorService(db=db)
    try:
        if detected_type == InputType.URL:
            report = await orchestrator.execute_url_scan(
                target_url=content.strip(),
                user_id=user_id,
                scan_id=scan_id,
                context=context,
                enable_sandbox=False,
            )
            return _format_url_security_report(report)
        else:
            report = await orchestrator.execute_multimodal_scan(
                input_type=effective_input_type,
                user_id=user_id,
                content_bytes=content_bytes,
                text_content=content,
                filename=filename,
                scan_id=scan_id,
                context=context,
            )
            return _format_multimodal_analysis_report(report)
    except Exception as exc:
        logger.error(f"Synchronous analysis execution failed for {scan_id}: {exc}", exc_info=True)
        if settings.PILOT_MODE_ENABLED:
            repo = ScanRepository(db)
            today_key = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            repo.refund_daily_scan_quota(user_id=user_id, date_key=today_key, scan_id=scan_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Analysis execution encountered an unexpected internal error.",
        )


@router.get(
    "/{analysis_id}",
    response_model=Union[AnalyzeReportResponse, Dict[str, Any]],
    summary="Retrieve Analysis Report or Status",
    description="Fetches the finalized Security Assessment Report or current processing status by analysis ID. Enforces tenant isolation.",
)
def get_analysis_report(
    analysis_id: str,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    """
    Retrieves the authoritative analysis report or status for a given analysis ID.
    Enforces user ownership.
    """
    repo = ScanRepository(db)
    scan = repo.get_scan(scan_id=analysis_id, user_id=user_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis not found")

    if scan.status in ("QUEUED", "PROCESSING"):
        return {
            "analysis_id": scan.id,
            "scan_id": scan.id,
            "status": scan.status,
            "message": f"Analysis is currently in progress (status: {scan.status}). Please check back shortly.",
            "created_at": scan.created_at.isoformat(),
        }

    if not scan.assessment:
        return {
            "analysis_id": scan.id,
            "scan_id": scan.id,
            "status": scan.status,
            "message": "Assessment incomplete or no assessment record available.",
            "created_at": scan.created_at.isoformat(),
        }

    category, label, advice, what_checked, what_not_checked = _map_assessment_to_verdict_fields(
        scan.assessment, scan.findings, scan.evidence
    )

    findings_items = [
        FindingItem(
            finding_code=f.finding_code,
            title=f.title,
            description=f.description,
            severity=f.severity,
            confidence=float(f.confidence),
            source_engine=f.source_engine,
        )
        for f in scan.findings
    ]

    return AnalyzeReportResponse(
        analysis_id=scan.id,
        scan_id=scan.id,
        status=scan.status,
        input_type=scan.input_type,
        target_summary=sanitize_target_for_display(scan.raw_target),
        verdict_category=category,
        verdict_label=label,
        risk_score=scan.assessment.risk_score,
        trust_score=scan.assessment.trust_score,
        risk_level=scan.assessment.risk_level,
        confidence=round(float(scan.assessment.confidence), 4),
        coverage_ratio=round(float(scan.assessment.coverage_ratio), 4),
        recommended_action=scan.assessment.recommended_action,
        summary=scan.assessment.summary,
        why_this_result=scan.assessment.explanation or scan.assessment.summary,
        what_we_checked=what_checked,
        what_we_could_not_check=what_not_checked,
        findings=findings_items,
        next_steps=advice,
        created_at=scan.created_at.isoformat(),
    )
