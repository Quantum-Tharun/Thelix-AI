"""
Scans API Router
Client-facing endpoints for scan submission, report retrieval, feedback, uploads, and lifecycle events.
"""
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form, BackgroundTasks, Response
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
import uuid
import hashlib
import os

from app.database.session import get_db
from app.auth.security import get_current_user_id, get_current_user_claims
from app.repositories.scan_repository import ScanRepository
from app.services.orchestrator_service import OrchestratorService
from app.services.input_detector import (
    detect_and_validate_input_type,
    ProhibitedFileFormatException,
    sanitize_target_for_display,
    InputType,
)
from risk_engine.report_builder import VerdictCategory
from app.config import settings
from app.schemas.scan_schemas import (
    CreateScanRequest,
    ScanResponse,
    FeedbackRequest,
    AuditEventResponse,
)

router = APIRouter()


def enforce_pilot_access_and_quota(
    claims: Dict[str, Any],
    user_id: str,
    db: Session,
    check_quota: bool = True,
) -> None:
    """
    Enforces emergency shutdown, pilot user enrollment restrictions, and daily scan quotas.
    """
    if settings.EMERGENCY_SHUTDOWN:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Emergency shutdown active: New scan submissions and artifact uploads are temporarily suspended.",
        )

    if not settings.PILOT_MODE_ENABLED:
        return

    import re
    allowed = settings.parsed_pilot_allowed_emails
    raw_email = str(claims.get("email", ""))
    # Canonical email normalization: strip zero-width characters and whitespace, lowercase
    email = re.sub(r"[\u200b-\u200d\ufeff]", "", raw_email).strip().lower()
    sub = str(claims.get("sub", "")).strip().lower()
    uid = user_id.strip().lower()

    # Stage E: Email-based pilot enrollment requires an explicit trustworthy verified-email signal.
    # Missing verification claims are NOT interpreted as verified.
    # User-controlled metadata (user_metadata) is client-writable in Supabase and strictly untrusted.
    email_is_verified = False
    if claims.get("email_verified") is True:
        email_is_verified = True
    elif claims.get("email_confirmed_at") is not None and bool(str(claims.get("email_confirmed_at")).strip()):
        email_is_verified = True
    elif isinstance(claims.get("app_metadata"), dict) and claims["app_metadata"].get("email_verified") is True:
        email_is_verified = True

    is_enrolled = False
    if allowed:
        if email and email_is_verified and email in allowed:
            is_enrolled = True
        elif sub and sub in allowed:
            is_enrolled = True
        elif uid and uid in allowed:
            is_enrolled = True

    if not is_enrolled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: User account is not enrolled in the limited pilot program.",
        )

    if check_quota:
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



@router.post("", status_code=status.HTTP_201_CREATED)
async def create_scan(
    payload: CreateScanRequest,
    response: Response,
    background_tasks: BackgroundTasks,
    sync: bool = False,
    user_id: str = Depends(get_current_user_id),
    claims: Dict[str, Any] = Depends(get_current_user_claims),
    db: Session = Depends(get_db),
):
    """
    Submits a target for evidence-based security assessment.
    If sync=True or enable_sandbox=False, runs synchronously (201 Created).
    If sync=False and enable_sandbox=True, executes in the background (202 Accepted).
    """
    enforce_pilot_access_and_quota(claims, user_id, db)

    scan_id = str(uuid.uuid4())

    # For long-running browser inspections, persist durable task atomically in DB outbox
    if payload.enable_sandbox and not sync:
        repo = ScanRepository(db)
        try:
            repo.create_scan_with_outbox_task(
                scan_id=scan_id,
                user_id=user_id,
                input_type=payload.input_type,
                raw_target=payload.target,
                payload_dict={
                    "target_url": payload.target,
                    "user_id": user_id,
                    "context": payload.context,
                    "enable_sandbox": True,
                },
            )
        except Exception as e:
            logger.error(f"Failed to persist durable scan outbox task for {scan_id}: {e}")
            if settings.PILOT_MODE_ENABLED:
                today_key = datetime.now(timezone.utc).strftime("%Y-%m-%d")
                repo.refund_daily_scan_quota(user_id=user_id, date_key=today_key, scan_id=scan_id)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to enqueue scan in durable task queue.",
            )

        response.status_code = status.HTTP_202_ACCEPTED
        return {
            "scan_id": scan_id,
            "status": "QUEUED",
            "message": "Scan queued for asynchronous analysis. Retrieve status at /v1/scans/{scan_id} or report at /v1/scans/{scan_id}/report",
        }

    orchestrator = OrchestratorService(db=db)
    try:
        report = await orchestrator.execute_url_scan(
            target_url=payload.target,
            user_id=user_id,
            scan_id=scan_id,
            context=payload.context,
            enable_sandbox=payload.enable_sandbox,
        )
        return {
            "scan_id": scan_id,
            "status": report.scan_status,
            "report": report.to_dict(),
        }
    except Exception as e:
        if settings.PILOT_MODE_ENABLED:
            repo = ScanRepository(db)
            today_key = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            repo.refund_daily_scan_quota(user_id=user_id, date_key=today_key, scan_id=scan_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Scan execution failed. Please check scan status or audit events.",
        )


@router.get("", response_model=List[ScanResponse])
def list_scans(
    limit: int = 50,
    offset: int = 0,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    """
    Lists historical scans belonging to the authenticated user.
    """
    repo = ScanRepository(db)
    scans = repo.list_scans(user_id=user_id, limit=limit, offset=offset)
    return [
        ScanResponse(
            scan_id=s.id,
            user_id=s.user_id,
            status=s.status,
            input_type=s.input_type,
            raw_target=s.raw_target,
            normalized_target=s.normalized_target,
            created_at=s.created_at.isoformat(),
            completed_at=s.completed_at.isoformat() if s.completed_at else None,
        )
        for s in scans
    ]


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(
    scan_id: str,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    """
    Retrieves current scan lifecycle status. Enforces user ownership.
    """
    repo = ScanRepository(db)
    scan = repo.get_scan(scan_id=scan_id, user_id=user_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    return ScanResponse(
        scan_id=scan.id,
        user_id=scan.user_id,
        status=scan.status,
        input_type=scan.input_type,
        raw_target=scan.raw_target,
        normalized_target=scan.normalized_target,
        created_at=scan.created_at.isoformat(),
        completed_at=scan.completed_at.isoformat() if scan.completed_at else None,
    )


def _map_assessment_to_verdict_fields(assessment, findings, evidence):
    risk_level = (assessment.risk_level or "").upper()
    recommended_action = (assessment.recommended_action or "").upper()

    has_malware = any("malware" in f.finding_code.lower() or "malware" in f.title.lower() for f in findings)
    has_phishing = any(
        f.finding_code in ("HOMOGLYPH_ATTACK", "KNOWN_MALICIOUS_DOMAIN", "TYPOSQUATTING_SUSPECTED", "SUSPICIOUS_REDIRECT")
        or "phishing" in f.title.lower()
        or "scam" in f.title.lower()
        for f in findings
    )

    if recommended_action == "INCONCLUSIVE" or risk_level == "UNKNOWN":
        category = VerdictCategory.INCONCLUSIVE.value
        label = "Inconclusive / Insufficient Evidence"
        advice = [
            "We could not inspect enough of this input to make a conclusive safety determination.",
            "Exercise caution and avoid sharing sensitive credentials or personal details.",
            "Try re-submitting with additional context or direct text/file evidence.",
        ]
    elif has_malware:
        category = VerdictCategory.MALWARE_INDICATORS_DETECTED.value
        label = "Malware Indicators Detected"
        advice = [
            "Do not download, open, execute, or distribute content from this source.",
            "If already downloaded, quarantine or delete the file immediately.",
            "Run a full anti-malware scan on your local device.",
        ]
    elif risk_level in ("HIGH", "CRITICAL") or recommended_action == "BLOCK" or has_phishing:
        category = VerdictCategory.PHISHING_OR_SCAM.value
        label = "Phishing / Scam Indicators Detected"
        advice = [
            "Do not provide passwords, OTPs, or payment information to this source.",
            "Close any browser sessions opened from this link immediately.",
            "If received from an unknown sender, report it as spam/phishing.",
        ]
    elif risk_level == "MEDIUM" or recommended_action == "WARN":
        category = VerdictCategory.SUSPICIOUS.value
        label = "Suspicious (Caution Recommended)"
        advice = [
            "Indicators of risk were detected that warrant heightened caution.",
            "Verify the authenticity of the sender or website through independent official channels.",
            "Avoid clicking unverified links or downloading attachments.",
        ]
    else:
        category = VerdictCategory.LIKELY_SAFE.value
        label = "Likely Safe (No Significant Threats Detected)"
        advice = [
            "Completed checks did not identify significant indicators of threat or scam activity.",
            "Remember that automated tools cannot guarantee absolute safety.",
            "Continue following standard cybersecurity best practices.",
        ]

    what_checked = [f"{e.source_engine}: {e.indicator_type}" for e in evidence] if evidence else [
        "URL static syntax and reputation analysis",
        "Deterministic heuristic scam & phishing pattern evaluation",
    ]

    what_not_checked = [
        "Dynamic browser sandbox execution (static analysis path active)",
        "Local executable execution (safely prevented by security policy)",
    ]

    return category, label, advice, what_checked, what_not_checked


@router.get("/{scan_id}/report")
def get_scan_report(
    scan_id: str,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    """
    Retrieves the finalized, structured Security Assessment Report.
    """
    repo = ScanRepository(db)
    scan = repo.get_scan(scan_id=scan_id, user_id=user_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    if not scan.assessment:
        return {
            "scan_id": scan.id,
            "status": scan.status,
            "message": "Assessment in progress or incomplete.",
        }

    category, label, advice, what_checked, what_not_checked = _map_assessment_to_verdict_fields(
        scan.assessment, scan.findings, scan.evidence
    )

    return {
        "scan_id": scan.id,
        "target_url": scan.raw_target,
        "normalized_url": scan.normalized_target,
        "status": scan.status,
        "verdict_category": category,
        "verdict_label": label,
        "why_this_result": scan.assessment.explanation or scan.assessment.summary,
        "what_we_checked": what_checked,
        "what_we_could_not_check": what_not_checked,
        "next_steps": advice,
        "assessment": {
            "risk_score": scan.assessment.risk_score,
            "trust_score": scan.assessment.trust_score,
            "risk_level": scan.assessment.risk_level,
            "confidence": scan.assessment.confidence,
            "coverage_ratio": scan.assessment.coverage_ratio,
            "recommended_action": scan.assessment.recommended_action,
            "summary": scan.assessment.summary,
            "explanation": scan.assessment.explanation,
        },
        "findings": [
            {
                "finding_code": f.finding_code,
                "title": f.title,
                "description": f.description,
                "severity": f.severity,
                "confidence": f.confidence,
                "source_engine": f.source_engine,
            }
            for f in scan.findings
        ],
        "evidence_count": len(scan.evidence),
        "created_at": scan.created_at.isoformat(),
    }


@router.get("/{scan_id}/events", response_model=List[AuditEventResponse])
def get_scan_events(
    scan_id: str,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    """
    Retrieves immutable audit event timeline for the scan.
    """
    repo = ScanRepository(db)
    scan = repo.get_scan(scan_id=scan_id, user_id=user_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    events = repo.get_audit_events(scan_id=scan_id)
    return [
        AuditEventResponse(
            id=ev.id,
            scan_id=ev.scan_id,
            event_type=ev.event_type,
            details=ev.details_json,
            created_at=ev.created_at.isoformat(),
        )
        for ev in events
    ]


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(
    scan_id: str,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    """
    Deletes a scan and associated artifacts/evidence. Enforces user ownership.
    """
    repo = ScanRepository(db)
    deleted = repo.delete_scan(scan_id=scan_id, user_id=user_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return None


@router.post("/{scan_id}/feedback", status_code=status.HTTP_201_CREATED)
def submit_feedback(
    scan_id: str,
    payload: FeedbackRequest,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    """
    Records end-user feedback on accuracy (e.g. false positives).
    """
    repo = ScanRepository(db)
    scan = repo.get_scan(scan_id=scan_id, user_id=user_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    feedback = repo.add_feedback(
        scan_id=scan_id,
        user_id=user_id,
        rating=payload.rating,
        comments=payload.comments,
    )
    return {"feedback_id": feedback.id, "status": "recorded"}


# Support non-deprecated Starlette 413 constant without triggering deprecation warning
HTTP_413_CODE = getattr(status, "HTTP_413_CONTENT_TOO_LARGE", 413)


@router.post("/uploads", status_code=status.HTTP_201_CREATED)
async def upload_artifact(
    file: UploadFile = File(...),
    artifact_type: str = Form("screenshot"),
    user_id: str = Depends(get_current_user_id),
    claims: Dict[str, Any] = Depends(get_current_user_claims),
    db: Session = Depends(get_db),
):
    """
    Uploads an inspection artifact (e.g. screenshot, document) securely.
    Computes SHA-256 and validates file constraints.
    """
    enforce_pilot_access_and_quota(claims, user_id, db, check_quota=False)
    max_size = 10 * 1024 * 1024  # 10 MB limit
    content = await file.read(max_size + 1)
    if len(content) > max_size:
        raise HTTPException(
            status_code=HTTP_413_CODE,
            detail="File size exceeds limit of 10MB",
        )

    file_hash = hashlib.sha256(content).hexdigest()
    artifact_id = str(uuid.uuid4())

    return {
        "artifact_id": artifact_id,
        "filename": file.filename,
        "content_type": file.content_type,
        "size_bytes": len(content),
        "file_hash": file_hash,
        "status": "staged",
    }


@router.post("/multimodal", status_code=status.HTTP_201_CREATED)
async def create_multimodal_scan(
    file: Optional[UploadFile] = File(None),
    text_content: Optional[str] = Form(None),
    input_type: str = Form("screenshot"),
    context: Optional[str] = Form(None),
    user_id: str = Depends(get_current_user_id),
    claims: Dict[str, Any] = Depends(get_current_user_claims),
    db: Session = Depends(get_db),
):
    """
    Submits multimodal content (screenshot, QR code, PDF, text document, or message)
    for unified threat detection and shared Risk Engine evaluation.
    """
    # Verify enrollment first without consuming quota
    enforce_pilot_access_and_quota(claims, user_id, db, check_quota=False)

    valid_types = {"url", "screenshot", "qr", "pdf", "text", "message"}
    if input_type.lower() not in valid_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported input_type '{input_type}'. Supported: {sorted(list(valid_types))}",
        )

    content_bytes: Optional[bytes] = None
    filename: Optional[str] = None

    if file:
        max_size = 10 * 1024 * 1024  # 10 MB
        content_bytes = await file.read(max_size + 1)
        if len(content_bytes) > max_size:
            raise HTTPException(
                status_code=HTTP_413_CODE,
                detail="Uploaded file exceeds maximum limit of 10MB",
            )
        filename = file.filename

    if text_content and len(text_content) > 500_000:
        raise HTTPException(
            status_code=HTTP_413_CODE,
            detail="Text content exceeds maximum limit of 500,000 characters",
        )

    if not content_bytes and not text_content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either a file upload or text_content must be provided for multimodal analysis",
        )

    # Content-aware input sniffing and magic byte verification
    try:
        detected_type, detection_meta = detect_and_validate_input_type(
            content_bytes=content_bytes,
            text_content=text_content,
            declared_type=input_type,
            filename=filename,
        )
        effective_input_type = detected_type.value
    except ProhibitedFileFormatException as pfe:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported input: {pfe.message}",
        )
    except Exception as e:
        if isinstance(e, HTTPException):
            raise
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Input validation error: {str(e)}",
        )

    # Atomically reserve quota only after all input validation checks pass
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

    orchestrator = OrchestratorService(db=db)
    scan_id = str(uuid.uuid4())

    try:
        report = await orchestrator.execute_multimodal_scan(
            input_type=effective_input_type,
            user_id=user_id,
            content_bytes=content_bytes,
            text_content=text_content,
            filename=filename,
            scan_id=scan_id,
            context=context,
        )
        return {
            "scan_id": scan_id,
            "status": report.status.value,
            "report": report.to_dict(),
        }
    except Exception as e:
        if settings.PILOT_MODE_ENABLED:
            repo = ScanRepository(db)
            today_key = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            repo.refund_daily_scan_quota(user_id=user_id, date_key=today_key, scan_id=scan_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Multimodal scan processing failed. Please check scan status or error logs.",
        )

