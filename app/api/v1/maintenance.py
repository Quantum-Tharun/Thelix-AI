"""
Operational Maintenance API Router
Endpoints for scheduled data retention pruning, stuck scan reconciliation,
and user right-to-be-forgotten / data deletion workflows.
"""
from fastapi import APIRouter, Depends, HTTPException, status, Header
from sqlalchemy.orm import Session
from typing import Optional, Dict, Any

from app.database.session import get_db
from app.auth.security import get_service_or_user_id, get_authenticated_user_id
from app.services.retention_service import RetentionService
from app.config import settings

router = APIRouter()


@router.post("/retention/run", status_code=status.HTTP_200_OK)
def run_retention_lifecycle(
    max_scan_days: Optional[int] = None,
    max_artifact_days: Optional[int] = None,
    max_audit_days: Optional[int] = None,
    caller_id: str = Depends(get_service_or_user_id),
    db: Session = Depends(get_db),
):
    """
    Executes automated data retention lifecycle cleanup.
    Restricted to internal service token or service_role credentials.
    """
    if caller_id != "service_role":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Retention maintenance tasks require internal service role authorization",
        )

    retention_svc = RetentionService(db)
    artifacts_pruned = retention_svc.cleanup_expired_artifacts(max_age_days=max_artifact_days)
    scans_pruned = retention_svc.cleanup_expired_scans(max_age_days=max_scan_days, preserve_audit_events=True)
    audit_events_pruned = retention_svc.cleanup_expired_audit_events(max_age_days=max_audit_days)
    temp_files_pruned = retention_svc.cleanup_temp_files()

    return {
        "status": "completed",
        "artifacts_pruned": artifacts_pruned,
        "scans_pruned": scans_pruned,
        "audit_events_pruned": audit_events_pruned,
        "temp_files_pruned": temp_files_pruned,
    }


@router.post("/reconcile-stuck", status_code=status.HTTP_200_OK)
def reconcile_stuck_scans(
    timeout_minutes: Optional[int] = None,
    caller_id: str = Depends(get_service_or_user_id),
    db: Session = Depends(get_db),
):
    """
    Transitions stuck non-terminal scans (exceeding timeout) to FAILED with ERR_SCAN_TIMEOUT.
    Guarantees no scans remain permanently pending following worker crashes or timeouts.
    """
    if caller_id != "service_role":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Reconciliation maintenance tasks require internal service role authorization",
        )

    retention_svc = RetentionService(db)
    reconciled_count = retention_svc.reconcile_stuck_scans(timeout_minutes=timeout_minutes)

    return {
        "status": "completed",
        "stuck_scans_reconciled": reconciled_count,
    }


@router.delete("/users/{target_user_id}/data", status_code=status.HTTP_200_OK)
def purge_user_data(
    target_user_id: str,
    caller_id: str = Depends(get_service_or_user_id),
    db: Session = Depends(get_db),
):
    """
    Authorized user data purge (GDPR / right-to-be-forgotten):
    Deletes all scans, evidence, findings, assessments, artifacts, and feedback for target_user_id.
    Pseudonymizes security audit log records to preserve non-repudiation audit trails.
    """
    # Allow user to delete their own data, or allow service_role to delete on their behalf
    if caller_id != "service_role" and caller_id != target_user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot purge data belonging to another user",
        )

    retention_svc = RetentionService(db)
    result = retention_svc.purge_user_data(user_id=target_user_id)

    return {
        "status": "completed",
        "user_id": target_user_id,
        "summary": result,
    }


@router.get("/metrics", status_code=status.HTTP_200_OK)
def get_operational_metrics(
    caller_id: str = Depends(get_service_or_user_id),
    db: Session = Depends(get_db),
):
    """
    Returns privacy-preserving operational metrics for pilot monitoring and reliability oversight.
    Restricted to internal service token or service_role credentials.
    Exposes no raw target URLs, private messages, tokens, or personal identifiers.
    """
    if caller_id != "service_role":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operational metrics require internal service role authorization",
        )

    from datetime import datetime, timezone
    from sqlalchemy import func
    from app.models.entities import Scan, RiskAssessment, ScanFeedback, AuditEvent

    # 1. Total counts by input_type
    input_counts = dict(
        db.query(Scan.input_type, func.count(Scan.id))
        .group_by(Scan.input_type)
        .all()
    )

    # 2. Total counts by lifecycle status
    status_counts = dict(
        db.query(Scan.status, func.count(Scan.id))
        .group_by(Scan.status)
        .all()
    )

    # 3. Assessment outcome classifications
    verdict_counts = dict(
        db.query(RiskAssessment.recommended_action, func.count(RiskAssessment.id))
        .group_by(RiskAssessment.recommended_action)
        .all()
    )

    # 4. User feedback summary
    feedback_ratings = dict(
        db.query(ScanFeedback.rating, func.count(ScanFeedback.id))
        .group_by(ScanFeedback.rating)
        .all()
    )

    # 5. Reconciled stuck scans count
    reconciled_events = (
        db.query(func.count(AuditEvent.id))
        .filter(AuditEvent.event_type == "SCAN_TIMEOUT_RECONCILED")
        .scalar() or 0
    )

    return {
        "status": "operational",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scans_by_input_type": input_counts,
        "scans_by_status": status_counts,
        "assessments_by_verdict": verdict_counts,
        "feedback_by_rating": feedback_ratings,
        "reconciled_timeout_events": reconciled_events,
        "pilot_mode_active": settings.PILOT_MODE_ENABLED,
        "emergency_shutdown_active": settings.EMERGENCY_SHUTDOWN,
    }
