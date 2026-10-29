"""
Retention Service
Manages data retention lifecycles, artifact pruning, stuck scan reconciliation,
audit trail preservation, and authorized user data purges.
"""
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone, timedelta
import os
import shutil
import glob
import logging
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.models.entities import (
    Scan,
    ScanTask,
    Artifact,
    AuditEvent,
    ScanFeedback,
    ScanStatus,
    TERMINAL_SCAN_STATES,
)
from app.config import settings

logger = logging.getLogger("thelix.retention")


class RetentionService:
    """
    Executes automated and scheduled lifecycle policies:
    - Pruning of expired scan records according to SCAN_RETENTION_DAYS.
    - Pruning of expired inspection artifacts according to ARTIFACT_RETENTION_DAYS.
    - Pruning of expired audit logs according to AUDIT_LOG_RETENTION_DAYS.
    - Anonymizing/disassociating audit records to preserve security audit logs.
    - Cleaning up temporary disk files older than TTL.
    - Reconciling stuck scans (in-flight when server crashed/restarted).
    - Authorized user deletion (GDPR / right to be forgotten).
    """

    def __init__(self, db: Session):
        self.db = db

    def cleanup_expired_artifacts(self, max_age_days: Optional[int] = None) -> int:
        """
        Deletes artifacts older than the retention threshold or past their retention_until date.
        Removes both physical storage files (if on disk) and relational database records.
        """
        days = max_age_days if max_age_days is not None else settings.ARTIFACT_RETENTION_DAYS
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        now = datetime.now(timezone.utc)
        expired_artifacts = (
            self.db.query(Artifact)
            .filter((Artifact.created_at < cutoff) | ((Artifact.retention_until != None) & (Artifact.retention_until <= now)))
            .all()
        )

        deleted_count = 0
        for artifact in expired_artifacts:
            # If artifact was saved to local disk, safely remove file
            if artifact.storage_path and os.path.exists(artifact.storage_path):
                try:
                    os.remove(artifact.storage_path)
                    logger.info(f"Removed expired artifact disk file: {artifact.storage_path}")
                except OSError as e:
                    logger.warning(f"Could not delete physical artifact file {artifact.storage_path}: {e}")

            self.db.delete(artifact)
            deleted_count += 1

        if deleted_count > 0:
            self.db.commit()
            logger.info(f"Purged {deleted_count} expired artifacts (cutoff: {cutoff.isoformat()})")

        return deleted_count

    @staticmethod
    def _sanitize_audit_details(details: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitizes audit details dictionary by scrubbing private scan targets,
        raw URLs, filenames, and prompts, replacing them with irreversible truncated hashes.
        """
        import hashlib
        sanitized = dict(details or {})
        sensitive_keys = ["target", "target_url", "raw_target", "url", "filename", "user_prompt", "content"]
        for key in sensitive_keys:
            if key in sanitized:
                val = str(sanitized.pop(key))
                sanitized[f"{key}_hash"] = hashlib.sha256(val.encode("utf-8")).hexdigest()[:16]
        return sanitized

    def cleanup_expired_scans(self, max_age_days: Optional[int] = None, preserve_audit_events: bool = True) -> int:
        """
        Purges completed or terminal scans older than SCAN_RETENTION_DAYS.
        If preserve_audit_events is True, audit records are uncoupled (scan_id set to None)
        so security audit history remains intact while private scan content is destroyed.
        """
        days = max_age_days if max_age_days is not None else settings.SCAN_RETENTION_DAYS
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        expired_scans = (
            self.db.query(Scan)
            .filter(Scan.created_at < cutoff)
            .all()
        )

        deleted_count = 0
        for scan in expired_scans:
            if preserve_audit_events:
                # Disassociate audit events before deleting scan to avoid cascading deletion
                for event in list(scan.audit_events):
                    event.scan_id = None
                    details = self._sanitize_audit_details(event.details_json)
                    if "preserved_scan_reference" not in details:
                        details["original_scan_id_hash"] = scan.id[:8] + "..."
                        details["scan_retention_purged_at"] = datetime.now(timezone.utc).isoformat()
                    event.details_json = details
                self.db.flush()

            self.db.delete(scan)
            deleted_count += 1

        if deleted_count > 0:
            self.db.commit()
            logger.info(f"Purged {deleted_count} expired scans (cutoff: {cutoff.isoformat()})")

        return deleted_count

    def cleanup_expired_audit_events(self, max_age_days: Optional[int] = None) -> int:
        """
        Purges audit logs that have exceeded the compliance audit retention window (e.g. 90 days).
        Ensures audit records are never prematurely deleted.
        """
        days = max_age_days if max_age_days is not None else settings.AUDIT_LOG_RETENTION_DAYS
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        expired_events = (
            self.db.query(AuditEvent)
            .filter(AuditEvent.created_at < cutoff)
            .all()
        )

        deleted_count = len(expired_events)
        for event in expired_events:
            self.db.delete(event)

        if deleted_count > 0:
            self.db.commit()
            logger.info(f"Purged {deleted_count} expired audit events (cutoff: {cutoff.isoformat()})")

        return deleted_count

    def cleanup_temp_files(self, temp_patterns: Optional[List[str]] = None, max_age_seconds: int = 3600) -> int:
        """
        Cleans up abandoned scratch files, staged uploads, or disposable sandbox directories
        older than max_age_seconds.
        """
        import tempfile
        sys_temp = tempfile.gettempdir()
        patterns = temp_patterns or [
            os.path.join(sys_temp, "thelix_sandbox_profile_*"),
            os.path.join(sys_temp, "thelix_upload_*"),
        ]

        now = datetime.now(timezone.utc).timestamp()
        removed_count = 0

        for pattern in patterns:
            for item in glob.glob(pattern):
                try:
                    mtime = os.path.getmtime(item)
                    if (now - mtime) > max_age_seconds:
                        if os.path.isdir(item):
                            shutil.rmtree(item, ignore_errors=True)
                        else:
                            os.remove(item)
                        removed_count += 1
                except Exception as e:
                    logger.warning(f"Error cleaning temp item {item}: {e}")

        return removed_count

    def reconcile_stuck_scans(self, timeout_minutes: Optional[int] = None) -> int:
        """
        Detects scans left in non-terminal states (QUEUED, VALIDATING, EXTRACTING, PROCESSING,
        ANALYZING, AGGREGATING) that have exceeded the timeout threshold, and expired exhausted tasks.
        Transitions them to FAILED with ERR_SCAN_TIMEOUT / TASK_MAX_RETRIES_EXCEEDED so they never stay permanently pending.
        """
        from app.repositories.scan_repository import ScanRepository
        repo = ScanRepository(self.db)
        exhausted_tasks_reconciled = repo.reconcile_expired_exhausted_tasks(limit=50)

        minutes = timeout_minutes if timeout_minutes is not None else settings.STUCK_SCAN_TIMEOUT_MINUTES
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)

        non_terminal = (
            self.db.query(Scan)
            .filter(Scan.status.notin_(TERMINAL_SCAN_STATES), Scan.created_at < cutoff)
            .all()
        )

        reconciled_count = 0
        for scan in non_terminal:
            # Active lease protection: do not mark a live, valid leased task failed merely because its scan is old
            active_lease = (
                self.db.query(ScanTask)
                .filter(
                    ScanTask.scan_id == scan.id,
                    ScanTask.status == "PROCESSING",
                    ScanTask.lease_expires_at > datetime.now(timezone.utc),
                )
                .first()
            )
            if active_lease:
                logger.info(
                    f"Scan {scan.id} is actively leased to worker '{active_lease.lease_owner}' until "
                    f"{active_lease.lease_expires_at}; skipping reconciliation."
                )
                continue

            prev_status = scan.status

            # Atomic conditional update at database level: only transition if STILL non-terminal
            updated = (
                self.db.query(Scan)
                .filter(
                    Scan.id == scan.id,
                    Scan.status.notin_(TERMINAL_SCAN_STATES),
                )
                .update(
                    {
                        Scan.status: ScanStatus.FAILED.value,
                        Scan.completed_at: datetime.now(timezone.utc),
                    },
                    synchronize_session=False,
                )
            )

            # If updated == 0, another worker transitioned scan to terminal state (e.g. COMPLETED)
            if updated == 0:
                logger.info(
                    f"Scan {scan.id} already transitioned to terminal state or reconciled by another worker; skipping."
                )
                continue

            # Mark associated non-terminal tasks as FAILED so they do not remain permanently pending/processing
            self.db.query(ScanTask).filter(
                ScanTask.scan_id == scan.id,
                ScanTask.status.notin_(["COMPLETED", "FAILED", "CANCELLED"]),
            ).update(
                {
                    ScanTask.status: "FAILED",
                    ScanTask.error_code: "ERR_SCAN_TIMEOUT",
                    ScanTask.error_message: "Scan exceeded processing time limit; reconciled to failure.",
                    ScanTask.completed_at: datetime.now(timezone.utc),
                    ScanTask.lease_owner: None,
                    ScanTask.lease_expires_at: None,
                },
                synchronize_session=False,
            )

            # Record timeout audit event
            timeout_event = AuditEvent(
                scan_id=scan.id,
                user_id=scan.user_id,
                event_type="SCAN_TIMEOUT_RECONCILED",
                details_json={
                    "previous_status": prev_status,
                    "timeout_threshold_minutes": minutes,
                    "error_code": "ERR_SCAN_TIMEOUT",
                    "reason": "Scan exceeded processing time limit or worker process was restarted.",
                },
                created_at=datetime.now(timezone.utc),
            )
            self.db.add(timeout_event)

            # Stage G: Refund daily quota if pilot mode is enabled so worker crashes do not burn quota
            if settings.PILOT_MODE_ENABLED:
                date_key = scan.created_at.strftime("%Y-%m-%d")
                repo.refund_daily_scan_quota(user_id=scan.user_id, date_key=date_key, scan_id=scan.id)

            reconciled_count += 1
            logger.warning(f"Reconciled stuck scan {scan.id} (was '{prev_status}') -> FAILED (ERR_SCAN_TIMEOUT)")

        if reconciled_count > 0:
            self.db.commit()

        return reconciled_count + exhausted_tasks_reconciled

    def purge_user_data(self, user_id: str) -> Dict[str, int]:
        """
        Executes authorized user right-to-be-forgotten / deletion request:
        - Deletes all user scans and cascaded evidence, findings, assessments, artifacts.
        - Deletes user feedback.
        - Pseudonymizes audit logs (user_id -> 'ANONYMIZED_USER') to maintain security audit compliance.
        """
        # Find scans
        user_scans = self.db.query(Scan).filter(Scan.user_id == user_id).all()
        scans_count = len(user_scans)
        for s in user_scans:
            # Clean artifact disk files if any
            for art in s.artifacts:
                if art.storage_path and os.path.exists(art.storage_path):
                    try:
                        os.remove(art.storage_path)
                    except OSError:
                        pass
            self.db.delete(s)

        # Find feedback
        feedback_items = self.db.query(ScanFeedback).filter(ScanFeedback.user_id == user_id).all()
        feedback_count = len(feedback_items)
        for fb in feedback_items:
            self.db.delete(fb)

        # Pseudonymize audit events and scrub sensitive target details
        audit_events = self.db.query(AuditEvent).filter(AuditEvent.user_id == user_id).all()
        audit_count = len(audit_events)
        for ev in audit_events:
            ev.user_id = "ANONYMIZED_USER"
            ev.scan_id = None
            details = self._sanitize_audit_details(ev.details_json)
            details["user_purged_at"] = datetime.now(timezone.utc).isoformat()
            ev.details_json = details

        self.db.commit()
        logger.info(f"Purged user {user_id} data: {scans_count} scans, {feedback_count} feedback, {audit_count} audit logs pseudonymized.")
        return {
            "scans_deleted": scans_count,
            "feedback_deleted": feedback_count,
            "audit_records_pseudonymized": audit_count,
        }
