"""
Scan Repository
Encapsulates transaction-safe relational database queries, scan ownership enforcement,
and audit logging.
"""
from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import desc

import threading
import logging
from app.models.entities import (
    Scan,
    ScanTask,
    EvidenceRecord,
    FindingRecord,
    RiskAssessment,
    ScanFeedback,
    AuditEvent,
    Artifact,
    UserDailyQuota,
    QuotaRefundRecord,
    ScanStatus,
    TERMINAL_SCAN_STATES,
    VALID_STATUS_TRANSITIONS,
)
from risk_engine.evidence import Evidence, Finding
from app.config import settings

logger = logging.getLogger("thelix.repository.scan")
_quota_lock = threading.RLock()


class ScanRepository:
    """
    Data access layer for scan lifecycle, evidence, findings, and audit records.
    """

    def __init__(self, db: Session):
        self.db = db
        self._cached_scan: Optional[Scan] = None

    def create_scan(
        self,
        scan_id: str,
        user_id: str,
        input_type: str,
        raw_target: str,
        policy_version: str = "1.0.0",
        engine_versions: Optional[Dict[str, str]] = None,
    ) -> Scan:
        if self._cached_scan and self._cached_scan.id == scan_id:
            return self._cached_scan

        existing = self.db.get(Scan, scan_id) if hasattr(self.db, "get") else self.db.query(Scan).filter(Scan.id == scan_id).first()
        if existing:
            self._cached_scan = existing
            return existing

        scan = Scan(
            id=scan_id,
            user_id=user_id,
            input_type=input_type,
            raw_target=raw_target,
            status=ScanStatus.QUEUED.value,
            policy_version=policy_version,
            engine_versions=engine_versions or {},
            created_at=datetime.now(timezone.utc),
        )
        self.db.add(scan)
        self.db.commit()
        self._cached_scan = scan
        return scan

    def create_scan_with_outbox_task(
        self,
        scan_id: str,
        user_id: str,
        input_type: str,
        raw_target: str,
        payload_dict: Dict[str, Any],
        max_attempts: int = 3,
        policy_version: str = "1.0.0",
        engine_versions: Optional[Dict[str, str]] = None,
    ) -> Tuple[Scan, ScanTask]:
        """
        Atomically persists the Scan record (status QUEUED) and its durable ScanTask outbox work item
        in the exact same database transaction.
        Guarantees no committed scan exists without a discoverable durable task.
        """
        scan = Scan(
            id=scan_id,
            user_id=user_id,
            input_type=input_type,
            raw_target=raw_target,
            status=ScanStatus.QUEUED.value,
            policy_version=policy_version,
            engine_versions=engine_versions or {},
            created_at=datetime.now(timezone.utc),
        )
        task = ScanTask(
            scan_id=scan_id,
            engine_name="background_orchestrator",
            status="PENDING",
            attempt_count=0,
            max_attempts=max_attempts,
            payload_json=payload_dict,
        )
        self.db.add(scan)
        self.db.add(task)
        self.db.commit()
        self._cached_scan = scan
        return scan, task

    def claim_next_task(
        self,
        worker_id: str,
        lease_duration_seconds: int = 300,
    ) -> Optional[ScanTask]:
        """
        Safely claims the next available pending or expired-lease durable task.
        Uses PostgreSQL SELECT ... FOR UPDATE SKIP LOCKED when running on PostgreSQL,
        or atomic conditional UPDATE on SQLite.
        Transactions are kept minimal and short: row lock is released immediately after lease claim.
        """
        from datetime import timedelta
        now = datetime.now(timezone.utc)
        lease_expiry = now + timedelta(seconds=lease_duration_seconds)

        # Check database dialect
        bind = self.db.get_bind()
        is_postgres = bool(bind and bind.dialect.name == "postgresql")

        if is_postgres:
            from sqlalchemy import text
            row = self.db.execute(
                text(
                    """
                    SELECT id FROM public.scan_tasks
                    WHERE (status = 'PENDING' OR (status = 'PROCESSING' AND lease_expires_at < :now))
                      AND attempt_count < max_attempts
                    ORDER BY started_at NULLS FIRST, id ASC
                    LIMIT 1
                    FOR UPDATE SKIP LOCKED
                    """
                ),
                {"now": now},
            ).first()

            if not row:
                return None

            task_id = row[0]
            task = self.db.query(ScanTask).filter(ScanTask.id == task_id).first()
            if not task:
                return None

            task.status = "PROCESSING"
            task.lease_owner = worker_id
            task.lease_expires_at = lease_expiry
            task.started_at = now
            task.attempt_count += 1
            self.db.commit()
            return task
        else:
            # SQLite / fallback: atomic conditional update
            from sqlalchemy import or_, and_
            candidates = (
                self.db.query(ScanTask.id)
                .filter(
                    or_(
                        ScanTask.status == "PENDING",
                        and_(ScanTask.status == "PROCESSING", ScanTask.lease_expires_at < now),
                    ),
                    ScanTask.attempt_count < ScanTask.max_attempts,
                )
                .limit(20)
                .all()
            )

            for (cand_id,) in candidates:
                updated = (
                    self.db.query(ScanTask)
                    .filter(
                        ScanTask.id == cand_id,
                        or_(
                            ScanTask.status == "PENDING",
                            and_(ScanTask.status == "PROCESSING", ScanTask.lease_expires_at < now),
                        ),
                    )
                    .update(
                        {
                            ScanTask.status: "PROCESSING",
                            ScanTask.lease_owner: worker_id,
                            ScanTask.lease_expires_at: lease_expiry,
                            ScanTask.started_at: now,
                            ScanTask.attempt_count: ScanTask.attempt_count + 1,
                        },
                        synchronize_session=False,
                    )
                )
                self.db.commit()
                if updated == 1:
                    return self.db.query(ScanTask).filter(ScanTask.id == cand_id).first()

            return None

    def complete_task(
        self,
        task_id: str,
        latency_ms: int = 0,
    ) -> Optional[ScanTask]:
        task = self.db.query(ScanTask).filter(ScanTask.id == task_id).first()
        if not task:
            return None
        task.status = "COMPLETED"
        task.completed_at = datetime.now(timezone.utc)
        task.latency_ms = latency_ms
        task.lease_owner = None
        task.lease_expires_at = None
        self.db.commit()
        return task

    def fail_task_attempt(
        self,
        task_id: str,
        error_code: str,
        error_message: str,
    ) -> Optional[ScanTask]:
        """
        Records attempt failure. If attempt_count >= max_attempts, marks task permanently FAILED.
        Otherwise resets to PENDING so another worker can retry after lease release.
        """
        task = self.db.query(ScanTask).filter(ScanTask.id == task_id).first()
        if not task:
            return None
        now = datetime.now(timezone.utc)
        task.error_code = error_code
        task.error_message = error_message[:500] if error_message else None
        task.lease_owner = None
        task.lease_expires_at = None

        if task.attempt_count >= task.max_attempts:
            task.status = "FAILED"
            task.completed_at = now
        else:
            task.status = "PENDING"

        self.db.commit()
        return task

    def reconcile_expired_exhausted_tasks(self, limit: int = 10) -> int:
        """
        Detects and finalizes tasks that reached attempt_count >= max_attempts whose worker
        died abruptly, leaving the task in PROCESSING with an expired lease.
        Transitions the task and its associated non-terminal scan to FAILED,
        neutralizes the lease, logs an audit event, and idempotently refunds quota.
        """
        now = datetime.now(timezone.utc)
        bind = self.db.get_bind()
        is_postgres = bool(bind and bind.dialect.name == "postgresql")

        reconciled_count = 0

        if is_postgres:
            from sqlalchemy import text
            rows = self.db.execute(
                text(
                    """
                    SELECT id FROM public.scan_tasks
                    WHERE status = 'PROCESSING'
                      AND lease_expires_at < :now
                      AND attempt_count >= max_attempts
                    ORDER BY lease_expires_at ASC
                    LIMIT :limit
                    FOR UPDATE SKIP LOCKED
                    """
                ),
                {"now": now, "limit": limit},
            ).fetchall()

            for (task_id,) in rows:
                task = self.db.query(ScanTask).filter(ScanTask.id == task_id).first()
                if not task:
                    continue
                self._finalize_exhausted_task(task, now)
                reconciled_count += 1
        else:
            # SQLite / dialect fallback: conditional atomic update
            with _quota_lock:
                candidates = (
                    self.db.query(ScanTask.id)
                    .filter(
                        ScanTask.status == "PROCESSING",
                        ScanTask.lease_expires_at < now,
                        ScanTask.attempt_count >= ScanTask.max_attempts,
                    )
                    .limit(limit)
                    .all()
                )

                for (cand_id,) in candidates:
                    try:
                        updated = (
                            self.db.query(ScanTask)
                            .filter(
                                ScanTask.id == cand_id,
                                ScanTask.status == "PROCESSING",
                                ScanTask.lease_expires_at < now,
                                ScanTask.attempt_count >= ScanTask.max_attempts,
                            )
                            .update(
                                {
                                    ScanTask.status: "FAILED",
                                    ScanTask.error_code: "TASK_MAX_RETRIES_EXCEEDED",
                                    ScanTask.error_message: "Worker process terminated abruptly on final attempt; lease expired.",
                                    ScanTask.completed_at: now,
                                    ScanTask.lease_owner: None,
                                    ScanTask.lease_expires_at: None,
                                },
                                synchronize_session=False,
                            )
                        )
                        self.db.commit()
                        if updated == 1:
                            task = self.db.query(ScanTask).filter(ScanTask.id == cand_id).first()
                            if task:
                                self._finalize_exhausted_scan_and_quota(task, now)
                            reconciled_count += 1
                    except Exception as e:
                        self.db.rollback()
                        logger.warning(f"Concurrent update conflict in reconcile_expired_exhausted_tasks: {e}")

        return reconciled_count

    def _finalize_exhausted_task(self, task: ScanTask, now: datetime):
        task.status = "FAILED"
        task.error_code = "TASK_MAX_RETRIES_EXCEEDED"
        task.error_message = "Worker process terminated abruptly on final attempt; lease expired."
        task.completed_at = now
        task.lease_owner = None
        task.lease_expires_at = None
        self.db.commit()
        self._finalize_exhausted_scan_and_quota(task, now)

    def _finalize_exhausted_scan_and_quota(self, task: ScanTask, now: datetime):
        scan = self.db.query(Scan).filter(Scan.id == task.scan_id).first()
        if not scan:
            return

        current_status = scan.status.upper() if scan.status else ""
        if current_status not in TERMINAL_SCAN_STATES:
            # Safely transition scan to FAILED
            scan.status = ScanStatus.FAILED.value
            scan.completed_at = now
            self.record_audit_event(
                "SCAN_FAILED",
                scan_id=scan.id,
                user_id=scan.user_id,
                details={
                    "error_code": "TASK_MAX_RETRIES_EXCEEDED",
                    "error_message": "Task exceeded maximum retry attempts and worker lease expired.",
                },
            )
            self.db.commit()

            # Refund quota idempotently if pilot mode is enabled
            if settings.PILOT_MODE_ENABLED:
                date_key = scan.created_at.strftime("%Y-%m-%d")
                self.refund_daily_scan_quota(user_id=scan.user_id, date_key=date_key, scan_id=scan.id)

    def update_scan_status(
        self,
        scan_id: str,
        status: str,
        normalized_target: Optional[str] = None,
        completed_at: Optional[datetime] = None,
        force: bool = False,
    ) -> Optional[Scan]:
        """
        Transitions scan status safely according to the scan state machine.
        Guarantees terminal states cannot be overwritten and invalid transitions are rejected.
        """
        if self._cached_scan and self._cached_scan.id == scan_id:
            scan = self._cached_scan
        else:
            scan = self.db.get(Scan, scan_id) if hasattr(self.db, "get") else self.db.query(Scan).filter(Scan.id == scan_id).first()
            self._cached_scan = scan

        if not scan:
            return None

        current = scan.status.upper() if scan.status else ScanStatus.QUEUED.value
        target_status = status.upper()

        # Terminal state protection
        if current in TERMINAL_SCAN_STATES and not force:
            logger.warning(
                f"Scan {scan_id} is in terminal state '{current}'; ignoring requested transition to '{target_status}'"
            )
            return scan

        # Transition validation
        if current != target_status and not force:
            allowed = VALID_STATUS_TRANSITIONS.get(current, set())
            if target_status not in allowed:
                logger.warning(
                    f"Invalid state transition rejected for scan {scan_id}: '{current}' -> '{target_status}'"
                )
                return scan

        scan.status = target_status
        if normalized_target:
            scan.normalized_target = normalized_target
        if completed_at:
            scan.completed_at = completed_at
        elif target_status in TERMINAL_SCAN_STATES and not scan.completed_at:
            scan.completed_at = datetime.now(timezone.utc)

        self.db.commit()
        return scan

    def fail_scan(
        self,
        scan_id: str,
        error_code: str,
        error_message: str,
        engine_name: str = "orchestrator",
    ) -> Optional[Scan]:
        """
        Atomically marks a scan as FAILED, records the task failure reason,
        and logs an audit event.
        """
        scan = self.update_scan_status(
            scan_id=scan_id,
            status=ScanStatus.FAILED.value,
            completed_at=datetime.now(timezone.utc),
            force=True,
        )
        if scan:
            self.record_task(
                scan_id=scan_id,
                engine_name=engine_name,
                status="FAILED",
                error_code=error_code,
                error_message=error_message,
            )
            self.record_audit_event(
                "SCAN_FAILED",
                scan_id=scan_id,
                user_id=scan.user_id,
                details={"error_code": error_code, "error_message": error_message[:200]},
            )
        return scan

    def record_task(
        self,
        scan_id: str,
        engine_name: str,
        status: str,
        started_at: Optional[datetime] = None,
        completed_at: Optional[datetime] = None,
        latency_ms: int = 0,
        error_code: Optional[str] = None,
        error_message: Optional[str] = None,
    ) -> ScanTask:
        task = ScanTask(
            scan_id=scan_id,
            engine_name=engine_name,
            status=status,
            started_at=started_at,
            completed_at=completed_at,
            latency_ms=latency_ms,
            error_code=error_code,
            error_message=error_message,
        )
        self.db.add(task)
        self.db.commit()
        return task

    def save_evidence_and_findings(
        self,
        scan_id: str,
        evidence_list: List[Evidence],
        findings_list: List[Finding],
    ):
        for e in evidence_list:
            ev_rec = EvidenceRecord(
                id=e.evidence_id,
                scan_id=scan_id,
                indicator_type=e.indicator_type,
                indicator_value_or_reference=e.indicator_value_or_reference,
                source_engine=e.source_engine,
                source_version=e.source_version,
                reliability=e.reliability,
                confidence=e.confidence,
                correlation_group=e.correlation_group,
                observation_json=e.observation,
                created_at=e.observed_at,
            )
            self.db.add(ev_rec)

        for f in findings_list:
            fn_rec = FindingRecord(
                scan_id=scan_id,
                finding_code=f.finding_code,
                title=f.title,
                description=f.description,
                severity=f.severity.value,
                confidence=f.confidence,
                source_engine=f.source_engine,
                source_version=f.source_version,
                correlation_group=f.correlation_group,
                evidence_refs_json=f.evidence_references,
            )
            self.db.add(fn_rec)

        self.db.commit()

    def save_risk_assessment(
        self,
        scan_id: str,
        risk_score: int,
        trust_score: int,
        risk_level: str,
        confidence: float,
        coverage_ratio: float,
        recommended_action: str,
        summary: str,
        explanation: Optional[str] = None,
    ) -> RiskAssessment:
        assessment = RiskAssessment(
            scan_id=scan_id,
            risk_score=risk_score,
            trust_score=trust_score,
            risk_level=risk_level,
            confidence=confidence,
            coverage_ratio=coverage_ratio,
            recommended_action=recommended_action,
            summary=summary,
            explanation=explanation,
            created_at=datetime.now(timezone.utc),
        )
        self.db.add(assessment)
        self.db.commit()
        return assessment

    def get_scan(self, scan_id: str, user_id: Optional[str] = None) -> Optional[Scan]:
        if self._cached_scan and self._cached_scan.id == scan_id:
            if user_id is None or self._cached_scan.user_id == user_id:
                return self._cached_scan
        scan = self.db.get(Scan, scan_id) if hasattr(self.db, "get") else self.db.query(Scan).filter(Scan.id == scan_id).first()
        if scan and (user_id is None or scan.user_id == user_id):
            self._cached_scan = scan
            return scan
        return None

    def list_scans(self, user_id: str, limit: int = 50, offset: int = 0) -> List[Scan]:
        return (
            self.db.query(Scan)
            .filter(Scan.user_id == user_id)
            .order_by(desc(Scan.created_at))
            .offset(offset)
            .limit(limit)
            .all()
        )

    def delete_scan(self, scan_id: str, user_id: str) -> bool:
        scan = self.get_scan(scan_id=scan_id, user_id=user_id)
        if not scan:
            return False
        self.db.delete(scan)
        self.db.commit()
        if self._cached_scan and self._cached_scan.id == scan_id:
            self._cached_scan = None
        return True

    def add_feedback(
        self, scan_id: str, user_id: str, rating: str, comments: Optional[str] = None
    ) -> ScanFeedback:
        existing = (
            self.db.query(ScanFeedback)
            .filter(ScanFeedback.scan_id == scan_id, ScanFeedback.user_id == user_id)
            .first()
        )
        if existing:
            existing.rating = rating
            existing.comments = comments
            self.db.commit()
            return existing

        feedback = ScanFeedback(
            scan_id=scan_id,
            user_id=user_id,
            rating=rating,
            comments=comments,
            created_at=datetime.now(timezone.utc),
        )
        self.db.add(feedback)
        self.db.commit()
        return feedback

    def record_audit_event(
        self,
        event_type: str,
        scan_id: Optional[str] = None,
        user_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        event = AuditEvent(
            scan_id=scan_id,
            user_id=user_id,
            event_type=event_type,
            details_json=details or {},
            created_at=datetime.now(timezone.utc),
        )
        self.db.add(event)
        self.db.commit()
        return event

    def get_audit_events(self, scan_id: str) -> List[AuditEvent]:
        return (
            self.db.query(AuditEvent)
            .filter(AuditEvent.scan_id == scan_id)
            .order_by(AuditEvent.created_at)
            .all()
        )

    def add_artifact(
        self,
        scan_id: str,
        artifact_type: str,
        storage_path: str,
        mime_type: str,
        file_size_bytes: int,
        file_hash: Optional[str] = None,
    ) -> Artifact:
        artifact = Artifact(
            scan_id=scan_id,
            artifact_type=artifact_type,
            storage_path=storage_path,
            mime_type=mime_type,
            file_size_bytes=file_size_bytes,
            file_hash=file_hash,
            created_at=datetime.now(timezone.utc),
        )
        self.db.add(artifact)
        self.db.commit()
        self.db.refresh(artifact)
        return artifact

    def count_user_scans_since(self, user_id: str, since: datetime) -> int:
        """Counts the total number of scans initiated by user_id since the specified timestamp."""
        return (
            self.db.query(Scan)
            .filter(Scan.user_id == user_id, Scan.created_at >= since)
            .count()
        )

    def clear_cache(self) -> None:
        """Clears cached in-memory scan entity to ensure identity-map consistency."""
        self._cached_scan = None

    def reserve_daily_scan_quota(self, user_id: str, date_key: str, limit: int) -> bool:
        """
        Atomically increments and reserves a scan quota slot for the user for the given date.
        Uses thread-safe locking and an atomic database-level conditional update to guarantee
        concurrency safety across multiple threads and worker processes.
        Returns True if reservation succeeded within limit, False if quota exceeded.
        """
        with _quota_lock:
            for attempt in range(2):
                try:
                    record = self.db.query(UserDailyQuota).filter(
                        UserDailyQuota.user_id == user_id,
                        UserDailyQuota.date_key == date_key,
                    ).first()

                    if not record:
                        today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
                        existing_scans = self.count_user_scans_since(user_id=user_id, since=today_start)
                        try:
                            record = UserDailyQuota(
                                user_id=user_id,
                                date_key=date_key,
                                scan_count=existing_scans,
                            )
                            self.db.add(record)
                            self.db.commit()
                        except Exception:
                            self.db.rollback()

                    # Execute atomic database-level conditional update
                    updated = self.db.query(UserDailyQuota).filter(
                        UserDailyQuota.user_id == user_id,
                        UserDailyQuota.date_key == date_key,
                        UserDailyQuota.scan_count < limit,
                    ).update(
                        {
                            UserDailyQuota.scan_count: UserDailyQuota.scan_count + 1,
                            UserDailyQuota.updated_at: datetime.now(timezone.utc),
                        },
                        synchronize_session=False,
                    )
                    self.db.commit()
                    if updated > 0:
                        return True

                    row = self.db.query(UserDailyQuota).filter(
                        UserDailyQuota.user_id == user_id,
                        UserDailyQuota.date_key == date_key,
                    ).first()
                    if row and row.scan_count >= limit:
                        return False
                except Exception:
                    self.db.rollback()
                    if attempt == 1:
                        raise
            return False

    def refund_daily_scan_quota(
        self, user_id: str, date_key: str, scan_id: Optional[str] = None
    ) -> bool:
        """
        Rolls back 1 quota reservation in the event of an immediate validation rejection,
        failure, or timeout reconciliation.
        Guarantees:
        - When scan_id is provided, refunds are strictly idempotent: duplicate refund calls
          cannot double-credit quota.
        - Counter cannot decrement below zero.
        - Database state transitions atomically in a single transaction.
        Returns True if a reservation was refunded, False if already refunded, quota was already 0, or no row existed.
        """
        with _quota_lock:
            try:
                if scan_id:
                    # Check for existing refund record
                    existing_refund = self.db.query(QuotaRefundRecord).filter(
                        QuotaRefundRecord.scan_id == scan_id
                    ).first()
                    if existing_refund:
                        logger.info(f"Scan {scan_id} was already refunded; skipping duplicate refund.")
                        return False

                    # Attempt to record refund intent under unique scan_id constraint
                    refund_record = QuotaRefundRecord(
                        scan_id=scan_id,
                        user_id=user_id,
                        date_key=date_key,
                        refunded_at=datetime.now(timezone.utc),
                    )
                    self.db.add(refund_record)
                    try:
                        self.db.flush()
                    except Exception:
                        self.db.rollback()
                        logger.info(f"Concurrent refund collision for scan {scan_id}; aborted duplicate refund.")
                        return False

                updated = self.db.query(UserDailyQuota).filter(
                    UserDailyQuota.user_id == user_id,
                    UserDailyQuota.date_key == date_key,
                    UserDailyQuota.scan_count > 0,
                ).update(
                    {
                        UserDailyQuota.scan_count: UserDailyQuota.scan_count - 1,
                        UserDailyQuota.updated_at: datetime.now(timezone.utc),
                    },
                    synchronize_session="fetch",
                )

                if scan_id:
                    audit_event = AuditEvent(
                        scan_id=scan_id,
                        user_id=user_id,
                        event_type="QUOTA_REFUNDED",
                        details_json={
                            "date_key": date_key,
                            "refunded_at": datetime.now(timezone.utc).isoformat(),
                            "quota_decremented": bool(updated > 0),
                        },
                        created_at=datetime.now(timezone.utc),
                    )
                    self.db.add(audit_event)

                self.db.commit()
                self.db.expire_all()
                return updated > 0
            except Exception:
                self.db.rollback()
                raise



