"""
Durable Background Scan Worker Service
Provides autonomous, transaction-safe task polling, claiming, lease expiration recovery,
idempotent execution, and bounded retry policy for asynchronous Thelix AI scans.
"""
import time
import uuid
import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session

from app.config import settings
from app.database.session import SessionLocal
from app.models.entities import Scan, ScanTask, ScanStatus, TERMINAL_SCAN_STATES
from app.repositories.scan_repository import ScanRepository
from app.services.orchestrator_service import OrchestratorService

logger = logging.getLogger("thelix.worker.scan")


class DurableScanWorker:
    """
    Durable background scan worker that claims and processes queued scans independently
    of the FastAPI request process.
    """

    def __init__(
        self,
        worker_id: Optional[str] = None,
        lease_duration_seconds: int = 300,
        poll_interval_seconds: float = 2.0,
    ):
        self.worker_id = worker_id or f"worker-{uuid.uuid4().hex[:8]}"
        self.lease_duration_seconds = lease_duration_seconds
        self.poll_interval_seconds = poll_interval_seconds
        self._is_running = False

    async def process_one(self, db: Optional[Session] = None) -> bool:
        """
        Polls and executes a single durable scan task.
        Returns True if a task was claimed and processed, False if queue was empty.
        """
        owns_db = False
        if db is None:
            db = SessionLocal()
            owns_db = True

        try:
            repo = ScanRepository(db)
            # Reconcile any expired exhausted tasks left by crashed workers
            reconciled = repo.reconcile_expired_exhausted_tasks(limit=5)
            if reconciled > 0:
                logger.info(f"Worker '{self.worker_id}' reconciled {reconciled} expired exhausted task(s).")

            task = repo.claim_next_task(
                worker_id=self.worker_id,
                lease_duration_seconds=self.lease_duration_seconds,
            )

            if not task:
                return bool(reconciled > 0)

            task_id = task.id
            scan_id = task.scan_id
            payload = task.payload_json or {}
            attempt = task.attempt_count
            max_att = task.max_attempts

            logger.info(
                f"Worker '{self.worker_id}' claimed task {task_id} for scan {scan_id} "
                f"(attempt {attempt}/{max_att})"
            )

            # Check scan status: idempotent protection against duplicate execution
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if not scan or scan.status in TERMINAL_SCAN_STATES:
                logger.info(
                    f"Scan {scan_id} is already in terminal state or missing; completing task {task_id} idempotently."
                )
                repo.complete_task(task_id)
                return True

            # Safely transition scan status to PROCESSING
            repo.update_scan_status(scan_id, ScanStatus.PROCESSING.value)

            target_url = payload.get("target_url") or scan.raw_target
            user_id = payload.get("user_id") or scan.user_id
            context = payload.get("context")
            enable_sandbox = payload.get("enable_sandbox", True)

            t0 = time.time()
            try:
                orchestrator = OrchestratorService(db=db)
                await orchestrator.execute_url_scan(
                    target_url=target_url,
                    user_id=user_id,
                    scan_id=scan_id,
                    context=context,
                    enable_sandbox=enable_sandbox,
                )
                dur = int((time.time() - t0) * 1000)
                repo.complete_task(task_id, latency_ms=dur)
                logger.info(f"Worker '{self.worker_id}' successfully completed scan {scan_id} in {dur}ms")
            except Exception as exc:
                dur = int((time.time() - t0) * 1000)
                err_msg = str(exc)[:500]
                logger.error(f"Worker '{self.worker_id}' failed processing scan {scan_id}: {exc}", exc_info=True)

                failed_task = repo.fail_task_attempt(
                    task_id=task_id,
                    error_code="WORKER_TASK_FAILED",
                    error_message=err_msg,
                )

                if failed_task and failed_task.status == "FAILED":
                    # Max retries exhausted: mark scan permanently FAILED and refund quota
                    logger.warning(
                        f"Scan {scan_id} exceeded max retry attempts ({max_att}); transitioning to FAILED."
                    )
                    repo.fail_scan(
                        scan_id=scan_id,
                        error_code="TASK_MAX_RETRIES_EXCEEDED",
                        error_message=err_msg,
                        engine_name="durable_worker",
                    )
                    if settings.PILOT_MODE_ENABLED:
                        date_key = scan.created_at.strftime("%Y-%m-%d")
                        repo.refund_daily_scan_quota(user_id=scan.user_id, date_key=date_key, scan_id=scan.id)

            return True
        finally:
            if owns_db:
                db.close()

    async def run_loop(self, stop_event: Optional[asyncio.Event] = None):
        """
        Runs continuous polling loop until stop_event is set.
        """
        self._is_running = True
        logger.info(
            f"Starting DurableScanWorker '{self.worker_id}' (poll interval: {self.poll_interval_seconds}s, "
            f"lease: {self.lease_duration_seconds}s)"
        )

        while self._is_running:
            if stop_event and stop_event.is_set():
                break

            try:
                processed = await self.process_one()
                if not processed:
                    # Queue is empty, sleep for poll interval
                    await asyncio.sleep(self.poll_interval_seconds)
            except Exception as e:
                logger.error(f"Unexpected worker loop exception in '{self.worker_id}': {e}", exc_info=True)
                await asyncio.sleep(self.poll_interval_seconds)

        self._is_running = False
        logger.info(f"DurableScanWorker '{self.worker_id}' stopped cleanly.")

    def stop(self):
        self._is_running = False
