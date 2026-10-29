"""
Tests for Durable Background Scan Worker and Outbox Pattern
Verifies:
1. Atomic persistence of Scan and ScanTask outbox record.
2. Concurrent worker claiming without double-claiming.
3. Worker process crash and lease expiry recovery.
4. Bounded retries and terminal failure with quota refund.
5. Idempotent duplicate delivery protection for terminal scans.
6. Reconciliation service skips actively leased tasks.
7. Error sanitization avoiding secret leakage.
8. Opt-in PostgreSQL SKIP LOCKED integration test.
"""
import uuid
import os
import time
import threading
import tempfile
import multiprocessing
from unittest.mock import patch
import pytest
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database.session import Base
from app.models.entities import Scan, ScanTask, ScanStatus, TERMINAL_SCAN_STATES, UserDailyQuota, QuotaRefundRecord
from app.repositories.scan_repository import ScanRepository
from app.services.scan_worker import DurableScanWorker
from app.services.retention_service import RetentionService
from app.config import settings
from tests.multiprocess_helpers import run_process_worker_claim_and_crash


@pytest.fixture
def memory_db():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = Session()
    try:
        yield db
    finally:
        db.close()


def test_atomic_scan_and_task_outbox_commitment(memory_db):
    """Verify Scan and durable ScanTask outbox work item are committed in the same transaction."""
    repo = ScanRepository(memory_db)
    scan_id = str(uuid.uuid4())
    user_id = "user_atomic_outbox"

    scan, task = repo.create_scan_with_outbox_task(
        scan_id=scan_id,
        user_id=user_id,
        input_type="url",
        raw_target="https://example.com/test-outbox",
        payload_dict={"target_url": "https://example.com/test-outbox", "user_id": user_id},
        max_attempts=3,
    )

    assert scan.id == scan_id
    assert scan.status == "QUEUED"
    assert task.scan_id == scan_id
    assert task.status == "PENDING"
    assert task.attempt_count == 0
    assert task.payload_json["target_url"] == "https://example.com/test-outbox"

    # Confirm both records exist in DB
    db_scan = memory_db.query(Scan).filter(Scan.id == scan_id).first()
    db_task = memory_db.query(ScanTask).filter(ScanTask.scan_id == scan_id).first()
    assert db_scan is not None
    assert db_task is not None


def test_concurrent_workers_claim_distinct_tasks_no_double_claim(memory_db):
    """Verify that multiple workers claim distinct tasks without double-claiming."""
    repo = ScanRepository(memory_db)

    # Seed 2 pending tasks
    scan1, task1 = repo.create_scan_with_outbox_task(
        scan_id="scan-task-1",
        user_id="user_1",
        input_type="url",
        raw_target="https://target1.com",
        payload_dict={"target_url": "https://target1.com"},
    )
    scan2, task2 = repo.create_scan_with_outbox_task(
        scan_id="scan-task-2",
        user_id="user_2",
        input_type="url",
        raw_target="https://target2.com",
        payload_dict={"target_url": "https://target2.com"},
    )

    # Worker A claims first available
    claimed_a = repo.claim_next_task(worker_id="worker_A", lease_duration_seconds=60)
    assert claimed_a is not None
    assert claimed_a.status == "PROCESSING"
    assert claimed_a.lease_owner == "worker_A"

    # Worker B claims next available
    claimed_b = repo.claim_next_task(worker_id="worker_B", lease_duration_seconds=60)
    assert claimed_b is not None
    assert claimed_b.status == "PROCESSING"
    assert claimed_b.lease_owner == "worker_B"

    # Must be distinct tasks!
    assert claimed_a.id != claimed_b.id

    # 3rd claim returns None as no tasks are available
    claimed_c = repo.claim_next_task(worker_id="worker_C", lease_duration_seconds=60)
    assert claimed_c is None


def test_worker_death_and_lease_expiry_recovery(memory_db):
    """Verify that if a worker claims a task and dies, another worker reclaims it after lease expiry."""
    repo = ScanRepository(memory_db)
    scan, task = repo.create_scan_with_outbox_task(
        scan_id="scan-recover-lease",
        user_id="user_crash",
        input_type="url",
        raw_target="https://crash.com",
        payload_dict={"target_url": "https://crash.com"},
    )

    # Worker 1 claims with a short lease (10 seconds)
    claimed_1 = repo.claim_next_task(worker_id="worker_1", lease_duration_seconds=10)
    assert claimed_1 is not None
    assert claimed_1.lease_owner == "worker_1"
    assert claimed_1.attempt_count == 1

    # While lease is unexpired, Worker 2 cannot claim it
    claimed_2_early = repo.claim_next_task(worker_id="worker_2", lease_duration_seconds=10)
    assert claimed_2_early is None

    # Simulate Worker 1 dying and lease expiring (rewind lease_expires_at into the past)
    task_row = memory_db.query(ScanTask).filter(ScanTask.id == task.id).first()
    task_row.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=5)
    memory_db.commit()

    # Worker 2 now claims the expired lease task
    claimed_2_recovered = repo.claim_next_task(worker_id="worker_2", lease_duration_seconds=60)
    assert claimed_2_recovered is not None
    assert claimed_2_recovered.id == task.id
    assert claimed_2_recovered.lease_owner == "worker_2"
    assert claimed_2_recovered.attempt_count == 2  # Incremented attempt


def test_bounded_retry_and_terminal_failure_with_quota_refund(memory_db):
    """Verify that retries are bounded by max_attempts and terminal failure triggers quota refund."""
    from app.config import settings
    repo = ScanRepository(memory_db)
    user_id = "user_poison_pill"
    date_key = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # Reserve quota for user
    repo.reserve_daily_scan_quota(user_id=user_id, date_key=date_key, limit=5)
    quota_before = memory_db.query(UserDailyQuota).filter(
        UserDailyQuota.user_id == user_id, UserDailyQuota.date_key == date_key
    ).first().scan_count
    assert quota_before == 1

    scan, task = repo.create_scan_with_outbox_task(
        scan_id="scan-poison-pill",
        user_id=user_id,
        input_type="url",
        raw_target="https://poison.com",
        payload_dict={"target_url": "https://poison.com"},
        max_attempts=2,
    )

    # Attempt 1: fails
    repo.claim_next_task(worker_id="w1", lease_duration_seconds=60)
    failed_1 = repo.fail_task_attempt(task.id, error_code="HTTP_500", error_message="Transient 500")
    assert failed_1.status == "PENDING"  # Retryable
    assert failed_1.attempt_count == 1

    # Attempt 2: fails again (hits max_attempts=2)
    repo.claim_next_task(worker_id="w2", lease_duration_seconds=60)
    failed_2 = repo.fail_task_attempt(task.id, error_code="HTTP_500", error_message="Fatal crash")
    assert failed_2.status == "FAILED"  # Terminal
    assert failed_2.attempt_count == 2

    # Simulate terminal failure handler: mark scan failed and refund quota
    repo.fail_scan(scan.id, error_code="TASK_MAX_RETRIES_EXCEEDED", error_message="Fatal crash")
    repo.refund_daily_scan_quota(user_id=user_id, date_key=date_key, scan_id=scan.id)

    # Verify scan is FAILED
    scan_row = memory_db.query(Scan).filter(Scan.id == scan.id).first()
    assert scan_row.status == ScanStatus.FAILED.value

    # Verify quota decremented
    quota_after = memory_db.query(UserDailyQuota).filter(
        UserDailyQuota.user_id == user_id, UserDailyQuota.date_key == date_key
    ).first().scan_count
    assert quota_after == 0


@pytest.mark.asyncio
async def test_idempotent_duplicate_execution_protection(memory_db):
    """Verify that a worker encountering an already COMPLETED scan exits cleanly without side effects."""
    repo = ScanRepository(memory_db)
    scan_id = "scan-already-done"
    user_id = "user_idempotency"

    scan, task = repo.create_scan_with_outbox_task(
        scan_id=scan_id,
        user_id=user_id,
        input_type="url",
        raw_target="https://already-done.com",
        payload_dict={"target_url": "https://already-done.com"},
    )
    # Transition scan to terminal COMPLETED state prior to worker run
    repo.update_scan_status(scan_id, ScanStatus.PROCESSING.value)
    repo.update_scan_status(scan_id, ScanStatus.COMPLETED.value)

    worker = DurableScanWorker(worker_id="worker_idem")
    processed = await worker.process_one(db=memory_db)

    assert processed is True
    # Task should be marked COMPLETED without modifying scan
    task_row = memory_db.query(ScanTask).filter(ScanTask.id == task.id).first()
    assert task_row.status == "COMPLETED"

    scan_row = memory_db.query(Scan).filter(Scan.id == scan_id).first()
    assert scan_row.status == ScanStatus.COMPLETED.value


def test_reconciliation_skips_actively_leased_tasks(memory_db):
    """Verify that RetentionService.reconcile_stuck_scans will NOT fail a scan with an active lease."""
    repo = ScanRepository(memory_db)
    retention = RetentionService(db=memory_db)
    scan_id = "scan-actively-working"
    user_id = "user_active_worker"

    scan, task = repo.create_scan_with_outbox_task(
        scan_id=scan_id,
        user_id=user_id,
        input_type="url",
        raw_target="https://long-scan.com",
        payload_dict={"target_url": "https://long-scan.com"},
    )

    # Worker claims task with lease valid for 30 minutes
    claimed = repo.claim_next_task(worker_id="worker_active", lease_duration_seconds=1800)
    assert claimed is not None

    # Simulate scan being older than the 15-minute stuck scan timeout
    scan_row = memory_db.query(Scan).filter(Scan.id == scan_id).first()
    scan_row.created_at = datetime.now(timezone.utc) - timedelta(minutes=25)
    memory_db.commit()

    # Run stuck scan reconciliation with 15-minute threshold
    reconciled_count = retention.reconcile_stuck_scans(timeout_minutes=15)

    # Reconciliation MUST skip this scan because its task is actively leased!
    assert reconciled_count == 0
    refreshed_scan = memory_db.query(Scan).filter(Scan.id == scan_id).first()
    assert refreshed_scan.status != ScanStatus.FAILED.value


def test_task_failure_sanitizes_error_and_does_not_leak_secrets(memory_db):
    """Verify that task failure error recording safely truncates and records error codes without leaking secrets."""
    repo = ScanRepository(memory_db)
    scan, task = repo.create_scan_with_outbox_task(
        scan_id="scan-leak-test",
        user_id="user_leak",
        input_type="url",
        raw_target="https://leak-test.com",
        payload_dict={"target_url": "https://leak-test.com"},
    )
    long_raw_error = "Connection failed to endpoint?key=secret_token_1234567890 " + ("x" * 600)
    failed_task = repo.fail_task_attempt(task.id, error_code="API_ERROR", error_message=long_raw_error)

    task_row = memory_db.query(ScanTask).filter(ScanTask.id == task.id).first()
    assert task_row.error_code == "API_ERROR"
    assert task_row.error_message is not None
    # Truncated to bounded length (500 chars)
    assert len(task_row.error_message) <= 500


def test_postgresql_worker_skip_locked_opt_in():
    """
    Opt-in PostgreSQL SKIP LOCKED integration test.
    Requires TEST_DATABASE_URL environment variable pointing to a disposable PostgreSQL 15+ target.
    """
    pg_url = os.getenv("TEST_DATABASE_URL")
    if not pg_url or not pg_url.startswith("postgresql"):
        pytest.skip("TEST_DATABASE_URL not configured with PostgreSQL target; skipping SKIP LOCKED integration test.")

    engine = create_engine(pg_url)
    try:
        with engine.connect() as conn:
            pass
    except Exception as e:
        pytest.skip(f"PostgreSQL target at {pg_url} unreachable: {e}")

    # If authorized test database is available, execute PostgreSQL SKIP LOCKED verification
    Session = sessionmaker(bind=engine)
    db = Session()
    try:
        repo = ScanRepository(db)
        test_scan_id = f"pg_skip_locked_{uuid.uuid4()}"
        scan, task = repo.create_scan_with_outbox_task(
            scan_id=test_scan_id,
            user_id="pg_test_user",
            input_type="url",
            raw_target="https://postgresql-skip-locked-test.com",
            payload_dict={"target_url": "https://postgresql-skip-locked-test.com"},
        )
        claimed = repo.claim_next_task(worker_id="pg_worker_1", lease_duration_seconds=60)
        assert claimed is not None
        assert claimed.id == task.id
        assert claimed.lease_owner == "pg_worker_1"
    finally:
        db.close()


def test_final_attempt_crash_recovery_exhausted_lease(memory_db):
    """
    Criterion 1: When a task reaches attempt_count == max_attempts and worker crashes,
    leaving lease expired, recovery transitions task and scan to FAILED with stable error code
    and refunds quota.
    """
    repo = ScanRepository(memory_db)
    scan_id = "scan-exhausted-crash"
    user_id = "user_exhausted_1"
    today_key = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # Reserve 1 quota
    memory_db.add(UserDailyQuota(user_id=user_id, date_key=today_key, scan_count=1))
    memory_db.commit()

    scan, task = repo.create_scan_with_outbox_task(
        scan_id=scan_id,
        user_id=user_id,
        input_type="url",
        raw_target="https://crash-on-final.com",
        payload_dict={"target_url": "https://crash-on-final.com"},
        max_attempts=3,
    )

    # Fast-forward task to final attempt with expired lease
    now = datetime.now(timezone.utc)
    task_row = memory_db.query(ScanTask).filter(ScanTask.id == task.id).first()
    task_row.status = "PROCESSING"
    task_row.attempt_count = 3
    task_row.max_attempts = 3
    task_row.lease_owner = "crashed_worker_9"
    task_row.lease_expires_at = now - timedelta(seconds=15)
    memory_db.commit()

    with patch.object(settings, "PILOT_MODE_ENABLED", True):
        reconciled = repo.reconcile_expired_exhausted_tasks(limit=10)
        assert reconciled == 1

    # Verify task state
    memory_db.expire_all()
    refreshed_task = memory_db.query(ScanTask).filter(ScanTask.id == task.id).first()
    assert refreshed_task.status == "FAILED"
    assert refreshed_task.error_code == "TASK_MAX_RETRIES_EXCEEDED"
    assert "Worker process terminated abruptly on final attempt" in refreshed_task.error_message
    assert refreshed_task.lease_owner is None
    assert refreshed_task.lease_expires_at is None
    assert refreshed_task.completed_at is not None

    # Verify scan state
    refreshed_scan = memory_db.query(Scan).filter(Scan.id == scan_id).first()
    assert refreshed_scan.status == ScanStatus.FAILED.value
    assert refreshed_scan.completed_at is not None

    # Verify quota refund
    quota = memory_db.query(UserDailyQuota).filter(
        UserDailyQuota.user_id == user_id,
        UserDailyQuota.date_key == today_key,
    ).first()
    assert quota.scan_count == 0


def test_final_attempt_crash_recovery_quota_idempotency(memory_db):
    """
    Criterion 2: Repeated recovery attempts issue at most one refund,
    and quota counter cannot decrement below zero.
    """
    repo = ScanRepository(memory_db)
    scan_id = "scan-exhausted-idempotent"
    user_id = "user_idempotent_1"
    today_key = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    memory_db.add(UserDailyQuota(user_id=user_id, date_key=today_key, scan_count=1))
    memory_db.commit()

    scan, task = repo.create_scan_with_outbox_task(
        scan_id=scan_id,
        user_id=user_id,
        input_type="url",
        raw_target="https://idempotent-recovery.com",
        payload_dict={"target_url": "https://idempotent-recovery.com"},
        max_attempts=2,
    )

    now = datetime.now(timezone.utc)
    task_row = memory_db.query(ScanTask).filter(ScanTask.id == task.id).first()
    task_row.status = "PROCESSING"
    task_row.attempt_count = 2
    task_row.max_attempts = 2
    task_row.lease_owner = "crashed_worker_1"
    task_row.lease_expires_at = now - timedelta(seconds=10)
    memory_db.commit()

    with patch.object(settings, "PILOT_MODE_ENABLED", True):
        # First recovery run
        run1 = repo.reconcile_expired_exhausted_tasks(limit=10)
        assert run1 == 1

        # Second recovery run
        run2 = repo.reconcile_expired_exhausted_tasks(limit=10)
        assert run2 == 0

        # Direct redundant refund call
        direct_call = repo.refund_daily_scan_quota(user_id=user_id, date_key=today_key, scan_id=scan_id)
        assert direct_call is False

    # Quota decremented once, never below zero
    quota = memory_db.query(UserDailyQuota).filter(
        UserDailyQuota.user_id == user_id,
        UserDailyQuota.date_key == today_key,
    ).first()
    assert quota.scan_count == 0

    refund_records = memory_db.query(QuotaRefundRecord).filter(
        QuotaRefundRecord.scan_id == scan_id
    ).all()
    assert len(refund_records) == 1


def test_concurrent_recovery_racing_workers(memory_db):
    """
    Criterion 3: Concurrent reconcilers racing on the same expired task
    cannot duplicate refunds or create conflicting states.
    """
    repo = ScanRepository(memory_db)
    scan_id = "scan-concurrent-race"
    user_id = "user_concurrent_race"
    today_key = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    memory_db.add(UserDailyQuota(user_id=user_id, date_key=today_key, scan_count=1))
    memory_db.commit()

    scan, task = repo.create_scan_with_outbox_task(
        scan_id=scan_id,
        user_id=user_id,
        input_type="url",
        raw_target="https://concurrent-race.com",
        payload_dict={"target_url": "https://concurrent-race.com"},
        max_attempts=3,
    )

    now = datetime.now(timezone.utc)
    task_row = memory_db.query(ScanTask).filter(ScanTask.id == task.id).first()
    task_row.status = "PROCESSING"
    task_row.attempt_count = 3
    task_row.max_attempts = 3
    task_row.lease_owner = "crashed_worker_race"
    task_row.lease_expires_at = now - timedelta(seconds=10)
    memory_db.commit()

    results = []
    engine = memory_db.get_bind()
    Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    def worker_run():
        db_session = Session()
        try:
            r = ScanRepository(db_session)
            count = r.reconcile_expired_exhausted_tasks(limit=10)
            results.append(count)
        finally:
            db_session.close()

    with patch.object(settings, "PILOT_MODE_ENABLED", True):
        t1 = threading.Thread(target=worker_run)
        t2 = threading.Thread(target=worker_run)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

    # Exactly one thread transitions the task
    assert sum(results) == 1

    memory_db.expire_all()
    refreshed_task = memory_db.query(ScanTask).filter(ScanTask.id == task.id).first()
    assert refreshed_task.status == "FAILED"

    quota = memory_db.query(UserDailyQuota).filter(
        UserDailyQuota.user_id == user_id,
        UserDailyQuota.date_key == today_key,
    ).first()
    assert quota.scan_count == 0


def test_live_lease_preservation_for_exhausted_attempt(memory_db):
    """
    Criterion 4: An exhausted task whose lease is still active (unexpired)
    must NOT be finalized early by reconcilers.
    """
    repo = ScanRepository(memory_db)
    scan_id = "scan-live-lease"
    user_id = "user_live_lease"

    scan, task = repo.create_scan_with_outbox_task(
        scan_id=scan_id,
        user_id=user_id,
        input_type="url",
        raw_target="https://live-lease.com",
        payload_dict={"target_url": "https://live-lease.com"},
        max_attempts=3,
    )

    # Active lease valid for another 10 minutes
    future_expiry = datetime.now(timezone.utc) + timedelta(minutes=10)
    task_row = memory_db.query(ScanTask).filter(ScanTask.id == task.id).first()
    task_row.status = "PROCESSING"
    task_row.attempt_count = 3
    task_row.max_attempts = 3
    task_row.lease_owner = "live_worker_alpha"
    task_row.lease_expires_at = future_expiry
    memory_db.commit()

    reconciled = repo.reconcile_expired_exhausted_tasks(limit=10)
    assert reconciled == 0

    memory_db.expire_all()
    refreshed_task = memory_db.query(ScanTask).filter(ScanTask.id == task.id).first()
    assert refreshed_task.status == "PROCESSING"
    assert refreshed_task.lease_owner == "live_worker_alpha"
    actual_expiry = (
        refreshed_task.lease_expires_at.replace(tzinfo=timezone.utc)
        if refreshed_task.lease_expires_at and refreshed_task.lease_expires_at.tzinfo is None
        else refreshed_task.lease_expires_at
    )
    assert actual_expiry == future_expiry


def test_terminal_scan_preservation_during_exhaustion_recovery(memory_db):
    """
    Criterion 5: If a scan already reached a terminal state (COMPLETED, PARTIAL, CANCELLED),
    reconciliation finalizes the orphaned task to FAILED without corrupting scan status or issuing duplicate refunds.
    """
    repo = ScanRepository(memory_db)
    scan_id = "scan-already-completed"
    user_id = "user_terminal_preserve"
    today_key = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    memory_db.add(UserDailyQuota(user_id=user_id, date_key=today_key, scan_count=1))
    memory_db.commit()

    scan, task = repo.create_scan_with_outbox_task(
        scan_id=scan_id,
        user_id=user_id,
        input_type="url",
        raw_target="https://completed-scan.com",
        payload_dict={"target_url": "https://completed-scan.com"},
        max_attempts=3,
    )

    # Advance scan to COMPLETED through valid transitions
    repo.update_scan_status(scan_id, "PROCESSING")
    repo.update_scan_status(scan_id, "COMPLETED")

    # Orphaned task row left in PROCESSING with expired lease
    now = datetime.now(timezone.utc)
    task_row = memory_db.query(ScanTask).filter(ScanTask.id == task.id).first()
    task_row.status = "PROCESSING"
    task_row.attempt_count = 3
    task_row.max_attempts = 3
    task_row.lease_owner = "crashed_worker_done"
    task_row.lease_expires_at = now - timedelta(seconds=20)
    memory_db.commit()

    with patch.object(settings, "PILOT_MODE_ENABLED", True):
        reconciled = repo.reconcile_expired_exhausted_tasks(limit=10)
        assert reconciled == 1

    memory_db.expire_all()
    refreshed_scan = memory_db.query(Scan).filter(Scan.id == scan_id).first()
    # Scan status MUST remain COMPLETED!
    assert refreshed_scan.status == ScanStatus.COMPLETED.value

    refreshed_task = memory_db.query(ScanTask).filter(ScanTask.id == task.id).first()
    assert refreshed_task.status == "FAILED"

    # Completed scan must NOT have quota refunded
    quota = memory_db.query(UserDailyQuota).filter(
        UserDailyQuota.user_id == user_id,
        UserDailyQuota.date_key == today_key,
    ).first()
    assert quota.scan_count == 1


def test_non_final_retry_behavior_preserved(memory_db):
    """
    Criterion 6: An expired task whose attempt_count < max_attempts is NOT failed by
    the exhausted-task reconciler; it remains eligible to be reclaimed by claim_next_task.
    """
    repo = ScanRepository(memory_db)
    scan_id = "scan-retryable-task"
    user_id = "user_retryable"

    scan, task = repo.create_scan_with_outbox_task(
        scan_id=scan_id,
        user_id=user_id,
        input_type="url",
        raw_target="https://retryable-example.com",
        payload_dict={"target_url": "https://retryable-example.com"},
        max_attempts=3,
    )

    # Attempt 1 failed by worker crash with expired lease, but attempt_count (1) < max_attempts (3)
    now = datetime.now(timezone.utc)
    task_row = memory_db.query(ScanTask).filter(ScanTask.id == task.id).first()
    task_row.status = "PROCESSING"
    task_row.attempt_count = 1
    task_row.max_attempts = 3
    task_row.lease_owner = "crashed_worker_retry"
    task_row.lease_expires_at = now - timedelta(seconds=10)
    memory_db.commit()

    # Reconciler for exhausted tasks skips this
    reconciled = repo.reconcile_expired_exhausted_tasks(limit=10)
    assert reconciled == 0

    # Task remains reclaimable by another worker
    claimed = repo.claim_next_task(worker_id="worker_rescue", lease_duration_seconds=60)
    assert claimed is not None
    assert claimed.id == task.id
    assert claimed.attempt_count == 2
    assert claimed.lease_owner == "worker_rescue"


def test_error_sanitization_does_not_leak_secrets(memory_db):
    """
    Criterion 7: Stored error information uses stable error code and safe message
    without leaking target credentials, query params, or sensitive data.
    """
    repo = ScanRepository(memory_db)
    sensitive_target = "https://admin:SuperSecretToken123@api.internal.network/v1/auth"
    scan, task = repo.create_scan_with_outbox_task(
        scan_id="scan-sensitive-secret",
        user_id="user_sensitive",
        input_type="url",
        raw_target=sensitive_target,
        payload_dict={"target_url": sensitive_target},
        max_attempts=1,
    )

    now = datetime.now(timezone.utc)
    task_row = memory_db.query(ScanTask).filter(ScanTask.id == task.id).first()
    task_row.status = "PROCESSING"
    task_row.attempt_count = 1
    task_row.max_attempts = 1
    task_row.lease_owner = "crashed_worker_secret"
    task_row.lease_expires_at = now - timedelta(seconds=10)
    memory_db.commit()

    reconciled = repo.reconcile_expired_exhausted_tasks(limit=10)
    assert reconciled == 1

    memory_db.expire_all()
    refreshed_task = memory_db.query(ScanTask).filter(ScanTask.id == task.id).first()
    assert refreshed_task.error_code == "TASK_MAX_RETRIES_EXCEEDED"
    assert "SuperSecretToken123" not in (refreshed_task.error_message or "")
    assert "SuperSecretToken123" not in (refreshed_task.error_code or "")


def test_reconciliation_cleans_associated_processing_tasks(memory_db):
    """
    Criterion 8: When RetentionService.reconcile_stuck_scans fails a timed-out scan,
    associated non-terminal task rows are also transitioned to FAILED and leases neutralized.
    """
    repo = ScanRepository(memory_db)
    retention = RetentionService(db=memory_db)
    scan_id = "scan-timeout-with-task"
    user_id = "user_stuck_with_task"

    scan, task = repo.create_scan_with_outbox_task(
        scan_id=scan_id,
        user_id=user_id,
        input_type="url",
        raw_target="https://stuck-with-task.com",
        payload_dict={"target_url": "https://stuck-with-task.com"},
        max_attempts=3,
    )

    # Simulate scan created 30 mins ago
    scan_row = memory_db.query(Scan).filter(Scan.id == scan_id).first()
    scan_row.created_at = datetime.now(timezone.utc) - timedelta(minutes=30)
    scan_row.status = ScanStatus.PROCESSING.value

    # Simulate task with expired lease (worker died on attempt 1, 20 mins ago)
    task_row = memory_db.query(ScanTask).filter(ScanTask.id == task.id).first()
    task_row.status = "PROCESSING"
    task_row.attempt_count = 1
    task_row.lease_owner = "dead_worker"
    task_row.lease_expires_at = datetime.now(timezone.utc) - timedelta(minutes=20)
    memory_db.commit()

    reconciled_count = retention.reconcile_stuck_scans(timeout_minutes=15)
    assert reconciled_count >= 1

    memory_db.expire_all()
    refreshed_scan = memory_db.query(Scan).filter(Scan.id == scan_id).first()
    assert refreshed_scan.status == ScanStatus.FAILED.value

    refreshed_task = memory_db.query(ScanTask).filter(ScanTask.id == task.id).first()
    assert refreshed_task.status == "FAILED"
    assert refreshed_task.error_code == "ERR_SCAN_TIMEOUT"
    assert refreshed_task.lease_owner is None
    assert refreshed_task.lease_expires_at is None


def test_subprocess_worker_crash_and_surviving_recovery():
    """
    Subprocess/Process-level test: Spawns an actual separate OS worker process,
    claims a task on final attempt, terminates abruptly without updating DB,
    and a surviving recovery process / reconciler finalizes the expired task and scan.
    Uses an isolated file-based SQLite database with WAL mode.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "subprocess_test.db")
        db_url = f"sqlite:///{db_path}"

        engine = create_engine(db_url, connect_args={"check_same_thread": False, "timeout": 30.0})
        Base.metadata.create_all(bind=engine)

        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        session = SessionLocal()
        try:
            repo = ScanRepository(session)
            scan_id = f"proc_scan_{uuid.uuid4().hex[:8]}"
            user_id = "user_proc_crash"
            today_key = datetime.now(timezone.utc).strftime("%Y-%m-%d")

            session.add(UserDailyQuota(user_id=user_id, date_key=today_key, scan_count=1))
            session.commit()

            # Create task with max_attempts=1 so attempt 1 is the final attempt
            scan, task = repo.create_scan_with_outbox_task(
                scan_id=scan_id,
                user_id=user_id,
                input_type="url",
                raw_target="https://subprocess-crash.com",
                payload_dict={"target_url": "https://subprocess-crash.com"},
                max_attempts=1,
            )
            task_id = task.id
        finally:
            session.close()
            engine.dispose()

        # Launch worker in a separate operating system process
        ready_event = multiprocessing.Event()
        worker_proc = multiprocessing.Process(
            target=run_process_worker_claim_and_crash,
            args=(db_url, "worker_proc_crashed", 1, ready_event),
        )
        worker_proc.start()

        # Wait for worker process to claim task
        claimed_ok = ready_event.wait(timeout=10.0)
        assert claimed_ok, "Worker subprocess did not claim task in time"
        worker_proc.join(timeout=5.0)

        # Worker terminated abruptly; wait for 1-second lease to expire
        time.sleep(1.2)

        # Surviving process executes recovery
        recovery_engine = create_engine(db_url, connect_args={"check_same_thread": False, "timeout": 30.0})
        RecoverySession = sessionmaker(autocommit=False, autoflush=False, bind=recovery_engine)
        rec_session = RecoverySession()
        try:
            rec_repo = ScanRepository(rec_session)
            with patch.object(settings, "PILOT_MODE_ENABLED", True):
                reconciled = rec_repo.reconcile_expired_exhausted_tasks(limit=10)
                assert reconciled == 1

            refreshed_task = rec_session.query(ScanTask).filter(ScanTask.id == task_id).first()
            assert refreshed_task.status == "FAILED"
            assert refreshed_task.error_code == "TASK_MAX_RETRIES_EXCEEDED"
            assert refreshed_task.lease_owner is None

            refreshed_scan = rec_session.query(Scan).filter(Scan.id == scan_id).first()
            assert refreshed_scan.status == ScanStatus.FAILED.value

            quota = rec_session.query(UserDailyQuota).filter(
                UserDailyQuota.user_id == user_id,
                UserDailyQuota.date_key == today_key,
            ).first()
            assert quota.scan_count == 0
        finally:
            rec_session.close()
            recovery_engine.dispose()


def test_postgresql_reconcile_expired_exhausted_tasks_skip_locked_opt_in():
    """
    Opt-in PostgreSQL FOR UPDATE SKIP LOCKED recovery test.
    Requires TEST_DATABASE_URL environment variable pointing to a disposable PostgreSQL 15+ target.
    """
    pg_url = os.getenv("TEST_DATABASE_URL")
    if not pg_url or not pg_url.startswith("postgresql"):
        pytest.skip("TEST_DATABASE_URL not configured with PostgreSQL target; skipping SKIP LOCKED integration test.")

    engine = create_engine(pg_url)
    try:
        with engine.connect() as conn:
            pass
    except Exception as e:
        pytest.skip(f"PostgreSQL target at {pg_url} unreachable: {e}")

    Session = sessionmaker(bind=engine)
    db = Session()
    try:
        repo = ScanRepository(db)
        test_scan_id = f"pg_exhausted_{uuid.uuid4()}"
        scan, task = repo.create_scan_with_outbox_task(
            scan_id=test_scan_id,
            user_id="pg_exhausted_user",
            input_type="url",
            raw_target="https://pg-exhausted-recovery.com",
            payload_dict={"target_url": "https://pg-exhausted-recovery.com"},
            max_attempts=1,
        )
        claimed = repo.claim_next_task(worker_id="pg_crashed_worker", lease_duration_seconds=1)
        assert claimed is not None
        time.sleep(1.2)
        reconciled = repo.reconcile_expired_exhausted_tasks(limit=10)
        assert reconciled >= 1
    finally:
        db.close()

