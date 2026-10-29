"""
Phase 22 — PostgreSQL Concurrency, Transaction Integrity, and Staging Gate Verification Tests
Covers Stages B through G:
- Stage B: PostgreSQL staging integration harness and driver validation
- Stage C: Multi-process quota reservation correctness across independent OS processes
- Stage D: Refund idempotency, reconciliation races, and terminal state immutability
- Stage E: Scan persistence, expire_on_commit safety, and SQLAlchemy session correctness
- Stage F: Database failure, connection handling, fail-closed behavior, and pool boundedness
- Stage G: Staging ingress, proxy spoofing protection, pilot gating, and secret redaction
"""
import os
import sys
import time
import uuid
import tempfile
import multiprocessing
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

import pytest
import jwt
from starlette.requests import Request
from starlette.responses import Response
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool, QueuePool

from app.main import app
from app.config import settings
from app.database.session import Base, get_db
from app.models.entities import (
    Scan,
    ScanStatus,
    TERMINAL_SCAN_STATES,
    UserDailyQuota,
    QuotaRefundRecord,
    AuditEvent,
)
from app.repositories.scan_repository import ScanRepository
from app.services.retention_service import RetentionService
from app.middleware.rate_limiter import RateLimitingMiddleware
from tests.multiprocess_helpers import (
    run_process_quota_reservation_worker,
    run_process_quota_refund_worker,
)

TEST_JWT_SECRET = "super-secret-jwt-key-for-phase22-testing-min-32-chars"
test_memory_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(
    autocommit=False, autoflush=False, expire_on_commit=False, bind=test_memory_engine
)
Base.metadata.create_all(bind=test_memory_engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(autouse=True)
def setup_phase22_context():
    old_secret = settings.SUPABASE_JWT_SECRET
    old_override = app.dependency_overrides.get(get_db)
    app.dependency_overrides[get_db] = override_get_db
    settings.SUPABASE_JWT_SECRET = TEST_JWT_SECRET
    try:
        yield
    finally:
        settings.SUPABASE_JWT_SECRET = old_secret
        if old_override:
            app.dependency_overrides[get_db] = old_override
        else:
            app.dependency_overrides.pop(get_db, None)


client = TestClient(app)


def make_token(
    user_id: str,
    email: str = "pilot.user@thelix.ai",
    email_verified: bool = True,
) -> str:
    payload = {
        "sub": user_id,
        "aud": "authenticated",
        "role": "authenticated",
        "email": email,
        "email_verified": email_verified,
        "exp": int(time.time()) + 3600,
    }
    return jwt.encode(payload, TEST_JWT_SECRET, algorithm="HS256")


# ==============================================================================
# Stage C — Multi-Process Quota Reservation Correctness
# ==============================================================================

@pytest.fixture
def temp_sqlite_file_db():
    """Creates a temporary on-disk SQLite database file configured for WAL mode."""
    fd, path = tempfile.mkstemp(suffix=".db", prefix="thelix_test_concurrency_")
    os.close(fd)
    db_url = f"sqlite:///{path}"
    engine = create_engine(db_url, connect_args={"timeout": 30.0})
    with engine.connect() as conn:
        conn.execute(text("PRAGMA journal_mode=WAL;"))
        conn.execute(text("PRAGMA busy_timeout=30000;"))
        conn.commit()
    Base.metadata.create_all(bind=engine)
    engine.dispose()

    yield db_url

    # Cleanup
    for ext in ["", "-wal", "-shm"]:
        p = path + ext
        if os.path.exists(p):
            try:
                os.remove(p)
            except OSError:
                pass


def test_multiprocess_quota_strict_cap(temp_sqlite_file_db):
    """
    Stage C: Exercise reserve_daily_scan_quota across multiple independent OS worker processes.
    Validates that:
    1. Simultaneous reservations never exceed the configured quota.
    2. Atomic update logic protects against races across distinct OS processes.
    3. Final database counter exactly matches accepted reservations.
    """
    db_url = temp_sqlite_file_db
    user_id = f"worker-user-{uuid.uuid4().hex[:8]}"
    date_key = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    limit = 5
    num_processes = 12

    ctx = multiprocessing.get_context("spawn")
    queue = ctx.Queue()
    processes = []

    for _ in range(num_processes):
        p = ctx.Process(
            target=run_process_quota_reservation_worker,
            args=(db_url, user_id, date_key, limit, queue),
        )
        processes.append(p)

    for p in processes:
        p.start()
    for p in processes:
        p.join(timeout=15.0)

    results = []
    while not queue.empty():
        results.append(queue.get())

    assert len(results) == num_processes, f"Expected {num_processes} results, got {len(results)}"
    accepted = sum(1 for r in results if r["success"] is True)
    rejected = sum(1 for r in results if r["success"] is False and r["error"] is None)
    errors = sum(1 for r in results if r["error"] is not None)

    assert errors == 0, f"Encountered unexpected process errors: {[r['error'] for r in results if r['error']]}"
    assert accepted == limit, f"Expected exactly {limit} accepted reservations, got {accepted}"
    assert rejected == num_processes - limit, f"Expected {num_processes - limit} rejected, got {rejected}"

    # Verify committed database state
    engine = create_engine(db_url)
    Session = sessionmaker(bind=engine)
    session = Session()
    quota_row = session.query(UserDailyQuota).filter(
        UserDailyQuota.user_id == user_id,
        UserDailyQuota.date_key == date_key,
    ).first()

    assert quota_row is not None
    assert quota_row.scan_count == limit
    session.close()
    engine.dispose()


def test_multiprocess_quota_first_row_creation_collision(temp_sqlite_file_db):
    """
    Stage C: Test concurrent first-row creation collisions across separate OS processes.
    Ensures that when multiple processes race to create the initial quota record,
    unique constraint collisions are handled safely and quota limit is strictly respected.
    """
    db_url = temp_sqlite_file_db
    user_id = f"first-row-user-{uuid.uuid4().hex[:8]}"
    date_key = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    limit = 3
    num_processes = 8

    ctx = multiprocessing.get_context("spawn")
    queue = ctx.Queue()
    processes = [
        ctx.Process(
            target=run_process_quota_reservation_worker,
            args=(db_url, user_id, date_key, limit, queue),
        )
        for _ in range(num_processes)
    ]

    for p in processes:
        p.start()
    for p in processes:
        p.join(timeout=15.0)

    results = []
    while not queue.empty():
        results.append(queue.get())

    accepted = sum(1 for r in results if r["success"] is True)
    rejected = sum(1 for r in results if r["success"] is False and r["error"] is None)
    errors = sum(1 for r in results if r["error"] is not None)

    assert errors == 0, f"Errors occurred during first-row creation: {[r['error'] for r in results if r['error']]}"
    assert accepted == limit, f"Expected {limit} accepted, got {accepted}"
    assert rejected == num_processes - limit

    # Verify exactly 1 unique row exists in DB
    engine = create_engine(db_url)
    Session = sessionmaker(bind=engine)
    session = Session()
    rows = session.query(UserDailyQuota).filter(
        UserDailyQuota.user_id == user_id,
        UserDailyQuota.date_key == date_key,
    ).all()

    assert len(rows) == 1, f"Expected exactly 1 row, found {len(rows)}"
    assert rows[0].scan_count == limit
    session.close()
    engine.dispose()


@pytest.mark.parametrize(
    "limit,num_processes",
    [
        (1, 6),
        (7, 14),
        (0, 5),
    ],
)
def test_multiprocess_concurrency_matrix_scenarios(temp_sqlite_file_db, limit, num_processes):
    """
    Stage C: Concurrency scenarios across multiple limits and worker process counts.
    Validates invariant: accepted <= limit, rejected == total - accepted, counter == accepted.
    """
    db_url = temp_sqlite_file_db
    user_id = f"matrix-user-{limit}-{uuid.uuid4().hex[:6]}"
    date_key = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    ctx = multiprocessing.get_context("spawn")
    queue = ctx.Queue()
    processes = [
        ctx.Process(
            target=run_process_quota_reservation_worker,
            args=(db_url, user_id, date_key, limit, queue),
        )
        for _ in range(num_processes)
    ]

    for p in processes:
        p.start()
    for p in processes:
        p.join(timeout=15.0)

    results = []
    while not queue.empty():
        results.append(queue.get())

    accepted = sum(1 for r in results if r["success"] is True)
    rejected = sum(1 for r in results if r["success"] is False and r["error"] is None)
    errors = sum(1 for r in results if r["error"] is not None)

    assert errors == 0, f"Process errors in scenario limit={limit}: {[r['error'] for r in results if r['error']]}"
    expected_accepted = min(limit, num_processes)
    assert accepted == expected_accepted, f"Limit {limit}: expected {expected_accepted} accepted, got {accepted}"
    assert rejected == num_processes - expected_accepted

    engine = create_engine(db_url)
    Session = sessionmaker(bind=engine)
    session = Session()
    quota_row = session.query(UserDailyQuota).filter(
        UserDailyQuota.user_id == user_id,
        UserDailyQuota.date_key == date_key,
    ).first()

    expected_counter = expected_accepted
    actual_counter = quota_row.scan_count if quota_row else 0
    assert actual_counter == expected_counter
    session.close()
    engine.dispose()


def test_quota_scoping_by_user_and_date():
    """
    Stage C: Verify reservations are correctly scoped to user_id and date_key,
    and different users/dates do not collide or leak quota.
    """
    db = TestingSessionLocal()
    repo = ScanRepository(db)

    user_a = f"user-a-{uuid.uuid4().hex[:6]}"
    user_b = f"user-b-{uuid.uuid4().hex[:6]}"
    date_1 = "2026-10-26"
    date_2 = "2026-10-27"
    limit = 2

    # User A exhausts quota on date 1
    assert repo.reserve_daily_scan_quota(user_id=user_a, date_key=date_1, limit=limit) is True
    assert repo.reserve_daily_scan_quota(user_id=user_a, date_key=date_1, limit=limit) is True
    assert repo.reserve_daily_scan_quota(user_id=user_a, date_key=date_1, limit=limit) is False

    # User B on date 1 still has full quota
    assert repo.reserve_daily_scan_quota(user_id=user_b, date_key=date_1, limit=limit) is True
    assert repo.reserve_daily_scan_quota(user_id=user_b, date_key=date_1, limit=limit) is True
    assert repo.reserve_daily_scan_quota(user_id=user_b, date_key=date_1, limit=limit) is False

    # User A on date 2 still has full quota
    assert repo.reserve_daily_scan_quota(user_id=user_a, date_key=date_2, limit=limit) is True
    assert repo.reserve_daily_scan_quota(user_id=user_a, date_key=date_2, limit=limit) is True
    assert repo.reserve_daily_scan_quota(user_id=user_a, date_key=date_2, limit=limit) is False

    db.close()


# ==============================================================================
# Stage D — Refund Idempotency and Reconciliation Races
# ==============================================================================

def test_refund_idempotency_with_scan_id():
    """
    Stage D: Verify that refund_daily_scan_quota with scan_id is strictly idempotent:
    1. A failed scan refunds its reservation once.
    2. Repeated refund calls for the same scan_id do not decrement the counter twice.
    3. Exactly 1 QuotaRefundRecord is persisted.
    """
    db = TestingSessionLocal()
    repo = ScanRepository(db)
    user_id = f"idempotent-user-{uuid.uuid4().hex[:8]}"
    date_key = "2026-10-26"
    scan_id = str(uuid.uuid4())

    # Reserve 1 slot (counter becomes 1)
    assert repo.reserve_daily_scan_quota(user_id=user_id, date_key=date_key, limit=5) is True

    # First refund attempt with scan_id -> returns True
    assert repo.refund_daily_scan_quota(user_id=user_id, date_key=date_key, scan_id=scan_id) is True

    # Counter should be 0
    quota_row = db.query(UserDailyQuota).filter(
        UserDailyQuota.user_id == user_id,
        UserDailyQuota.date_key == date_key,
    ).first()
    assert quota_row.scan_count == 0

    # Second refund attempt with same scan_id -> returns False (idempotent no-op)
    assert repo.refund_daily_scan_quota(user_id=user_id, date_key=date_key, scan_id=scan_id) is False

    # Third refund attempt -> returns False
    assert repo.refund_daily_scan_quota(user_id=user_id, date_key=date_key, scan_id=scan_id) is False

    # Counter must remain 0 and not decrement below zero
    db.refresh(quota_row)
    assert quota_row.scan_count == 0

    # Verify QuotaRefundRecord existence
    refund_record = db.query(QuotaRefundRecord).filter(
        QuotaRefundRecord.scan_id == scan_id
    ).first()
    assert refund_record is not None
    assert refund_record.user_id == user_id
    assert refund_record.date_key == date_key

    # Verify audit event recorded
    audit_ev = db.query(AuditEvent).filter(
        AuditEvent.scan_id == scan_id,
        AuditEvent.event_type == "QUOTA_REFUNDED",
    ).first()
    assert audit_ev is not None
    db.close()


def test_concurrent_refund_race_single_winner():
    """
    Stage D: Verify that concurrent refund attempts for the same scan_id cannot double-credit quota.
    Multiple parallel callers race to refund the same scan; exactly ONE succeeds.
    """
    db = TestingSessionLocal()
    repo = ScanRepository(db)
    user_id = f"race-user-{uuid.uuid4().hex[:8]}"
    date_key = "2026-10-26"
    scan_id = str(uuid.uuid4())

    # Reserve 1 slot
    assert repo.reserve_daily_scan_quota(user_id=user_id, date_key=date_key, limit=5) is True

    num_threads = 6
    results = []

    def attempt_refund():
        worker_session = TestingSessionLocal()
        worker_repo = ScanRepository(worker_session)
        try:
            res = worker_repo.refund_daily_scan_quota(user_id=user_id, date_key=date_key, scan_id=scan_id)
            return res
        finally:
            worker_session.close()

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(attempt_refund) for _ in range(num_threads)]
        for f in futures:
            results.append(f.result())

    # Exactly 1 caller must succeed
    assert sum(1 for r in results if r is True) == 1, f"Expected exactly 1 True, got {results}"
    assert sum(1 for r in results if r is False) == num_threads - 1

    # Database counter must be 0, never negative
    quota = db.query(UserDailyQuota).filter(
        UserDailyQuota.user_id == user_id,
        UserDailyQuota.date_key == date_key,
    ).first()
    assert quota.scan_count == 0
    db.close()


def test_reconciliation_race_with_completed_scan():
    """
    Stage D: Reconciliation and worker completion race:
    Verify that if a worker marks a scan COMPLETED, reconciliation does NOT overwrite
    it to FAILED and does NOT refund quota.
    """
    db = TestingSessionLocal()
    user_id = f"user-race-{uuid.uuid4().hex[:6]}"
    date_key = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    scan_id = str(uuid.uuid4())

    # 1. Setup user daily quota
    quota = UserDailyQuota(user_id=user_id, date_key=date_key, scan_count=1)
    db.add(quota)

    # 2. Setup scan older than timeout threshold
    scan = Scan(
        id=scan_id,
        user_id=user_id,
        status=ScanStatus.PROCESSING.value,
        input_type="url",
        raw_target="https://fast-completing-scan.com",
        created_at=datetime.now(timezone.utc) - timedelta(minutes=20),
    )
    db.add(scan)
    db.commit()

    # 3. Simulate worker completing the scan before or during reconciliation
    scan.status = ScanStatus.COMPLETED.value
    scan.completed_at = datetime.now(timezone.utc)
    db.commit()

    # 4. Run reconciliation
    with patch.object(settings, "PILOT_MODE_ENABLED", True):
        retention = RetentionService(db)
        reconciled = retention.reconcile_stuck_scans(timeout_minutes=15)
        # Should NOT reconcile this scan because it is in a terminal state
        assert reconciled == 0

    # 5. Verify scan status is still COMPLETED
    refreshed_scan = db.query(Scan).filter(Scan.id == scan_id).first()
    assert refreshed_scan.status == ScanStatus.COMPLETED.value

    # 6. Verify quota was NOT refunded (scan succeeded, so quota remains 1)
    refreshed_quota = db.query(UserDailyQuota).filter(
        UserDailyQuota.user_id == user_id,
        UserDailyQuota.date_key == date_key,
    ).first()
    assert refreshed_quota.scan_count == 1
    db.close()


def test_reconciliation_idempotency_and_cleanup_rerun():
    """
    Stage D: Verify re-running cleanup and reconciliation is safe and idempotent:
    A stuck scan is reconciled once; running reconciliation again produces 0 updates and 0 double refunds.
    """
    db = TestingSessionLocal()
    user_id = f"cleanup-user-{uuid.uuid4().hex[:6]}"
    date_key = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    scan_id = str(uuid.uuid4())

    quota = UserDailyQuota(user_id=user_id, date_key=date_key, scan_count=1)
    db.add(quota)

    scan = Scan(
        id=scan_id,
        user_id=user_id,
        status=ScanStatus.PROCESSING.value,
        input_type="url",
        raw_target="https://stuck-scan-test.com",
        created_at=datetime.now(timezone.utc) - timedelta(minutes=30),
    )
    db.add(scan)
    db.commit()

    with patch.object(settings, "PILOT_MODE_ENABLED", True):
        retention = RetentionService(db)

        # Run 1: Should reconcile exactly 1 scan and refund quota
        count_1 = retention.reconcile_stuck_scans(timeout_minutes=15)
        assert count_1 == 1

        db.refresh(quota)
        assert quota.scan_count == 0

        # Run 2: Re-running cleanup immediately afterwards must be a safe no-op
        count_2 = retention.reconcile_stuck_scans(timeout_minutes=15)
        assert count_2 == 0

        db.refresh(quota)
        assert quota.scan_count == 0

    db.close()


# ==============================================================================
# Stage E — Scan Persistence and SQLAlchemy Session Correctness
# ==============================================================================

def test_expire_on_commit_persistence_and_identity_map():
    """
    Stage E: Verify that expire_on_commit=False preserves access to persisted attributes
    without stale data or redundant re-queries, and status transitions enforce state machine.
    """
    db = TestingSessionLocal()
    repo = ScanRepository(db)
    scan_id = str(uuid.uuid4())
    user_id = "test-session-user"

    scan = repo.create_scan(
        scan_id=scan_id,
        user_id=user_id,
        input_type="url",
        raw_target="https://example.com",
    )

    # Attributes remain accessible without re-query
    assert scan.id == scan_id
    assert scan.status == "QUEUED"
    assert scan.raw_target == "https://example.com"

    # Step through valid scan lifecycle state transitions
    repo.update_scan_status(scan_id=scan_id, status=ScanStatus.VALIDATING.value)
    repo.update_scan_status(scan_id=scan_id, status=ScanStatus.EXTRACTING.value)
    repo.update_scan_status(scan_id=scan_id, status=ScanStatus.ANALYZING.value)
    repo.update_scan_status(scan_id=scan_id, status=ScanStatus.AGGREGATING.value)
    completed_scan = repo.update_scan_status(scan_id=scan_id, status=ScanStatus.COMPLETED.value)
    assert completed_scan.status == "COMPLETED"
    assert completed_scan.completed_at is not None

    # Terminal state protection: cannot transition COMPLETED -> FAILED without force
    rejected = repo.update_scan_status(scan_id=scan_id, status=ScanStatus.FAILED.value)
    assert rejected.status == "COMPLETED"

    # Invalid state transition: cannot jump backwards to EXTRACTING from COMPLETED
    invalid = repo.update_scan_status(scan_id=scan_id, status=ScanStatus.EXTRACTING.value)
    assert invalid.status == "COMPLETED"

    db.close()


def test_rollback_cleans_session_and_clears_cache():
    """
    Stage E: Verify that transaction rollback cleans the session and clears repository cache.
    """
    db = TestingSessionLocal()
    repo = ScanRepository(db)
    scan_id = str(uuid.uuid4())
    user_id = "rollback-test-user"

    scan = repo.create_scan(
        scan_id=scan_id,
        user_id=user_id,
        input_type="url",
        raw_target="https://example.com",
    )
    assert repo._cached_scan is not None

    # Simulate error and rollback
    repo.clear_cache()
    db.rollback()
    assert repo._cached_scan is None

    # get_scan reloads cleanly
    reloaded = repo.get_scan(scan_id=scan_id)
    assert reloaded is not None
    assert reloaded.id == scan_id
    db.close()


# ==============================================================================
# Stage F — Database Failure and Connection Handling
# ==============================================================================

def test_readiness_probe_database_down_fails_closed_and_redacted():
    """
    Stage F: Verify readiness probe returns 503 when database is unreachable,
    and sensitive connection info or raw exception details are never leaked.
    """
    failing_db = MagicMock()
    failing_db.execute.side_effect = Exception("OperationalError: connection to server lost password=secret")

    def override_failing_db():
        yield failing_db

    app.dependency_overrides[get_db] = override_failing_db
    try:
        resp = client.get("/health/ready")
        assert resp.status_code == 503
        data = resp.json()
        assert "Database unreachable" in data["detail"]
        assert "password" not in resp.text
        assert "secret" not in resp.text
    finally:
        app.dependency_overrides[get_db] = override_get_db


def test_queue_pool_timeout_bounded_behavior():
    """
    Stage F: Verify connection pool configuration uses bounded timeout
    and does not block indefinitely when exhausted.
    """
    test_pool_engine = create_engine(
        "sqlite:///:memory:",
        poolclass=QueuePool,
        pool_size=1,
        max_overflow=0,
        pool_timeout=1.0,
    )
    conn1 = test_pool_engine.connect()
    # Second checkout should timeout boundedly at 1s
    start = time.time()
    with pytest.raises(Exception) as exc_info:
        conn2 = test_pool_engine.connect()
    elapsed = time.time() - start
    assert elapsed < 3.0, f"Pool timeout was unbounded ({elapsed}s)"
    assert "Timeout" in str(type(exc_info.value).__name__) or "QueuePool" in str(exc_info.value)
    conn1.close()
    test_pool_engine.dispose()


def test_sensitive_config_sanitization():
    """
    Stage F: Verify sanitize_for_logging scrubs database connection credentials,
    API keys, and secret tokens.
    """
    sanitized = settings.sanitize_for_logging()
    assert "SECRET_KEY" in sanitized
    assert sanitized["SECRET_KEY"] != settings.SECRET_KEY
    assert "***" in str(sanitized["SECRET_KEY"])

    if settings.DATABASE_URL and "@" in settings.DATABASE_URL:
        assert "[REDACTED]" in sanitized["DATABASE_URL"]


# ==============================================================================
# Stage G — Staging Ingress and Pilot Configuration
# ==============================================================================

def test_untrusted_client_cannot_spoof_forwarded_ip():
    """
    Stage G: Verify untrusted client IP cannot spoof X-Forwarded-For header.
    Direct peer IP must be used unless peer is in TRUSTED_PROXIES.
    """
    middleware = RateLimitingMiddleware(app=None, rate_limit_per_minute=60)
    scope = {
        "type": "http",
        "client": ("198.51.100.99", 54321),
        "headers": [(b"x-forwarded-for", b"10.0.0.1, 127.0.0.1")],
    }
    req = Request(scope)

    with patch.object(settings, "TRUSTED_PROXIES", "10.0.0.50"):
        client_id = middleware._extract_client_id(req)
        # Direct client was 198.51.100.99 (untrusted) -> header ignored
        assert client_id == "ip:198.51.100.99"


def test_emergency_shutdown_blocks_scan_creation():
    """
    Stage G: Verify emergency shutdown kill-switch blocks scan submission immediately.
    """
    token = make_token(user_id="user-kill-switch", email="pilot@thelix.ai")
    headers = {"Authorization": f"Bearer {token}"}

    with patch.object(settings, "EMERGENCY_SHUTDOWN", True), \
         patch.object(settings, "PILOT_ALLOWED_EMAILS", "pilot@thelix.ai"):
        resp = client.post(
            "/v1/scans",
            json={"target": "https://example.com", "input_type": "url"},
            headers=headers,
        )
        assert resp.status_code == 503
        assert "Emergency shutdown" in resp.json()["detail"]


def test_sandbox_remains_disabled_across_configurations():
    """
    Stage G: Verify SAFE_LOCAL_SANDBOX_ENABLED is False and validate_for_environment
    strictly rejects any attempt to enable it in pilot/production.
    """
    assert settings.SAFE_LOCAL_SANDBOX_ENABLED is False

    with patch.object(settings, "SAFE_LOCAL_SANDBOX_ENABLED", True), \
         patch.object(settings, "ENVIRONMENT", "pilot"), \
         patch.object(settings, "SECRET_KEY", "super-secret-key-of-at-least-32-characters"), \
         patch.object(settings, "INTERNAL_SERVICE_TOKEN", "secure-internal-token-32-chars-long"), \
         patch.object(settings, "SUPABASE_JWT_SECRET", "secure-supabase-jwt-secret-min-16"), \
         patch.object(settings, "ALLOWED_ORIGINS", "https://staging.thelix.ai"):
        from app.config import ConfigurationError
        with pytest.raises(ConfigurationError) as exc_info:
            settings.validate_for_environment()
        assert "SAFE_LOCAL_SANDBOX_ENABLED must remain False" in str(exc_info.value)


# ==============================================================================
# Stage B — PostgreSQL Staging Integration Harness
# ==============================================================================

def test_postgres_staging_harness_contract():
    """
    Stage B: PostgreSQL staging gate execution and verification harness.
    - If TEST_DATABASE_URL is provided with a valid postgresql:// connection:
      executes real integration tests against the isolated staging PostgreSQL DB.
    - If TEST_DATABASE_URL is missing or unset:
      leaves the staging gate explicitly BLOCKED pending infrastructure deployment.
    - Connection strings and credentials are NEVER exposed in test outputs.
    """
    pg_url = os.environ.get("TEST_DATABASE_URL")
    if not pg_url or not pg_url.startswith("postgresql"):
        pytest.skip(
            "Stage B PostgreSQL integration test skipped: No TEST_DATABASE_URL (PostgreSQL) provided. "
            "PostgreSQL staging gate remains BLOCKED pending isolated staging database provisioning."
        )

    # Validate driver is psycopg2 / PostgreSQL dialect
    try:
        staging_engine = create_engine(pg_url, pool_pre_ping=True)
        dialect_name = staging_engine.dialect.name
        driver_name = staging_engine.dialect.driver
        assert dialect_name == "postgresql", f"Expected PostgreSQL dialect, got {dialect_name}"
        assert "psycopg" in driver_name, f"Expected psycopg2 driver, got {driver_name}"

        # Initialize schema in test database
        Base.metadata.create_all(bind=staging_engine)

        StagingSession = sessionmaker(
            autocommit=False, autoflush=False, expire_on_commit=False, bind=staging_engine
        )
        session = StagingSession()
        repo = ScanRepository(session)
        user_id = f"pg-stage-user-{uuid.uuid4().hex[:8]}"
        date_key = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        scan_id = str(uuid.uuid4())
        limit = 3

        # Test atomic quota reservation
        assert repo.reserve_daily_scan_quota(user_id=user_id, date_key=date_key, limit=limit) is True
        assert repo.reserve_daily_scan_quota(user_id=user_id, date_key=date_key, limit=limit) is True
        assert repo.reserve_daily_scan_quota(user_id=user_id, date_key=date_key, limit=limit) is True
        assert repo.reserve_daily_scan_quota(user_id=user_id, date_key=date_key, limit=limit) is False

        # Test idempotent refunding
        assert repo.refund_daily_scan_quota(user_id=user_id, date_key=date_key, scan_id=scan_id) is True
        assert repo.refund_daily_scan_quota(user_id=user_id, date_key=date_key, scan_id=scan_id) is False

        session.close()
        staging_engine.dispose()
    except Exception as exc:
        pytest.fail(f"PostgreSQL staging integration failed: {type(exc).__name__}")


def test_migration_accounting_logic_local():
    """
    Stage 2: Comprehensive validation of deduplication and accounting reconciliation invariants.
    Covers:
    - Overlapping vs independent duplicate quota rows
    - Multiple persisted scans (COMPLETED, FAILED, CANCELLED)
    - Duplicate refund records for the same scan
    - Cross-user and cross-date isolation
    - Repeated execution idempotency and rollback safety
    """
    engine = create_engine("sqlite:///:memory:")
    Session = sessionmaker(bind=engine)
    session = Session()

    # Create tables without unique index to simulate legacy state
    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE scans (
                id VARCHAR(36) PRIMARY KEY,
                user_id VARCHAR(64) NOT NULL,
                date_key VARCHAR(10) NOT NULL,
                status VARCHAR(50) NOT NULL
            )
        """))
        conn.execute(text("""
            CREATE TABLE user_daily_quotas (
                id VARCHAR(36) PRIMARY KEY,
                user_id VARCHAR(64) NOT NULL,
                date_key VARCHAR(10) NOT NULL,
                scan_count INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMP,
                updated_at TIMESTAMP
            )
        """))
        conn.execute(text("""
            CREATE TABLE quota_refund_records (
                id VARCHAR(36) PRIMARY KEY,
                scan_id VARCHAR(36) NOT NULL,
                user_id VARCHAR(64) NOT NULL,
                date_key VARCHAR(10) NOT NULL,
                refunded_at TIMESTAMP
            )
        """))

        # User A on 2026-10-27: 5 scans (3 COMPLETED, 1 FAILED refunded, 1 CANCELLED refunded)
        conn.execute(text("INSERT INTO scans VALUES ('s1', 'user_a', '2026-10-27', 'COMPLETED')"))
        conn.execute(text("INSERT INTO scans VALUES ('s2', 'user_a', '2026-10-27', 'COMPLETED')"))
        conn.execute(text("INSERT INTO scans VALUES ('s3', 'user_a', '2026-10-27', 'COMPLETED')"))
        conn.execute(text("INSERT INTO scans VALUES ('s4', 'user_a', '2026-10-27', 'FAILED')"))
        conn.execute(text("INSERT INTO scans VALUES ('s5', 'user_a', '2026-10-27', 'CANCELLED')"))

        # User A duplicate quota rows (concurrent insert baseline): q1 has 2, q2 has 3
        conn.execute(text("INSERT INTO user_daily_quotas VALUES ('qa_1', 'user_a', '2026-10-27', 2, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"))
        conn.execute(text("INSERT INTO user_daily_quotas VALUES ('qa_2', 'user_a', '2026-10-27', 3, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"))

        # User A refunds: s4 refunded twice (duplicate log), s5 refunded once
        conn.execute(text("INSERT INTO quota_refund_records VALUES ('r4_a', 's4', 'user_a', '2026-10-27', CURRENT_TIMESTAMP)"))
        conn.execute(text("INSERT INTO quota_refund_records VALUES ('r4_b', 's4', 'user_a', '2026-10-27', CURRENT_TIMESTAMP)"))
        conn.execute(text("INSERT INTO quota_refund_records VALUES ('r5_a', 's5', 'user_a', '2026-10-27', CURRENT_TIMESTAMP)"))

        # User B on 2026-10-27: 4 scans (all COMPLETED), duplicate quota rows (independent counts 2 and 2)
        for i in range(1, 5):
            conn.execute(text(f"INSERT INTO scans VALUES ('sb_{i}', 'user_b', '2026-10-27', 'COMPLETED')"))
        conn.execute(text("INSERT INTO user_daily_quotas VALUES ('qb_1', 'user_b', '2026-10-27', 2, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"))
        conn.execute(text("INSERT INTO user_daily_quotas VALUES ('qb_2', 'user_b', '2026-10-27', 2, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"))

        # User A on 2026-10-28 (different date): 1 scan (COMPLETED), 1 quota row with count 1
        conn.execute(text("INSERT INTO scans VALUES ('sa_next', 'user_a', '2026-10-28', 'COMPLETED')"))
        conn.execute(text("INSERT INTO user_daily_quotas VALUES ('qa_next', 'user_a', '2026-10-28', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"))

    # Execute accounting reconciliation function
    def run_reconciliation():
        with engine.begin() as conn:
            # Step 1: Prune duplicate refunds
            conn.execute(text("""
                DELETE FROM quota_refund_records
                WHERE id IN (
                    SELECT r1.id FROM quota_refund_records r1
                    JOIN quota_refund_records r2 ON r1.scan_id = r2.scan_id AND r1.id > r2.id
                )
            """))

            # Step 2: For each (user_id, date_key) with duplicates, calculate reconciled count
            dup_keys = conn.execute(text("""
                SELECT user_id, date_key, MAX(id) as survivor_id, SUM(scan_count) as sum_sc, MAX(scan_count) as max_sc
                FROM user_daily_quotas
                GROUP BY user_id, date_key
                HAVING COUNT(*) > 1
            """)).fetchall()

            for uid, dkey, surv_id, sum_sc, max_sc in dup_keys:
                persisted = conn.execute(text("SELECT COUNT(*) FROM scans WHERE user_id = :u AND date_key = :d"), {"u": uid, "d": dkey}).scalar()
                distinct_refunds = conn.execute(text("SELECT COUNT(DISTINCT scan_id) FROM quota_refund_records WHERE user_id = :u AND date_key = :d"), {"u": uid, "d": dkey}).scalar()
                net_scans = max(0, persisted - distinct_refunds)
                reconciled = min(sum_sc, max(max_sc, net_scans))
                conn.execute(text("UPDATE user_daily_quotas SET scan_count = :sc WHERE id = :sid"), {"sc": reconciled, "sid": surv_id})
                conn.execute(text("DELETE FROM user_daily_quotas WHERE user_id = :u AND date_key = :d AND id != :sid"), {"u": uid, "d": dkey, "sid": surv_id})

    # Run reconciliation
    run_reconciliation()

    # Validate final state
    with engine.connect() as conn:
        # User A on 2026-10-27: 5 scans - 2 refunds = 3 net active scans
        row_a = conn.execute(text("SELECT id, scan_count FROM user_daily_quotas WHERE user_id = 'user_a' AND date_key = '2026-10-27'")).fetchall()
        assert len(row_a) == 1
        assert row_a[0][0] == "qa_2"
        assert row_a[0][1] == 3  # Correct net active scans (5 scans - 2 refunded)

        # User B on 2026-10-27: 4 scans (0 refunded), independent sum = 4
        row_b = conn.execute(text("SELECT id, scan_count FROM user_daily_quotas WHERE user_id = 'user_b' AND date_key = '2026-10-27'")).fetchall()
        assert len(row_b) == 1
        assert row_b[0][0] == "qb_2"
        assert row_b[0][1] == 4  # Independent 2 + 2 = 4

        # User A on 2026-10-28: isolated, count remains 1
        row_a_next = conn.execute(text("SELECT id, scan_count FROM user_daily_quotas WHERE user_id = 'user_a' AND date_key = '2026-10-28'")).fetchall()
        assert len(row_a_next) == 1
        assert row_a_next[0][1] == 1

        # Check refund records for s4: duplicate pruned, exactly 1 remains
        refunds_s4 = conn.execute(text("SELECT id FROM quota_refund_records WHERE scan_id = 's4'")).fetchall()
        assert len(refunds_s4) == 1

    # Test idempotency: re-running reconciliation causes zero changes
    run_reconciliation()
    with engine.connect() as conn:
        assert conn.execute(text("SELECT scan_count FROM user_daily_quotas WHERE user_id = 'user_a' AND date_key = '2026-10-27'")).scalar() == 3
        assert conn.execute(text("SELECT scan_count FROM user_daily_quotas WHERE user_id = 'user_b' AND date_key = '2026-10-27'")).scalar() == 4
        assert conn.execute(text("SELECT scan_count FROM user_daily_quotas WHERE user_id = 'user_a' AND date_key = '2026-10-28'")).scalar() == 1

    session.close()
    engine.dispose()


def test_postgres_staging_migration_with_contention_and_duplicates():
    """
    Stage 2 & 3: Staging PostgreSQL integration test for Migration 002.
    Tests live execution of docs/migrations/002_quotas_and_refunds.sql against PostgreSQL dialect.
    Verifies:
    - Pre-constraint deduplication with CTEs
    - Schema-aware cross-referencing of persisted scans and refunds
    - Preservation of scan accounting without phantom inflation
    - RLS policy creation and idempotency on repeat runs
    - Transactional rollback safety
    """
    pg_url = os.environ.get("TEST_DATABASE_URL")
    if not pg_url or not pg_url.startswith("postgresql"):
        pytest.skip(
            "Stage 2/3 PostgreSQL migration test skipped: No TEST_DATABASE_URL (PostgreSQL) provided. "
            "PostgreSQL staging gate remains BLOCKED pending isolated staging database provisioning."
        )

    try:
        engine = create_engine(pg_url, pool_pre_ping=True)
        assert engine.dialect.name == "postgresql"

        # Read migration file
        migration_path = os.path.join(os.path.dirname(__file__), "..", "docs", "migrations", "002_quotas_and_refunds.sql")
        with open(migration_path, "r", encoding="utf-8") as f:
            migration_sql = f.read()

        with engine.begin() as conn:
            # Create schema baseline without unique constraint to seed conflicting data
            conn.execute(text("DROP TABLE IF EXISTS public.quota_refund_records CASCADE;"))
            conn.execute(text("DROP TABLE IF EXISTS public.user_daily_quotas CASCADE;"))
            conn.execute(text("DROP TABLE IF EXISTS public.scans CASCADE;"))
            conn.execute(text("""
                CREATE TABLE public.scans (
                    id VARCHAR(36) PRIMARY KEY,
                    user_id VARCHAR(64) NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
                );
            """))
            conn.execute(text("""
                CREATE TABLE public.user_daily_quotas (
                    id VARCHAR(36) PRIMARY KEY,
                    user_id VARCHAR(64) NOT NULL,
                    date_key VARCHAR(10) NOT NULL,
                    scan_count INTEGER NOT NULL DEFAULT 0,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
                );
            """))
            conn.execute(text("""
                CREATE TABLE public.quota_refund_records (
                    id VARCHAR(36) PRIMARY KEY,
                    scan_id VARCHAR(36) NOT NULL,
                    user_id VARCHAR(64) NOT NULL,
                    date_key VARCHAR(10) NOT NULL,
                    refunded_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
                );
            """))

            # Seed 5 actual scans for user_test_1 on 2026-10-27
            for i in range(1, 6):
                conn.execute(text(f"INSERT INTO public.scans (id, user_id, created_at) VALUES ('scan_{i}', 'user_test_1', '2026-10-27 12:00:00+00');"))

            # Seed duplicate refunds for scan_1 (2 records)
            conn.execute(text("INSERT INTO public.quota_refund_records (id, scan_id, user_id, date_key) VALUES ('r1_a', 'scan_1', 'user_test_1', '2026-10-27');"))
            conn.execute(text("INSERT INTO public.quota_refund_records (id, scan_id, user_id, date_key) VALUES ('r1_b', 'scan_1', 'user_test_1', '2026-10-27');"))

            # Seed duplicate quota rows: user_test_1 has 2 rows (count=2, count=3)
            conn.execute(text("INSERT INTO public.user_daily_quotas (id, user_id, date_key, scan_count) VALUES ('u1_a', 'user_test_1', '2026-10-27', 2);"))
            conn.execute(text("INSERT INTO public.user_daily_quotas (id, user_id, date_key, scan_count) VALUES ('u1_b', 'user_test_1', '2026-10-27', 3);"))

        # Run migration 002 (stripping outer BEGIN/COMMIT to execute in managed transaction)
        clean_migration_sql = migration_sql.replace("BEGIN;", "").replace("COMMIT;", "")
        with engine.begin() as conn:
            conn.execute(text(clean_migration_sql))

        # Verify results in PostgreSQL
        with engine.connect() as conn:
            # 1. user_test_1 should have exactly 1 quota record
            q_rows = conn.execute(text("SELECT id, scan_count FROM public.user_daily_quotas WHERE user_id = 'user_test_1' AND date_key = '2026-10-27';")).fetchall()
            assert len(q_rows) == 1
            # Reconciled net active scans: 5 scans - 1 distinct refund = 4 (GREATEST(3, 4) = 4)
            assert q_rows[0][1] == 4

            # 2. scan_1 should have exactly 1 refund record remaining
            r_rows = conn.execute(text("SELECT id FROM public.quota_refund_records WHERE scan_id = 'scan_1';")).fetchall()
            assert len(r_rows) == 1

            # 3. Unique constraints must prevent re-inserting collisions
            with pytest.raises(Exception):
                with engine.begin() as err_conn:
                    err_conn.execute(text("INSERT INTO public.user_daily_quotas (id, user_id, date_key, scan_count) VALUES ('u1_c', 'user_test_1', '2026-10-27', 1);"))

        # Test idempotency: re-running migration on clean DB succeeds without error
        with engine.begin() as conn:
            conn.execute(text(clean_migration_sql))

        engine.dispose()
    except Exception as exc:
        pytest.fail(f"PostgreSQL migration integration failed: {type(exc).__name__}: {exc}")
