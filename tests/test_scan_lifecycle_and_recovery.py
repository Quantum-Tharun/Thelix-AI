"""
Tests for Scan Lifecycle State Machine and Failure Recovery (Phase 13)
Verifies:
1. Valid state transitions according to scan lifecycle state machine.
2. Protection of terminal states (COMPLETED, FAILED, REJECTED, CANCELLED) against accidental overwrites.
3. Atomic fail_scan operations recording error codes, task failures, and audit events.
4. Error recovery in synchronous and background URL scans.
5. Error recovery in multimodal scan execution.
"""
import uuid
import pytest
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database.session import Base
from app.models.entities import Scan, ScanStatus, TERMINAL_SCAN_STATES, VALID_STATUS_TRANSITIONS
from app.repositories.scan_repository import ScanRepository
from app.services.orchestrator_service import OrchestratorService


@pytest.fixture
def test_db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = Session()
    try:
        yield db
    finally:
        db.close()


def test_valid_scan_state_transitions(test_db):
    """Verify valid transitions through the normal lifecycle."""
    repo = ScanRepository(test_db)
    scan_id = str(uuid.uuid4())
    user_id = "user_lifecycle_1"

    # QUEUED
    scan = repo.create_scan(scan_id=scan_id, user_id=user_id, input_type="url", raw_target="https://example.com")
    assert scan.status == ScanStatus.QUEUED.value

    # QUEUED -> VALIDATING
    scan = repo.update_scan_status(scan_id, ScanStatus.VALIDATING.value)
    assert scan.status == ScanStatus.VALIDATING.value

    # VALIDATING -> EXTRACTING
    scan = repo.update_scan_status(scan_id, ScanStatus.EXTRACTING.value)
    assert scan.status == ScanStatus.EXTRACTING.value

    # EXTRACTING -> ANALYZING
    scan = repo.update_scan_status(scan_id, ScanStatus.ANALYZING.value)
    assert scan.status == ScanStatus.ANALYZING.value

    # ANALYZING -> AGGREGATING
    scan = repo.update_scan_status(scan_id, ScanStatus.AGGREGATING.value)
    assert scan.status == ScanStatus.AGGREGATING.value

    # AGGREGATING -> COMPLETED (Terminal)
    scan = repo.update_scan_status(scan_id, ScanStatus.COMPLETED.value)
    assert scan.status == ScanStatus.COMPLETED.value
    assert scan.completed_at is not None


def test_terminal_state_protection_blocks_invalid_overwrites(test_db):
    """Verify that terminal states (COMPLETED, FAILED, REJECTED) cannot be overwritten by non-terminal transitions."""
    repo = ScanRepository(test_db)
    scan_id = str(uuid.uuid4())
    user_id = "user_terminal_guard"

    scan = repo.create_scan(scan_id=scan_id, user_id=user_id, input_type="url", raw_target="https://example.com")
    repo.update_scan_status(scan_id, ScanStatus.PROCESSING.value)
    repo.update_scan_status(scan_id, ScanStatus.COMPLETED.value)
    assert scan.status == ScanStatus.COMPLETED.value

    # Attempt invalid overwrite: COMPLETED -> PROCESSING
    updated = repo.update_scan_status(scan_id, ScanStatus.PROCESSING.value)
    assert updated.status == ScanStatus.COMPLETED.value  # Preserved!

    # Attempt invalid overwrite: COMPLETED -> ANALYZING
    updated = repo.update_scan_status(scan_id, ScanStatus.ANALYZING.value)
    assert updated.status == ScanStatus.COMPLETED.value  # Preserved!


def test_fail_scan_atomically_records_failure_and_audit(test_db):
    """Verify fail_scan transitions status to FAILED, records task error, and logs audit event."""
    repo = ScanRepository(test_db)
    scan_id = str(uuid.uuid4())
    user_id = "user_fail_test"

    repo.create_scan(scan_id=scan_id, user_id=user_id, input_type="url", raw_target="https://example.com")
    repo.update_scan_status(scan_id, ScanStatus.VALIDATING.value)

    scan = repo.fail_scan(
        scan_id=scan_id,
        error_code="TIMEOUT_LIMIT_EXCEEDED",
        error_message="Analysis exceeded maximum SLA timeout of 30s",
        engine_name="static_url_analyzer",
    )

    assert scan.status == ScanStatus.FAILED.value
    assert scan.completed_at is not None

    # Verify task was recorded
    tasks = test_db.query(Scan).filter(Scan.id == scan_id).first().tasks
    assert len(tasks) == 1
    assert tasks[0].status == "FAILED"
    assert tasks[0].error_code == "TIMEOUT_LIMIT_EXCEEDED"

    # Verify audit event was recorded
    audit_events = repo.get_audit_events(scan_id)
    fail_events = [e for e in audit_events if e.event_type == "SCAN_FAILED"]
    assert len(fail_events) == 1
    assert fail_events[0].details_json.get("error_code") == "TIMEOUT_LIMIT_EXCEEDED"


@pytest.mark.asyncio
async def test_unhandled_exception_in_url_scan_recovers_to_failed_state(test_db, monkeypatch):
    """Verify that an unexpected engine crash during execute_url_scan transitions scan to FAILED rather than hanging."""
    service = OrchestratorService(db=test_db)
    scan_id = str(uuid.uuid4())
    user_id = "user_crash_recovery"

    # Force an unhandled crash in aggregation
    def mock_crashing_aggregate(*args, **kwargs):
        raise RuntimeError("Simulated unhandled aggregator crash")

    from risk_engine.evidence_aggregator import EvidenceAggregator
    monkeypatch.setattr(EvidenceAggregator, "aggregate", mock_crashing_aggregate)

    with pytest.raises(RuntimeError):
        await service.execute_url_scan(
            target_url="https://crash-test.com",
            user_id=user_id,
            scan_id=scan_id,
            enable_sandbox=False,
        )

    # Check database state: must be transitioned to FAILED
    scan = service.repo.get_scan(scan_id, user_id=user_id)
    assert scan is not None
    assert scan.status == ScanStatus.FAILED.value
    assert scan.completed_at is not None

    # Check audit events for failure record
    audit_events = service.repo.get_audit_events(scan_id)
    assert any(e.event_type == "SCAN_FAILED" for e in audit_events)


@pytest.mark.asyncio
async def test_multimodal_scan_failure_transitions_to_failed_state(test_db, monkeypatch):
    """Verify that an unexpected multimodal extraction failure transitions scan to FAILED."""
    service = OrchestratorService(db=test_db)
    scan_id = str(uuid.uuid4())
    user_id = "user_mm_recovery"

    async def mock_crashing_multimodal(*args, **kwargs):
        raise ValueError("Simulated corrupted multimodal buffer")

    monkeypatch.setattr(service.multimodal_orchestrator, "analyze", mock_crashing_multimodal)

    with pytest.raises(ValueError):
        await service.execute_multimodal_scan(
            input_type="screenshot",
            user_id=user_id,
            content_bytes=b"fake-bytes",
            scan_id=scan_id,
        )

    scan = service.repo.get_scan(scan_id, user_id=user_id)
    assert scan is not None
    assert scan.status == ScanStatus.FAILED.value
    assert scan.completed_at is not None
