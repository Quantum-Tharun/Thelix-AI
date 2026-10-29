"""
Multi-process concurrency test helpers for Thelix AI database testing.
Provides picklable worker targets for multiprocessing.Process across separate OS processes.
"""
import os
import time
from typing import Optional
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.models.entities import Base
from app.repositories.scan_repository import ScanRepository


def run_process_quota_reservation_worker(
    db_url: str,
    user_id: str,
    date_key: str,
    limit: int,
    queue,
) -> None:
    """
    Executes in a separate operating-system worker process with an isolated
    database connection and session.
    """
    connect_args = {}
    if db_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
        connect_args["timeout"] = 30.0

    engine = create_engine(db_url, connect_args=connect_args, pool_pre_ping=True)
    if db_url.startswith("sqlite") and ":memory:" not in db_url:
        with engine.connect() as conn:
            conn.execute(text("PRAGMA journal_mode=WAL;"))
            conn.execute(text("PRAGMA busy_timeout=30000;"))
            conn.commit()

    SessionLocal = sessionmaker(autocommit=False, autoflush=False, expire_on_commit=False, bind=engine)
    session = SessionLocal()
    try:
        repo = ScanRepository(session)
        success = repo.reserve_daily_scan_quota(user_id=user_id, date_key=date_key, limit=limit)
        queue.put({"success": success, "error": None})
    except Exception as exc:
        queue.put({"success": False, "error": f"{type(exc).__name__}: {str(exc)}"})
    finally:
        session.close()
        engine.dispose()


def run_process_quota_refund_worker(
    db_url: str,
    user_id: str,
    date_key: str,
    scan_id: Optional[str],
    queue,
) -> None:
    """
    Executes in a separate OS process to test concurrent refund idempotency.
    """
    connect_args = {}
    if db_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
        connect_args["timeout"] = 30.0

    engine = create_engine(db_url, connect_args=connect_args, pool_pre_ping=True)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, expire_on_commit=False, bind=engine)
    session = SessionLocal()
    try:
        repo = ScanRepository(session)
        refunded = repo.refund_daily_scan_quota(user_id=user_id, date_key=date_key, scan_id=scan_id)
        queue.put({"refunded": refunded, "error": None})
    except Exception as exc:
        queue.put({"refunded": False, "error": f"{type(exc).__name__}: {str(exc)}"})
    finally:
        session.close()
        engine.dispose()


def run_process_worker_claim_and_crash(
    db_url: str,
    worker_id: str,
    lease_duration_seconds: int,
    ready_event,
) -> None:
    """
    Simulates a worker process claiming a task and then crashing / terminating abruptly
    without completing or acknowledging the task.
    """
    connect_args = {}
    if db_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
        connect_args["timeout"] = 30.0

    engine = create_engine(db_url, connect_args=connect_args, pool_pre_ping=True)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, expire_on_commit=False, bind=engine)
    session = SessionLocal()
    try:
        repo = ScanRepository(session)
        task = repo.claim_next_task(worker_id=worker_id, lease_duration_seconds=lease_duration_seconds)
        if ready_event is not None:
            ready_event.set()
        # Abrupt termination simulation: process exits without updating/failing task
    finally:
        session.close()
        engine.dispose()
