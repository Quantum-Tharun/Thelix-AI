"""
Relational Database Entities
SQLAlchemy models for Thelix AI scans, tasks, evidence, findings, reports, and audit logs.
"""
import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    String,
    Integer,
    Float,
    Boolean,
    DateTime,
    ForeignKey,
    Text,
    JSON,
    Index,
)
from sqlalchemy.orm import relationship

from app.database.session import Base


from enum import Enum
from typing import Set, Dict


class ScanStatus(str, Enum):
    """Authoritative scan lifecycle status values."""
    QUEUED = "QUEUED"
    VALIDATING = "VALIDATING"
    EXTRACTING = "EXTRACTING"
    PROCESSING = "PROCESSING"
    ANALYZING = "ANALYZING"
    AGGREGATING = "AGGREGATING"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    REJECTED = "REJECTED"
    CANCELLED = "CANCELLED"


# Terminal states cannot be overwritten by non-terminal transitions
TERMINAL_SCAN_STATES: Set[str] = {
    ScanStatus.COMPLETED.value,
    ScanStatus.PARTIAL.value,
    ScanStatus.FAILED.value,
    ScanStatus.REJECTED.value,
    ScanStatus.CANCELLED.value,
}

VALID_STATUS_TRANSITIONS: Dict[str, Set[str]] = {
    ScanStatus.QUEUED.value: {
        ScanStatus.VALIDATING.value,
        ScanStatus.PROCESSING.value,
        ScanStatus.CANCELLED.value,
        ScanStatus.FAILED.value,
    },
    ScanStatus.VALIDATING.value: {
        ScanStatus.VALIDATING.value,
        ScanStatus.EXTRACTING.value,
        ScanStatus.ANALYZING.value,
        ScanStatus.PROCESSING.value,
        ScanStatus.REJECTED.value,
        ScanStatus.FAILED.value,
        ScanStatus.CANCELLED.value,
    },
    ScanStatus.EXTRACTING.value: {
        ScanStatus.ANALYZING.value,
        ScanStatus.PROCESSING.value,
        ScanStatus.FAILED.value,
        ScanStatus.CANCELLED.value,
    },
    ScanStatus.PROCESSING.value: {
        ScanStatus.COMPLETED.value,
        ScanStatus.PARTIAL.value,
        ScanStatus.FAILED.value,
        ScanStatus.CANCELLED.value,
    },
    ScanStatus.ANALYZING.value: {
        ScanStatus.AGGREGATING.value,
        ScanStatus.COMPLETED.value,
        ScanStatus.PARTIAL.value,
        ScanStatus.FAILED.value,
        ScanStatus.CANCELLED.value,
    },
    ScanStatus.AGGREGATING.value: {
        ScanStatus.COMPLETED.value,
        ScanStatus.PARTIAL.value,
        ScanStatus.FAILED.value,
        ScanStatus.CANCELLED.value,
    },
    ScanStatus.COMPLETED.value: set(),
    ScanStatus.PARTIAL.value: set(),
    ScanStatus.FAILED.value: set(),
    ScanStatus.REJECTED.value: set(),
    ScanStatus.CANCELLED.value: set(),
}


def gen_uuid() -> str:
    return str(uuid.uuid4())


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    user_id = Column(String(64), nullable=False, index=True)  # References Supabase Auth UID
    input_type = Column(String(50), nullable=False)  # 'url', 'screenshot', 'qr', 'document'
    raw_target = Column(Text, nullable=False)
    normalized_target = Column(Text, nullable=True)
    status = Column(String(50), nullable=False, default="QUEUED", index=True)
    policy_version = Column(String(20), default="1.0.0", nullable=False)
    engine_versions = Column(JSON, default=dict, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False, index=True)
    completed_at = Column(DateTime, nullable=True)

    tasks = relationship("ScanTask", back_populates="scan", cascade="all, delete-orphan")
    evidence = relationship("EvidenceRecord", back_populates="scan", cascade="all, delete-orphan")
    findings = relationship("FindingRecord", back_populates="scan", cascade="all, delete-orphan")
    assessment = relationship("RiskAssessment", back_populates="scan", uselist=False, cascade="all, delete-orphan")
    artifacts = relationship("Artifact", back_populates="scan", cascade="all, delete-orphan")
    feedback = relationship("ScanFeedback", back_populates="scan", cascade="all, delete-orphan")
    audit_events = relationship("AuditEvent", back_populates="scan")


class Artifact(Base):
    __tablename__ = "artifacts"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    artifact_type = Column(String(50), nullable=False)  # 'screenshot', 'qr_image', 'dom_snapshot'
    storage_path = Column(Text, nullable=False)
    file_hash = Column(String(64), nullable=True)
    mime_type = Column(String(100), nullable=False)
    file_size_bytes = Column(Integer, nullable=False)
    retention_until = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    scan = relationship("Scan", back_populates="artifacts")


class ScanTask(Base):
    __tablename__ = "scan_tasks"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    engine_name = Column(String(100), nullable=False)
    status = Column(String(50), nullable=False, default="PENDING")
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    latency_ms = Column(Integer, default=0, nullable=False)
    error_code = Column(String(50), nullable=True)
    error_message = Column(Text, nullable=True)

    # Durable Outbox Worker & Lease Fields
    lease_owner = Column(String(64), nullable=True, index=True)
    lease_expires_at = Column(DateTime, nullable=True, index=True)
    attempt_count = Column(Integer, default=0, nullable=False)
    max_attempts = Column(Integer, default=3, nullable=False)
    payload_json = Column(JSON, default=dict, nullable=False)

    __table_args__ = (
        Index("idx_scan_tasks_claim", "status", "lease_expires_at"),
    )

    scan = relationship("Scan", back_populates="tasks")


class EvidenceRecord(Base):
    __tablename__ = "evidence"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    indicator_type = Column(String(100), nullable=False)
    indicator_value_or_reference = Column(Text, nullable=False)
    source_engine = Column(String(100), nullable=False)
    source_version = Column(String(20), nullable=False)
    reliability = Column(Float, nullable=False)
    confidence = Column(Float, nullable=False)
    correlation_group = Column(String(100), nullable=True)
    observation_json = Column(JSON, default=dict, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    scan = relationship("Scan", back_populates="evidence")


class FindingRecord(Base):
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_code = Column(String(100), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False)
    confidence = Column(Float, nullable=False)
    source_engine = Column(String(100), nullable=False)
    source_version = Column(String(20), nullable=False)
    correlation_group = Column(String(100), nullable=True)
    evidence_refs_json = Column(JSON, default=list, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    scan = relationship("Scan", back_populates="findings")


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    risk_score = Column(Integer, nullable=False)
    trust_score = Column(Integer, nullable=False)
    risk_level = Column(String(20), nullable=False)
    confidence = Column(Float, nullable=False)
    coverage_ratio = Column(Float, nullable=False)
    recommended_action = Column(String(20), nullable=False)
    summary = Column(Text, nullable=False)
    explanation = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    scan = relationship("Scan", back_populates="assessment")


class ScanFeedback(Base):
    __tablename__ = "scan_feedback"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(String(64), nullable=False, index=True)  # References Supabase Auth UID
    rating = Column(String(50), nullable=False)  # 'helpful', 'false_positive', 'false_negative'
    comments = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    scan = relationship("Scan", back_populates="feedback")


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True)
    user_id = Column(String(36), nullable=True, index=True)
    event_type = Column(String(100), nullable=False)
    details_json = Column(JSON, default=dict, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False, index=True)
    scan = relationship("Scan", back_populates="audit_events")


class UserDailyQuota(Base):
    __tablename__ = "user_daily_quotas"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    user_id = Column(String(64), nullable=False, index=True)
    date_key = Column(String(10), nullable=False, index=True)  # YYYY-MM-DD
    scan_count = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    __table_args__ = (
        Index("ix_user_daily_quota_unique", "user_id", "date_key", unique=True),
    )


class QuotaRefundRecord(Base):
    __tablename__ = "quota_refund_records"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    scan_id = Column(String(36), nullable=False, unique=True, index=True)
    user_id = Column(String(64), nullable=False, index=True)
    date_key = Column(String(10), nullable=False, index=True)  # YYYY-MM-DD
    refunded_at = Column(DateTime, default=utc_now, nullable=False)

