"""
Evidence & Findings Models
Defines immutable, normalized evidence records and aggregated findings.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> float:
        weights = {
            Severity.INFO: 0.0,
            Severity.LOW: 0.20,
            Severity.MEDIUM: 0.50,
            Severity.HIGH: 0.80,
            Severity.CRITICAL: 1.00,
        }
        return weights[self]


class ActionVerdict(str, Enum):
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"
    INCONCLUSIVE = "inconclusive"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class Evidence:
    """
    Normalized Evidence Record.
    Represents an atomic, tamper-evident observation made by an analysis engine.
    """
    evidence_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: Optional[str] = None
    indicator_type: str = ""                     # e.g., 'ip_literal', 'userinfo', 'idn_homograph', 'safe_browsing'
    indicator_value_or_reference: str = ""      # Exact indicator string or hash
    source_engine: str = ""                     # Engine identifier
    source_version: str = "1.0.0"               # Engine version
    observed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    observation: Dict[str, Any] = field(default_factory=dict)
    reliability: float = 1.0                    # Source reliability [0.0 - 1.0]
    confidence: float = 1.0                     # Observation confidence [0.0 - 1.0]
    correlation_group: Optional[str] = None     # Group to prevent double-counting correlated signals
    provenance: Optional[str] = None            # Origin metadata or citation

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "scan_id": self.scan_id,
            "indicator_type": self.indicator_type,
            "indicator_value_or_reference": self.indicator_value_or_reference,
            "source_engine": self.source_engine,
            "source_version": self.source_version,
            "observed_at": self.observed_at.isoformat(),
            "observation": self.observation,
            "reliability": self.reliability,
            "confidence": self.confidence,
            "correlation_group": self.correlation_group,
            "provenance": self.provenance,
        }


@dataclass
class Finding:
    """
    Aggregated Finding.
    Combines correlated evidence items into a high-level actionable security insight.
    """
    finding_code: str                           # Stable identifier (e.g. 'FIND-URL-IP-HOST')
    title: str
    description: str
    severity: Severity
    confidence: float                           # Aggregated confidence [0.0 - 1.0]
    source_engine: str
    source_version: str
    evidence_references: List[str] = field(default_factory=list)
    correlation_group: Optional[str] = None
    applicable_limitations: List[str] = field(default_factory=list)
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    category: str = "security_finding"
    confidence_meaning: str = "Deterministic heuristic detector confidence [0.0 - 1.0]"
    safe_excerpt: Optional[str] = None
    observed_versus_inferred: str = "directly_observed"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def severity_weight(self) -> float:
        return self.severity.weight

    @property
    def contribution(self) -> float:
        """Preliminary weighted contribution: severity_weight * confidence"""
        return self.severity_weight * self.confidence

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "finding_code": self.finding_code,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "confidence": round(self.confidence, 4),
            "confidence_meaning": self.confidence_meaning,
            "category": self.category,
            "source_engine": self.source_engine,
            "source_version": self.source_version,
            "evidence_references": self.evidence_references,
            "correlation_group": self.correlation_group,
            "applicable_limitations": self.applicable_limitations,
            "safe_excerpt": self.safe_excerpt,
            "observed_versus_inferred": self.observed_versus_inferred,
            "created_at": self.created_at.isoformat(),
        }
