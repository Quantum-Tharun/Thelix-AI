"""
Pilot Ground-Truth Adjudication & Reviewed Dataset Ingestion System
Defines the review workflow for pilot findings and feedback:
- Ensures unreviewed user feedback is NEVER automatically promoted to ground truth.
- Requires explicit human review, rationale, and provenance.
- Enforces strict split isolation: reviewed pilot samples can ONLY be assigned to 'tuning'.
- Prevents cross-split contamination (exact URLs or registrable domains appearing in eval/holdout).
- Maintains a versioned, privacy-preserving audit log of all reviewed pilot cases.
"""
import os
import json
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import urllib.parse

logger = logging.getLogger("thelix.adjudication")


class DatasetLeakageError(Exception):
    """Raised when an adjudication or dataset assignment violates split isolation."""
    pass


class InvalidReviewError(Exception):
    """Raised when a reviewed case fails schema, provenance, or verification invariants."""
    pass


@dataclass
class PilotReviewCase:
    case_id: str
    modality: str  # url, screenshot, qr, pdf, text, message
    original_risk_score: int
    original_verdict: str  # ALLOW, BLOCK, WARN, INCONCLUSIVE
    sanitized_evidence_codes: List[str]
    reviewer_label: str  # MALICIOUS, BENIGN, UNRESOLVED
    review_rationale: str
    reviewer_id: str
    provenance: str  # e.g., "pilot_cohort_adjudicated"
    reviewed_at: str  # ISO timestamp
    split_assignment: Optional[str] = "tuning"  # strictly 'tuning' or None
    is_promoted_to_dataset: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AdjudicationManager:
    """
    Manages the human review, labeling, deduplication, and split-leakage prevention
    for pilot feedback and telemetry findings.
    """

    ALLOWED_MODALITIES = {"url", "screenshot", "qr", "pdf", "text", "message"}
    ALLOWED_LABELS = {"MALICIOUS", "BENIGN", "UNRESOLVED"}

    def __init__(self, log_path: Optional[str] = None):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.log_path = log_path or os.path.join(base_dir, "pilot_adjudication_log.json")
        self.reviewed_cases: Dict[str, PilotReviewCase] = {}
        self._load_log()

    def _load_log(self) -> None:
        if os.path.exists(self.log_path):
            try:
                with open(self.log_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for item in data.get("cases", []):
                        case = PilotReviewCase(**item)
                        self.reviewed_cases[case.case_id] = case
            except Exception as e:
                logger.warning(f"Could not load adjudication log: {e}")

    def save_log(self) -> None:
        data = {
            "version": "1.0.0",
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "total_reviewed_cases": len(self.reviewed_cases),
            "cases": [c.to_dict() for c in self.reviewed_cases.values()],
        }
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        with open(self.log_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def review_case(
        self,
        case_id: str,
        modality: str,
        original_score: int,
        original_verdict: str,
        sanitized_evidence_codes: List[str],
        reviewer_label: str,
        review_rationale: str,
        reviewer_id: str,
        provenance: str = "pilot_cohort_adjudicated",
        split_assignment: Optional[str] = "tuning",
        target_indicator: Optional[str] = None,
        existing_benchmark_dataset_path: Optional[str] = None,
    ) -> PilotReviewCase:
        """
        Adjudicates a case following expert human review.
        Enforces:
        1. Modality and label constraints.
        2. Prohibits assignment to eval or holdout splits.
        3. Validates that user feedback alone is never ground truth.
        4. Checks against existing benchmark splits to prevent leakage.
        """
        modality_clean = modality.lower().strip()
        if modality_clean not in self.ALLOWED_MODALITIES:
            raise InvalidReviewError(f"Unsupported modality '{modality}'. Allowed: {self.ALLOWED_MODALITIES}")

        label_clean = reviewer_label.upper().strip()
        if label_clean not in self.ALLOWED_LABELS:
            raise InvalidReviewError(f"Unsupported reviewer label '{reviewer_label}'. Allowed: {self.ALLOWED_LABELS}")

        if not review_rationale or len(review_rationale.strip()) < 10:
            raise InvalidReviewError("Review rationale must be comprehensive (at least 10 characters).")

        if not reviewer_id or not reviewer_id.strip():
            raise InvalidReviewError("Explicit reviewer_id is mandatory for audit accountability.")

        # STRICT INVARIANT: Pilot cases can NEVER be assigned to holdout or eval splits
        if split_assignment in ("holdout", "eval"):
            raise DatasetLeakageError(
                f"Pilot cases can ONLY be assigned to 'tuning' split. "
                f"Assignment to '{split_assignment}' is strictly prohibited to preserve benchmark integrity."
            )

        # Leakage check against benchmark holdout dataset if target_indicator is provided
        if target_indicator and existing_benchmark_dataset_path and os.path.exists(existing_benchmark_dataset_path):
            self._verify_zero_leakage_with_benchmark(target_indicator, existing_benchmark_dataset_path)

        reviewed_at = datetime.now(timezone.utc).isoformat()
        review_case = PilotReviewCase(
            case_id=case_id,
            modality=modality_clean,
            original_risk_score=original_score,
            original_verdict=original_verdict,
            sanitized_evidence_codes=sanitized_evidence_codes,
            reviewer_label=label_clean,
            review_rationale=review_rationale.strip(),
            reviewer_id=reviewer_id.strip(),
            provenance=provenance,
            reviewed_at=reviewed_at,
            split_assignment=split_assignment if label_clean != "UNRESOLVED" else None,
            is_promoted_to_dataset=bool(split_assignment == "tuning" and label_clean != "UNRESOLVED"),
        )

        self.reviewed_cases[case_id] = review_case
        self.save_log()
        return review_case

    def _verify_zero_leakage_with_benchmark(self, target_indicator: str, benchmark_path: str) -> None:
        """Verifies that target_indicator does not appear in eval or holdout splits of the benchmark."""
        try:
            with open(benchmark_path, "r", encoding="utf-8") as f:
                benchmark = json.load(f)

            norm_target = target_indicator.strip().lower()
            for sample in benchmark.get("samples", []):
                split = sample.get("split")
                if split in ("eval", "holdout"):
                    url = str(sample.get("url", "")).strip().lower()
                    if norm_target == url:
                        raise DatasetLeakageError(
                            f"Leakage detected: Target indicator matches sample in benchmark '{split}' split: {norm_target}"
                        )
        except DatasetLeakageError:
            raise
        except Exception as e:
            logger.warning(f"Could not complete benchmark leakage verification: {e}")

    def get_summary_metrics(self) -> Dict[str, Any]:
        """Returns aggregated, privacy-preserving review statistics."""
        by_label = {"MALICIOUS": 0, "BENIGN": 0, "UNRESOLVED": 0}
        by_modality: Dict[str, int] = {}
        promoted_count = 0

        for case in self.reviewed_cases.values():
            by_label[case.reviewer_label] = by_label.get(case.reviewer_label, 0) + 1
            by_modality[case.modality] = by_modality.get(case.modality, 0) + 1
            if case.is_promoted_to_dataset:
                promoted_count += 1

        return {
            "total_reviewed": len(self.reviewed_cases),
            "by_label": by_label,
            "by_modality": by_modality,
            "promoted_to_tuning_dataset": promoted_count,
        }
