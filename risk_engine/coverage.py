"""
Coverage Tracker
Tracks the completeness of intended security checks.
Calculates coverage ratio and articulates analytical limitations.
"""
from dataclasses import dataclass, field
from typing import List, Set


@dataclass
class CoverageAssessment:
    """Detailed record of check completion and coverage ratio."""
    planned_checks: List[str]
    completed_checks: List[str]
    failed_checks: List[str]
    skipped_checks: List[str]
    coverage_ratio: float
    limitations: List[str] = field(default_factory=list)


class CoverageTracker:
    """
    Monitors which planned security checks executed successfully, failed, or were skipped.
    """

    @classmethod
    def evaluate(
        cls,
        planned: List[str],
        completed: List[str],
        failed: List[str],
        skipped: List[str]
    ) -> CoverageAssessment:
        planned_set: Set[str] = set(planned)
        completed_set: Set[str] = set(completed)
        failed_set: Set[str] = set(failed)
        skipped_set: Set[str] = set(skipped)

        total_planned = len(planned_set)
        if total_planned == 0:
            ratio = 1.0
        else:
            ratio = round(len(completed_set.intersection(planned_set)) / total_planned, 4)

        limitations: List[str] = []
        for f in sorted(list(failed_set)):
            limitations.append(f"Check '{f}' failed during execution and could not contribute evidence.")
        for s in sorted(list(skipped_set)):
            limitations.append(f"Check '{s}' was skipped according to security or execution policy.")

        if ratio < 0.50:
            limitations.append(f"Analysis coverage is limited ({int(ratio * 100)}%). Assessment may be incomplete.")

        return CoverageAssessment(
            planned_checks=sorted(list(planned_set)),
            completed_checks=sorted(list(completed_set)),
            failed_checks=sorted(list(failed_set)),
            skipped_checks=sorted(list(skipped_set)),
            coverage_ratio=ratio,
            limitations=limitations,
        )
