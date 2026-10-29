"""
Evidence Aggregator
Aggregates, deduplicates, and correlates atomic Evidence and Findings from multiple engines.
Resolves correlation groups to prevent artificial double-penalization.
"""
from typing import List, Dict, Tuple, Set
from risk_engine.evidence import Evidence, Finding, Severity


class EvidenceAggregator:
    """
    Coordinates multi-source evidence fusion and finding consolidation.
    """

    @classmethod
    def aggregate(
        cls,
        evidence_list: List[Evidence],
        findings_list: List[Finding]
    ) -> Tuple[List[Evidence], List[Finding]]:
        """
        Deduplicates evidence and consolidates findings by correlation group.
        """
        deduped_evidence = cls._deduplicate_evidence(evidence_list)
        consolidated_findings = cls._consolidate_findings(findings_list, deduped_evidence)
        return deduped_evidence, consolidated_findings

    @classmethod
    def _deduplicate_evidence(cls, evidence_list: List[Evidence]) -> List[Evidence]:
        """
        Removes identical evidence observations from the same engine on the same indicator.
        """
        seen: Set[str] = set()
        unique: List[Evidence] = []

        for e in evidence_list:
            key = f"{e.source_engine}:{e.indicator_type}:{e.indicator_value_or_reference}"
            if key not in seen:
                seen.add(key)
                unique.append(e)

        return unique

    @classmethod
    def _consolidate_findings(
        cls,
        findings_list: List[Finding],
        evidence_list: List[Evidence]
    ) -> List[Finding]:
        """
        Consolidates multiple findings belonging to the same correlation group.
        Retains the maximum severity in each correlation group while merging evidence references.
        """
        evidence_by_id = {e.evidence_id: e for e in evidence_list}
        grouped_findings: Dict[str, List[Finding]] = {}
        standalone_findings: List[Finding] = []

        for f in findings_list:
            if f.correlation_group:
                grouped_findings.setdefault(f.correlation_group, []).append(f)
            else:
                standalone_findings.append(f)

        consolidated: List[Finding] = []

        for group, group_items in grouped_findings.items():
            if len(group_items) == 1:
                consolidated.append(group_items[0])
                continue

            # Multiple findings in the same correlation group:
            # Pick highest severity item as primary, merge evidence references
            primary = max(group_items, key=lambda item: item.severity_weight)
            all_refs = set(primary.evidence_references)
            for item in group_items:
                all_refs.update(item.evidence_references)
            primary.evidence_references = sorted(list(all_refs))

            # Combine confidence conservatively: 1 - prod(1 - c_i)
            comb_conf = 1.0
            for item in group_items:
                comb_conf *= (1.0 - item.confidence)
            primary.confidence = round(1.0 - comb_conf, 4)

            consolidated.append(primary)

        # Merge standalone findings
        consolidated.extend(standalone_findings)

        # Sort findings by severity weight descending
        consolidated.sort(key=lambda x: x.severity_weight, reverse=True)
        return consolidated
