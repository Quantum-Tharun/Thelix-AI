"""
Thelix AI — Evaluation Dataset Validator & Split Leakage Checker
Ensures schema compliance, label validity, provenance tracking,
and guarantees ZERO split leakage across tuning, eval, and holdout splits.
"""
import os
import json
import urllib.parse
from typing import Dict, List, Set, Any, Tuple


class DatasetValidationError(Exception):
    """Raised when an evaluation dataset fails schema or split isolation checks."""
    pass


class DatasetValidator:
    """
    Validates evaluation datasets against strict data hygiene rules:
    1. Schema and metadata completeness.
    2. Unique sample IDs.
    3. Valid ground-truth labels and rationale.
    4. Exact payload and domain-level split isolation (zero cross-split leakage).
    """

    VALID_SPLITS = {"tuning", "eval", "holdout"}
    VALID_LABELS = {"BENIGN", "MALICIOUS", "INCONCLUSIVE_OR_FAILURE"}

    @classmethod
    def extract_domain(cls, url_or_target: str) -> str:
        """Extracts normalized hostname from URL, or returns empty string if not a URL."""
        try:
            parsed = urllib.parse.urlparse(url_or_target)
            return (parsed.hostname or "").lower()
        except Exception:
            return ""

    @classmethod
    def validate_dataset(cls, dataset_path: str) -> Dict[str, Any]:
        """
        Validates the specified dataset file.
        Returns a summary dictionary of dataset statistics.
        Raises DatasetValidationError on any violation.
        """
        if not os.path.exists(dataset_path):
            raise DatasetValidationError(f"Dataset file not found at: {dataset_path}")

        try:
            with open(dataset_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise DatasetValidationError(f"Corrupted JSON in {dataset_path}: {e}")

        metadata = data.get("dataset_metadata")
        if not metadata:
            raise DatasetValidationError(f"Missing 'dataset_metadata' in {dataset_path}")

        required_meta_keys = ["dataset_id", "version", "splits", "total_samples"]
        for k in required_meta_keys:
            if k not in metadata:
                raise DatasetValidationError(f"Missing required metadata key '{k}' in {dataset_path}")

        samples = data.get("samples", [])
        if not samples:
            raise DatasetValidationError(f"Dataset contains zero samples: {dataset_path}")

        if len(samples) != metadata["total_samples"]:
            raise DatasetValidationError(
                f"Sample count mismatch: metadata specifies {metadata['total_samples']} "
                f"but found {len(samples)} samples"
            )

        seen_ids: Set[str] = set()
        split_samples: Dict[str, List[Dict[str, Any]]] = {s: [] for s in cls.VALID_SPLITS}
        split_domains: Dict[str, Set[str]] = {s: set() for s in cls.VALID_SPLITS}
        split_payloads: Dict[str, Set[str]] = {s: set() for s in cls.VALID_SPLITS}

        label_counts: Dict[str, int] = {}
        provenance_counts: Dict[str, int] = {}

        for idx, sample in enumerate(samples):
            sid = sample.get("sample_id")
            if not sid:
                raise DatasetValidationError(f"Sample at index {idx} has missing 'sample_id'")
            if sid in seen_ids:
                raise DatasetValidationError(f"Duplicate sample_id '{sid}' at index {idx}")
            seen_ids.add(sid)

            split = sample.get("dataset_split")
            if split not in cls.VALID_SPLITS:
                raise DatasetValidationError(
                    f"Sample '{sid}' has invalid split '{split}'. Must be one of {cls.VALID_SPLITS}"
                )
            split_samples[split].append(sample)

            gt = sample.get("ground_truth_label")
            if gt not in cls.VALID_LABELS:
                raise DatasetValidationError(
                    f"Sample '{sid}' has invalid ground_truth_label '{gt}'. Must be one of {cls.VALID_LABELS}"
                )
            label_counts[gt] = label_counts.get(gt, 0) + 1

            conf = sample.get("label_confidence")
            if conf is None or not (0.0 <= float(conf) <= 1.0):
                raise DatasetValidationError(
                    f"Sample '{sid}' missing or invalid 'label_confidence' ({conf}). Must be 0.0 to 1.0"
                )

            provenance = sample.get("provenance_type") or sample.get("label_source", "unspecified")
            provenance_counts[provenance] = provenance_counts.get(provenance, 0) + 1

            # Extract payload identity for leakage checking
            target_payload = (
                sample.get("url")
                or sample.get("text_content")
                or sample.get("image_path")
                or sample.get("sample_id")
            )
            split_payloads[split].add(str(target_payload).strip().lower())

            # If it's a URL, track domain
            if "url" in sample:
                domain = cls.extract_domain(sample["url"])
                if domain:
                    split_domains[split].add(domain)

        # Split metadata count check
        meta_splits = metadata.get("splits", {})
        for split_name, expected_count in meta_splits.items():
            actual_count = len(split_samples.get(split_name, []))
            if actual_count != expected_count:
                raise DatasetValidationError(
                    f"Split '{split_name}' count mismatch: metadata expected {expected_count}, "
                    f"but dataset contains {actual_count}"
                )

        # LEAKAGE CHECKS
        # 1. Exact payload overlap check between any two distinct splits
        splits_list = list(cls.VALID_SPLITS)
        for i in range(len(splits_list)):
            for j in range(i + 1, len(splits_list)):
                s1, s2 = splits_list[i], splits_list[j]
                overlap = split_payloads[s1].intersection(split_payloads[s2])
                if overlap:
                    raise DatasetValidationError(
                        f"Prohibited exact payload leakage detected between '{s1}' and '{s2}': {list(overlap)[:5]}"
                    )

        # 2. Domain-level overlap check between holdout and (tuning/eval)
        holdout_tuning_domain_leak = split_domains["holdout"].intersection(split_domains["tuning"])
        if holdout_tuning_domain_leak:
            raise DatasetValidationError(
                f"Prohibited domain leakage between holdout and tuning: {list(holdout_tuning_domain_leak)[:5]}"
            )

        holdout_eval_domain_leak = split_domains["holdout"].intersection(split_domains["eval"])
        if holdout_eval_domain_leak:
            raise DatasetValidationError(
                f"Prohibited domain leakage between holdout and eval: {list(holdout_eval_domain_leak)[:5]}"
            )

        return {
            "dataset_id": metadata["dataset_id"],
            "version": metadata["version"],
            "total_samples": len(samples),
            "split_distribution": {k: len(v) for k, v in split_samples.items()},
            "label_distribution": label_counts,
            "provenance_distribution": provenance_counts,
            "status": "VALID_AND_LEAKAGE_FREE",
        }


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python dataset_validator.py <path_to_dataset.json>")
        sys.exit(1)
    try:
        summary = DatasetValidator.validate_dataset(sys.argv[1])
        print("Dataset validation passed:")
        print(json.dumps(summary, indent=2))
    except DatasetValidationError as e:
        print(f"Validation Error: {e}", file=sys.stderr)
        sys.exit(2)
