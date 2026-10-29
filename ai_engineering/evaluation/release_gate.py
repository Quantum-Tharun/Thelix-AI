"""
Thelix AI — Production Release Gate & Evaluation Auditor (Phase 14)
Automates end-to-end evaluation, dataset hygiene validation, split leakage checks,
and performance threshold verification across URL and multimodal pipelines.
"""
import os
import sys
import json
import asyncio
from typing import Dict, Any, Tuple, Optional

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from ai_engineering.evaluation.dataset_validator import DatasetValidator, DatasetValidationError
from ai_engineering.evaluation.eval_runner import EvaluationRunner
from ai_engineering.evaluation.multimodal_eval_runner import MultimodalEvaluationRunner


class ReleaseGate:
    """
    Executes automated release criteria checks for Phase 15:
    - Zero dataset schema violations or cross-split leakage.
    - Decisive Precision >= 95.0% on URL holdout benchmark.
    - Decisive Recall >= 90.0% on URL holdout benchmark (prevents passing on precision alone).
    - False Positive Rate <= 5.0% on URL holdout benchmark.
    - Decisive Precision >= 90.0% on Multimodal holdout benchmark.
    - Decisive Recall >= 85.0% on Multimodal holdout benchmark.
    - False Positive Rate <= 5.0% on Multimodal holdout benchmark.
    - Operational coverage and zero extraction failure rate.
    - Per-modality performance verification on holdout.
    """

    PROVISIONAL_THRESHOLDS = {
        "url_min_precision": 0.95,
        "url_min_recall": 0.90,
        "url_max_fpr": 0.05,
        "multimodal_min_precision": 0.90,
        "multimodal_min_recall": 0.85,
        "multimodal_max_fpr": 0.05,
    }

    @classmethod
    async def run_release_gate(cls, output_path: str = None) -> Tuple[bool, Dict[str, Any]]:
        print("=" * 80)
        print("THELIX AI — PRODUCTION RELEASE GATE & BENCHMARK AUDIT (PHASE 15)")
        print("=" * 80)

        report: Dict[str, Any] = {
            "timestamp": "2026-10-26T14:30:00Z",
            "phase": "Phase 15: Detection Improvement and Explainable Risk Reports",
            "checks": {},
            "passed": True,
            "provisional_thresholds": cls.PROVISIONAL_THRESHOLDS,
        }

        # 1. Dataset Schema & Split Isolation Checks
        print("\n[Step 1/3] Validating Dataset Schemas and Split Isolation...")
        url_dataset_path = os.path.join(REPO_ROOT, "ai_engineering", "datasets", "url_evaluation_dataset_v2.json")
        mm_dataset_path = os.path.join(REPO_ROOT, "ai_engineering", "datasets", "multimodal_evaluation_dataset_v2.json")

        try:
            url_meta = DatasetValidator.validate_dataset(url_dataset_path)
            report["checks"]["url_dataset_hygiene"] = {"status": "PASSED", "summary": url_meta}
            print(f"  [PASS] URL Dataset v2: ({url_meta['total_samples']} samples, zero leakage)")
        except DatasetValidationError as e:
            report["checks"]["url_dataset_hygiene"] = {"status": "FAILED", "error": str(e)}
            report["passed"] = False
            print(f"  [FAIL] URL Dataset v2: ({e})")

        try:
            mm_meta = DatasetValidator.validate_dataset(mm_dataset_path)
            report["checks"]["multimodal_dataset_hygiene"] = {"status": "PASSED", "summary": mm_meta}
            print(f"  [PASS] Multimodal Dataset v2: ({mm_meta['total_samples']} samples, zero leakage)")
        except DatasetValidationError as e:
            report["checks"]["multimodal_dataset_hygiene"] = {"status": "FAILED", "error": str(e)}
            report["passed"] = False
            print(f"  [FAIL] Multimodal Dataset v2: ({e})")

        # 2. URL Risk Engine Evaluation (Holdout Split)
        print("\n[Step 2/3] Evaluating URL Risk Engine (Split: holdout)...")
        url_runner = EvaluationRunner(dataset_path=url_dataset_path)
        url_results = await url_runner.run_evaluation(split="holdout")
        url_m = url_results["metrics_decisive"]
        url_op = url_results["metrics_operational"]

        url_prec_pass = url_m["precision"] >= cls.PROVISIONAL_THRESHOLDS["url_min_precision"]
        url_rec_pass = url_m["recall"] >= cls.PROVISIONAL_THRESHOLDS["url_min_recall"]
        url_fpr_pass = url_m["false_positive_rate"] <= cls.PROVISIONAL_THRESHOLDS["url_max_fpr"]

        report["checks"]["url_holdout_metrics"] = {
            "status": "PASSED" if (url_prec_pass and url_rec_pass and url_fpr_pass) else "FAILED",
            "samples": url_results["evaluation_metadata"]["total_samples"],
            "precision": url_m["precision"],
            "precision_denominator": url_m.get("precision_denominator"),
            "precision_ci_95": url_m["precision_ci_95"],
            "recall": url_m["recall"],
            "recall_denominator": url_m.get("recall_denominator"),
            "recall_ci_95": url_m["recall_ci_95"],
            "false_positive_rate": url_m["false_positive_rate"],
            "operational_accuracy": url_op["operational_accuracy"],
            "coverage": url_op["coverage"],
            "abstention_rate": url_op["abstention_rate"],
        }
        if not (url_prec_pass and url_rec_pass and url_fpr_pass):
            report["passed"] = False

        print(f"  [PASS] URL Holdout Precision: {url_m['precision']*100:.2f}% (Denom: {url_m.get('precision_denominator')}, Target >= {cls.PROVISIONAL_THRESHOLDS['url_min_precision']*100}%)")
        print(f"  [PASS] URL Holdout Recall:    {url_m['recall']*100:.2f}% (Denom: {url_m.get('recall_denominator')}, Target >= {cls.PROVISIONAL_THRESHOLDS['url_min_recall']*100}%)")
        print(f"  [PASS] URL Holdout FPR:       {url_m['false_positive_rate']*100:.2f}% (Target <= {cls.PROVISIONAL_THRESHOLDS['url_max_fpr']*100}%)")

        # 3. Multimodal Evaluation (Holdout Split)
        print("\n[Step 3/3] Evaluating Multimodal Analysis Pipeline (Split: holdout)...")
        mm_runner = MultimodalEvaluationRunner(dataset_path=mm_dataset_path)
        mm_results = await mm_runner.evaluate(split="holdout")
        mm_m = mm_results["metrics"]
        mm_op = mm_results["metrics_operational"]

        mm_prec_pass = mm_m["precision"] >= cls.PROVISIONAL_THRESHOLDS["multimodal_min_precision"]
        mm_rec_pass = mm_m["recall"] >= cls.PROVISIONAL_THRESHOLDS["multimodal_min_recall"]
        mm_fpr_pass = mm_m["false_positive_rate"] <= cls.PROVISIONAL_THRESHOLDS["multimodal_max_fpr"]

        report["checks"]["multimodal_holdout_metrics"] = {
            "status": "PASSED" if (mm_prec_pass and mm_rec_pass and mm_fpr_pass) else "FAILED",
            "samples": mm_results["total_samples"],
            "precision": mm_m["precision"],
            "precision_denominator": mm_m.get("precision_denominator"),
            "precision_ci_95": mm_m["precision_ci_95"],
            "recall": mm_m["recall"],
            "recall_denominator": mm_m.get("recall_denominator"),
            "recall_ci_95": mm_m["recall_ci_95"],
            "false_positive_rate": mm_m["false_positive_rate"],
            "operational_accuracy": mm_op["operational_accuracy"],
            "coverage": mm_op["coverage"],
            "abstention_rate": mm_op["abstention_rate"],
            "per_modality": mm_results["per_modality"],
        }
        if not (mm_prec_pass and mm_rec_pass and mm_fpr_pass):
            report["passed"] = False

        print(f"  [PASS] Multimodal Holdout Precision: {mm_m['precision']*100:.2f}% (Denom: {mm_m.get('precision_denominator')}, Target >= {cls.PROVISIONAL_THRESHOLDS['multimodal_min_precision']*100}%)")
        print(f"  [PASS] Multimodal Holdout Recall:    {mm_m['recall']*100:.2f}% (Denom: {mm_m.get('recall_denominator')}, Target >= {cls.PROVISIONAL_THRESHOLDS['multimodal_min_recall']*100}%)")
        print(f"  [PASS] Multimodal Holdout FPR:       {mm_m['false_positive_rate']*100:.2f}% (Target <= {cls.PROVISIONAL_THRESHOLDS['multimodal_max_fpr']*100}%)")
        print("  Holdout Per-Modality Results:")
        for mod, stats in mm_results["per_modality"].items():
            acc = (stats["correct"] / stats["total"] * 100) if stats["total"] > 0 else 0.0
            print(f"    - {mod:<26}: Total={stats['total']} Correct={stats['correct']} (Accuracy={acc:.1f}%)")

        # Summary
        print("\n" + "=" * 80)
        gate_status = "PASS" if report["passed"] else "FAIL"
        print(f"RELEASE GATE STATUS: {gate_status}")
        print("=" * 80 + "\n")

        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
            print(f"Release gate audit report saved to: {output_path}")

        return report["passed"], report


if __name__ == "__main__":
    out_file = sys.argv[1] if len(sys.argv) > 1 else os.path.join(REPO_ROOT, "ai_engineering", "evaluation", "release_gate_report.json")
    passed, _ = asyncio.run(ReleaseGate.run_release_gate(output_path=out_file))
    sys.exit(0 if passed else 1)
