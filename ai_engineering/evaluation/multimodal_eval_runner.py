"""
Thelix AI — Multimodal Threat Evaluation Benchmark Runner (Phase 12)
Measures detection precision, recall, false-positive/negative rates,
confusion matrices, extraction failure rates, and Wilson score confidence intervals
across suspicious messages, QR codes, PDFs, screenshots, and prompt injection attacks.
"""
import os
import sys
import io
import json
import math
import asyncio
import argparse
from typing import Dict, List, Any, Optional, Tuple

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import qrcode
from pypdf import PdfWriter
from PIL import Image

from ai_engineering.multimodal.contracts import InputType, MultimodalAnalysisReport
from ai_engineering.multimodal.multimodal_orchestrator import MultimodalOrchestrator
from risk_engine.evidence import ActionVerdict


from ai_engineering.evaluation.metrics import EvaluationMetrics, wilson_score_interval


def generate_synthetic_qr(payload: str) -> bytes:
    if not payload:
        # Generate blank image (no QR)
        img = Image.new("RGB", (200, 200), color="white")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()
    qr = qrcode.QRCode(box_size=10, border=8)
    qr.add_data(payload)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def generate_synthetic_pdf(text: str, links: Optional[List[str]] = None) -> bytes:
    """Generates synthetic PDF with exact xref table offsets to eliminate parser warnings."""
    if not text:
        writer = PdfWriter()
        writer.add_blank_page(width=612, height=792)
        buf = io.BytesIO()
        writer.write(buf)
        return buf.getvalue()

    full_text = text
    if links:
        full_text += "\n" + "\n".join(links)

    safe_text = full_text.replace("(", r"\(").replace(")", r"\)")
    stream_content = f"BT /F1 12 Tf 50 720 Td ({safe_text}) Tj ET"
    stream_bytes = stream_content.encode("latin-1", errors="replace")

    buf = bytearray()
    offsets = []

    buf.extend(b"%PDF-1.4\n")

    offsets.append(len(buf))
    buf.extend(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")

    offsets.append(len(buf))
    buf.extend(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")

    offsets.append(len(buf))
    buf.extend(b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>\nendobj\n")

    offsets.append(len(buf))
    buf.extend(f"4 0 obj\n<< /Length {len(stream_bytes)} >>\nstream\n".encode("ascii"))
    buf.extend(stream_bytes)
    buf.extend(b"\nendstream\nendobj\n")

    offsets.append(len(buf))
    buf.extend(b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n")

    startxref = len(buf)
    buf.extend(b"xref\n0 6\n0000000000 65535 f \n")
    for off in offsets:
        buf.extend(f"{off:010d} 00000 n \n".encode("ascii"))
    buf.extend(f"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{startxref}\n%%EOF\n".encode("ascii"))

    return bytes(buf)


class MultimodalEvaluationRunner:
    def __init__(self, dataset_path: Optional[str] = None):
        v2_path = os.path.join(REPO_ROOT, "ai_engineering", "datasets", "multimodal_evaluation_dataset_v2.json")
        v1_path = os.path.join(REPO_ROOT, "ai_engineering", "datasets", "multimodal_evaluation_dataset_v1.json")
        default_path = v2_path if os.path.exists(v2_path) else v1_path
        self.dataset_path = dataset_path or default_path
        with open(self.dataset_path, "r", encoding="utf-8") as f:
            self.data = json.load(f)
        self.metadata = self.data["dataset_metadata"]
        self.samples = self.data["samples"]
        self.orchestrator = MultimodalOrchestrator()

    async def evaluate(self, split: str = "all") -> Dict[str, Any]:
        filtered_samples = [
            s for s in self.samples
            if split == "all" or s.get("dataset_split") == split
        ]

        # Counters
        tp, fp, tn, fn = 0, 0, 0, 0
        inconclusive_count = 0
        inconclusive_benign = 0
        inconclusive_malicious = 0
        extraction_failures = 0

        modality_stats: Dict[str, Dict[str, int]] = {}
        sample_results: List[Dict[str, Any]] = []

        for sample in filtered_samples:
            s_id = sample["sample_id"]
            m_type_str = sample["input_type"]
            gt_label = sample["ground_truth_label"]
            gt_policy = sample["ground_truth_policy"]

            if m_type_str not in modality_stats:
                modality_stats[m_type_str] = {"total": 0, "correct": 0, "tp": 0, "fp": 0, "tn": 0, "fn": 0, "inconclusive": 0}
            modality_stats[m_type_str]["total"] += 1

            # Prepare Input
            file_bytes: Optional[bytes] = None
            filename: Optional[str] = None
            text_content: Optional[str] = None
            input_type_enum = InputType.MESSAGE_TEXT

            if m_type_str in ("suspicious_message", "adversarial_prompt_injection"):
                input_type_enum = InputType.MESSAGE_TEXT
                text_content = sample["text_content"]
            elif m_type_str == "qr_code":
                input_type_enum = InputType.QR_CODE
                filename = f"{s_id}.png"
                file_bytes = generate_synthetic_qr(sample.get("qr_payload", ""))
            elif m_type_str == "pdf_document":
                input_type_enum = InputType.DOCUMENT_PDF
                filename = f"{s_id}.pdf"
                file_bytes = generate_synthetic_pdf(sample.get("pdf_text", ""), sample.get("pdf_links", []))
            elif m_type_str == "screenshot":
                input_type_enum = InputType.SCREENSHOT
                filename = f"{s_id}.png"
                # For synthetic screenshot tests without external OCR hardware, we test direct OCR pipeline or synthetic image
                ocr_txt = sample.get("ocr_text") or sample.get("screenshot_text", "")
                if ocr_txt:
                    text_content = ocr_txt
                    input_type_enum = InputType.MESSAGE_TEXT
                else:
                    file_bytes = generate_synthetic_qr("")

            # Run Orchestrator
            try:
                report: MultimodalAnalysisReport = await self.orchestrator.analyze(
                    input_type=input_type_enum,
                    content_bytes=file_bytes,
                    filename=filename,
                    text_content=text_content,
                    context=f"Evaluation test sample {s_id}",
                )
            except Exception as e:
                extraction_failures += 1
                sample_results.append({
                    "sample_id": s_id,
                    "input_type": m_type_str,
                    "error": str(e),
                    "success": False,
                })
                continue

            verdict = report.recommended_action
            score = report.risk_score

            # Check if extraction had limitations or failed
            if report.limitations and any("LIMITATION" in lim for lim in report.limitations):
                if gt_label == "INCONCLUSIVE_OR_FAILURE":
                    inconclusive_count += 1
                    modality_stats[m_type_str]["inconclusive"] += 1
                    modality_stats[m_type_str]["correct"] += 1
                    sample_results.append({
                        "sample_id": s_id,
                        "input_type": m_type_str,
                        "ground_truth": gt_label,
                        "verdict": verdict.value if verdict else "NONE",
                        "status": "CORRECT_LIMITATION",
                    })
                    continue

            # Classify decision
            is_predicted_malicious = (verdict in (ActionVerdict.BLOCK, ActionVerdict.WARN)) or (score >= 40)
            is_ground_truth_malicious = (gt_label == "MALICIOUS")

            if verdict == ActionVerdict.INCONCLUSIVE:
                inconclusive_count += 1
                modality_stats[m_type_str]["inconclusive"] += 1
                if gt_label == "INCONCLUSIVE_OR_FAILURE":
                    modality_stats[m_type_str]["correct"] += 1
                    status = "CORRECT_INCONCLUSIVE"
                elif is_ground_truth_malicious:
                    inconclusive_malicious += 1
                    status = "INCONCLUSIVE_MALICIOUS"
                else:
                    inconclusive_benign += 1
                    status = "INCONCLUSIVE_BENIGN"
            elif is_ground_truth_malicious and is_predicted_malicious:
                tp += 1
                modality_stats[m_type_str]["tp"] += 1
                modality_stats[m_type_str]["correct"] += 1
                status = "TRUE_POSITIVE"
            elif not is_ground_truth_malicious and not is_predicted_malicious:
                tn += 1
                modality_stats[m_type_str]["tn"] += 1
                modality_stats[m_type_str]["correct"] += 1
                status = "TRUE_NEGATIVE"
            elif not is_ground_truth_malicious and is_predicted_malicious:
                fp += 1
                modality_stats[m_type_str]["fp"] += 1
                status = "FALSE_POSITIVE"
            else:
                fn += 1
                modality_stats[m_type_str]["fn"] += 1
                status = "FALSE_NEGATIVE"

            sample_results.append({
                "sample_id": s_id,
                "input_type": m_type_str,
                "ground_truth": gt_label,
                "predicted_verdict": verdict.value if verdict else "NONE",
                "risk_score": score,
                "status": status,
                "findings": [f.finding_code for f in report.findings],
            })

        # Calculate metrics via EvaluationMetrics engine
        eval_metrics = EvaluationMetrics(
            tp=tp, fp=fp, tn=tn, fn=fn,
            inconclusive_benign=inconclusive_benign,
            inconclusive_malicious=inconclusive_malicious,
            extraction_failures=extraction_failures,
        )
        metrics_dict = eval_metrics.to_dict()

        summary = {
            "dataset_id": self.metadata["dataset_id"],
            "dataset_version": self.metadata["version"],
            "split": split,
            "total_samples": len(filtered_samples),
            "confusion_matrix": {
                "true_positives": tp,
                "false_positives": fp,
                "true_negatives": tn,
                "false_negatives": fn,
                "inconclusive_benign": inconclusive_benign,
                "inconclusive_malicious": inconclusive_malicious,
                "total_inconclusive": inconclusive_count,
                "extraction_failures": extraction_failures,
            },
            "metrics": metrics_dict["metrics_decisive"],
            "metrics_operational": metrics_dict["metrics_operational"],
            "per_modality": modality_stats,
            "sample_details": sample_results,
        }
        return summary


def print_summary_table(summary: Dict[str, Any]):
    print("\n" + "=" * 70)
    print(f"THELIX AI — MULTIMODAL EVALUATION REPORT (v{summary['dataset_version']})")
    print("=" * 70)
    print(f"Dataset: {summary['dataset_id']} | Split: {summary['split']} | Samples: {summary['total_samples']}")
    print("-" * 70)
    cm = summary["confusion_matrix"]
    print(f"CONFUSION MATRIX:")
    print(f"  True Positives (TP):  {cm['true_positives']:<5} | False Positives (FP): {cm['false_positives']:<5}")
    print(f"  True Negatives (TN):  {cm['true_negatives']:<5} | False Negatives (FN): {cm['false_negatives']:<5}")
    print(f"  Inconclusive Cases:   {cm['total_inconclusive']:<5} | Extraction Failures:  {cm['extraction_failures']:<5}")
    print("-" * 70)
    m = summary["metrics"]
    op = summary["metrics_operational"]
    print(f"DECISIVE PERFORMANCE METRICS (Denominator: Decisive Predictions Only):")
    print(f"  Accuracy (Decisive) : {m['accuracy'] * 100:.2f}%  (95% CI: [{m['accuracy_ci_95'][0]*100:.1f}%, {m['accuracy_ci_95'][1]*100:.1f}%])")
    print(f"  Precision           : {m['precision'] * 100:.2f}%  (95% CI: [{m['precision_ci_95'][0]*100:.1f}%, {m['precision_ci_95'][1]*100:.1f}%]) [Denom: {m.get('precision_denominator', '-')}]")
    print(f"  Recall (Sensitivity): {m['recall'] * 100:.2f}%  (95% CI: [{m['recall_ci_95'][0]*100:.1f}%, {m['recall_ci_95'][1]*100:.1f}%]) [Denom: {m.get('recall_denominator', '-')}]")
    print(f"  Specificity         : {m['specificity'] * 100:.2f}%  (95% CI: [{m['specificity_ci_95'][0]*100:.1f}%, {m['specificity_ci_95'][1]*100:.1f}%])")
    print(f"  False Positive Rate : {m['false_positive_rate'] * 100:.2f}%")
    print(f"  False Negative Rate : {m['false_negative_rate'] * 100:.2f}%")
    print(f"  F1 Score            : {m['f1_score'] * 100:.2f}%")
    print("-" * 70)
    print(f"OPERATIONAL OUTCOMES (Denominator: All Submitted Samples N):")
    print(f"  Operational Accuracy: {op['operational_accuracy'] * 100:.2f}%  (95% CI: [{op['operational_accuracy_ci_95'][0]*100:.1f}%, {op['operational_accuracy_ci_95'][1]*100:.1f}%])")
    print(f"  Coverage            : {op['coverage'] * 100:.2f}%")
    print(f"  Abstention Rate     : {op['abstention_rate'] * 100:.2f}%")
    print(f"  Extraction Failures : {op['extraction_failure_rate'] * 100:.2f}%")
    print("-" * 70)
    print("PER-MODALITY BREAKDOWN:")
    for mod, stats in summary["per_modality"].items():
        acc = (stats["correct"] / stats["total"] * 100) if stats["total"] > 0 else 0.0
        print(f"  - {mod:<28}: Total={stats['total']:<3} Correct={stats['correct']:<3} (Accuracy={acc:.1f}%)")
    print("=" * 70 + "\n")


async def main():
    parser = argparse.ArgumentParser(description="Multimodal Evaluation Runner")
    parser.add_argument("--split", choices=["all", "tuning", "eval", "holdout"], default="all")
    parser.add_argument("--dataset", default=None, help="Custom dataset path")
    parser.add_argument("--out", default=None, help="Save JSON summary report")
    args = parser.parse_args()

    runner = MultimodalEvaluationRunner(dataset_path=args.dataset)
    summary = await runner.evaluate(split=args.split)
    print_summary_table(summary)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
        print(f"Report written to: {args.out}")


if __name__ == "__main__":
    asyncio.run(main())
