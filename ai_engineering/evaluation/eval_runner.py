"""
Thelix AI — Risk Engine Evaluation & Calibration Runner
Reproducible benchmark evaluator measuring detection quality, false-positive/false-negative rates,
confusion matrices, category breakdowns, score distributions, and Wilson score confidence intervals.
"""
import os
import sys
import json
import math
import asyncio
import argparse
import statistics
from typing import Dict, List, Any, Optional, Tuple

# Add repository root to path
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from risk_engine.engine import RiskEngine
from risk_engine.reputation_analyzer import ReputationProvider, ReputationResult, ReputationStatus
from risk_engine.evidence import ActionVerdict, RiskLevel


from ai_engineering.evaluation.metrics import EvaluationMetrics, wilson_score_interval

class FixtureReputationProvider(ReputationProvider):
    """
    In-memory offline threat intelligence provider simulating Google Safe Browsing
    and VirusTotal results directly from dataset sample fixtures.
    """
    def __init__(self, provider_name: str, version: str = "1.0.0"):
        super().__init__(cache=None)
        self.name = provider_name
        self.version = version
        self.current_status: ReputationStatus = ReputationStatus.NO_MATCH
        self.current_threats: List[str] = []

    def configure(self, status: ReputationStatus, threats: Optional[List[str]] = None):
        self.current_status = status
        self.current_threats = threats or []

    async def _execute_lookup(self, sanitized_url: str) -> ReputationResult:
        is_mal = (self.current_status == ReputationStatus.CONFIRMED_MALICIOUS)
        return ReputationResult(
            provider_name=self.name,
            provider_version=self.version,
            status=self.current_status,
            threat_types=self.current_threats if is_mal else [],
            positives_count=10 if is_mal else 0,
            total_engines=70,
            raw_response={"fixture": True},
        )


def calculate_percentiles(values: List[float], percentiles: List[int]) -> Dict[str, float]:
    """Calculates requested percentiles for a distribution."""
    if not values:
        return {f"p{p}": 0.0 for p in percentiles}
    sorted_vals = sorted(values)
    n = len(sorted_vals)
    res = {}
    for p in percentiles:
        k = (n - 1) * (p / 100.0)
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            res[f"p{p}"] = round(sorted_vals[int(k)], 2)
        else:
            val = sorted_vals[int(f)] * (c - k) + sorted_vals[int(c)] * (k - f)
            res[f"p{p}"] = round(val, 2)
    return res


class EvaluationRunner:
    """
    Executes reproducible offline risk evaluation across dataset splits.
    """
    def __init__(self, dataset_path: Optional[str] = None):
        v2_path = os.path.join(REPO_ROOT, "ai_engineering", "datasets", "url_evaluation_dataset_v2.json")
        v1_path = os.path.join(REPO_ROOT, "ai_engineering", "datasets", "url_evaluation_dataset_v1.json")
        default_path = v2_path if os.path.exists(v2_path) else v1_path
        self.dataset_path = dataset_path or default_path
        self.dataset: Dict[str, Any] = self._load_dataset()

        # Offline fixture providers
        self.gsb_provider = FixtureReputationProvider("google_safe_browsing")
        self.vt_provider = FixtureReputationProvider("virustotal")
        self.engine = RiskEngine(
            reputation_providers=[self.gsb_provider, self.vt_provider],
            enable_reputation=True,
        )

    def _load_dataset(self) -> Dict[str, Any]:
        if not os.path.exists(self.dataset_path):
            raise FileNotFoundError(f"Evaluation dataset not found at {self.dataset_path}")
        with open(self.dataset_path, "r", encoding="utf-8") as f:
            return json.load(f)

    async def run_evaluation(self, split: str = "eval") -> Dict[str, Any]:
        """
        Runs evaluation on a specified split ('eval', 'tuning', 'holdout', or 'all').
        Returns structured metrics dictionary.
        """
        all_samples = self.dataset.get("samples", [])
        if split != "all":
            samples = [s for s in all_samples if s.get("dataset_split") == split]
        else:
            samples = all_samples

        if not samples:
            raise ValueError(f"No samples found for split '{split}'")

        # Counts
        tp = 0
        fp = 0
        tn = 0
        fn = 0
        inconclusive_benign = 0
        inconclusive_malicious = 0

        # Score distributions
        benign_risk_scores: List[float] = []
        malicious_risk_scores: List[float] = []
        benign_confidences: List[float] = []
        malicious_confidences: List[float] = []
        coverage_ratios: List[float] = []

        category_stats: Dict[str, Dict[str, Any]] = {}
        detailed_results: List[Dict[str, Any]] = []

        for sample in samples:
            sid = sample["sample_id"]
            url = sample["url"]
            gt = sample["ground_truth_label"].upper()
            cat = sample.get("category", "unknown")
            fixtures = sample.get("reputation_fixtures", {})

            # Configure fixture providers
            gsb_stat = ReputationStatus[fixtures.get("google_safe_browsing", "NO_MATCH")]
            vt_stat = ReputationStatus[fixtures.get("virustotal", "NO_MATCH")]

            self.gsb_provider.configure(gsb_stat, ["MALWARE"] if gsb_stat == ReputationStatus.CONFIRMED_MALICIOUS else [])
            self.vt_provider.configure(vt_stat, ["PHISHING"] if vt_stat == ReputationStatus.CONFIRMED_MALICIOUS else [])

            # Run deterministic Risk Engine
            report = await self.engine.analyze_url(url, scan_id=f"eval-{sid}")

            verdict = report.recommended_action
            risk_score = report.risk_score
            trust_score = report.trust_score
            confidence = report.confidence
            coverage = report.coverage_ratio
            findings_codes = [f.finding_code for f in report.findings]

            coverage_ratios.append(coverage)

            # Map prediction: BLOCK / WARN = Threat Detected (Positive)
            # ALLOW = Safe (Negative)
            # INCONCLUSIVE = Abstention
            is_predicted_threat = verdict in (ActionVerdict.BLOCK, ActionVerdict.WARN)
            is_predicted_safe = (verdict == ActionVerdict.ALLOW)
            is_inconclusive = (verdict == ActionVerdict.INCONCLUSIVE)

            if gt == "BENIGN":
                benign_risk_scores.append(float(risk_score))
                benign_confidences.append(float(confidence))
                if is_inconclusive:
                    inconclusive_benign += 1
                    outcome = "INCONCLUSIVE_BENIGN"
                elif is_predicted_safe:
                    tn += 1
                    outcome = "TRUE_NEGATIVE"
                else:
                    fp += 1
                    outcome = "FALSE_POSITIVE"
            else:  # MALICIOUS
                malicious_risk_scores.append(float(risk_score))
                malicious_confidences.append(float(confidence))
                if is_inconclusive:
                    inconclusive_malicious += 1
                    outcome = "INCONCLUSIVE_MALICIOUS"
                elif is_predicted_threat:
                    tp += 1
                    outcome = "TRUE_POSITIVE"
                else:
                    fn += 1
                    outcome = "FALSE_NEGATIVE"

            # Category tracking
            if cat not in category_stats:
                category_stats[cat] = {
                    "total": 0, "tp": 0, "fp": 0, "tn": 0, "fn": 0,
                    "inconclusive": 0, "risk_scores": []
                }
            cstat = category_stats[cat]
            cstat["total"] += 1
            cstat["risk_scores"].append(float(risk_score))
            if outcome == "TRUE_POSITIVE":
                cstat["tp"] += 1
            elif outcome == "FALSE_POSITIVE":
                cstat["fp"] += 1
            elif outcome == "TRUE_NEGATIVE":
                cstat["tn"] += 1
            elif outcome == "FALSE_NEGATIVE":
                cstat["fn"] += 1
            elif "INCONCLUSIVE" in outcome:
                cstat["inconclusive"] += 1

            detailed_results.append({
                "sample_id": sid,
                "url": url,
                "ground_truth": gt,
                "verdict": verdict.value,
                "outcome": outcome,
                "risk_score": risk_score,
                "trust_score": trust_score,
                "confidence": confidence,
                "findings": findings_codes,
            })

        # Compute comprehensive metrics via EvaluationMetrics
        metrics_calc = EvaluationMetrics(
            tp=tp, fp=fp, tn=tn, fn=fn,
            inconclusive_benign=inconclusive_benign,
            inconclusive_malicious=inconclusive_malicious,
        )
        metrics_dict = metrics_calc.to_dict()

        # Score distributions
        def summarize_dist(vals: List[float]) -> Dict[str, Any]:
            if not vals:
                return {}
            pcts = calculate_percentiles(vals, [25, 50, 75, 95])
            return {
                "count": len(vals),
                "mean": round(statistics.mean(vals), 2),
                "median": round(statistics.median(vals), 2),
                "std": round(statistics.stdev(vals), 2) if len(vals) > 1 else 0.0,
                "min": round(min(vals), 2),
                "max": round(max(vals), 2),
                **pcts,
            }

        # Category summaries
        cat_summaries = {}
        for cname, cdata in category_stats.items():
            scores = cdata.pop("risk_scores")
            cdata["mean_risk_score"] = round(statistics.mean(scores), 2) if scores else 0.0
            cat_summaries[cname] = cdata

        return {
            "evaluation_metadata": {
                "dataset_version": self.dataset.get("dataset_metadata", {}).get("version", "2.0.0"),
                "dataset_split": split,
                "total_samples": metrics_calc.total_samples,
                "benign_samples": metrics_calc.total_benign,
                "malicious_samples": metrics_calc.total_malicious,
            },
            "confusion_matrix": {
                "true_positives": tp,
                "false_positives": fp,
                "true_negatives": tn,
                "false_negatives": fn,
                "inconclusive_benign": inconclusive_benign,
                "inconclusive_malicious": inconclusive_malicious,
                "total_inconclusive": metrics_calc.total_inconclusive,
            },
            "metrics_decisive": metrics_dict["metrics_decisive"],
            "metrics_operational": metrics_dict["metrics_operational"],
            "abstention_and_coverage": {
                "total_inconclusive": metrics_calc.total_inconclusive,
                "abstention_rate": metrics_calc.abstention_rate(),
                "inconclusive_rate_benign": metrics_calc.inconclusive_rate_benign(),
                "inconclusive_rate_malicious": metrics_calc.inconclusive_rate_malicious(),
                "coverage": metrics_calc.coverage(),
                "mean_engine_coverage": round(statistics.mean(coverage_ratios), 4) if coverage_ratios else 0.0,
            },
            "score_distributions": {
                "benign_risk_scores": summarize_dist(benign_risk_scores),
                "malicious_risk_scores": summarize_dist(malicious_risk_scores),
                "benign_confidence": summarize_dist(benign_confidences),
                "malicious_confidence": summarize_dist(malicious_confidences),
            },
            "performance_by_category": cat_summaries,
            "detailed_results": detailed_results,
        }

    def print_report(self, eval_data: Dict[str, Any]):
        """Prints formatted console report distinguishing decisive and operational performance."""
        meta = eval_data["evaluation_metadata"]
        cm = eval_data["confusion_matrix"]
        m = eval_data["metrics_decisive"]
        op = eval_data["metrics_operational"]
        ac = eval_data["abstention_and_coverage"]
        sd = eval_data["score_distributions"]

        print("\n" + "=" * 80)
        print(f"THELIX AI RISK ENGINE — EVALUATION REPORT (Split: {meta['dataset_split'].upper()})")
        print("=" * 80)
        print(f"Dataset Version: {meta['dataset_version']} | Total Samples: {meta['total_samples']} (Benign: {meta['benign_samples']}, Malicious: {meta['malicious_samples']})")
        print("-" * 80)
        print("CONFUSION MATRIX:")
        print(f"  True Positives  (TP) : {cm['true_positives']:<5} | False Positives (FP) : {cm['false_positives']:<5}")
        print(f"  True Negatives  (TN) : {cm['true_negatives']:<5} | False Negatives (FN) : {cm['false_negatives']:<5}")
        print(f"  Inconclusive Benign  : {cm['inconclusive_benign']:<5} | Inconclusive Malic.  : {cm['inconclusive_malicious']:<5}")
        print(f"  Total Inconclusive   : {cm['total_inconclusive']:<5} (Abstention Rate: {ac['abstention_rate'] * 100:.1f}%)")
        print("-" * 80)
        print("DECISIVE PERFORMANCE METRICS (Denominator: Decisive Predictions Only):")
        print(f"  Precision           : {m['precision'] * 100:.2f}%  (CI: [{m['precision_ci_95'][0]*100:.1f}%, {m['precision_ci_95'][1]*100:.1f}%]) [Denom: {m.get('precision_denominator', '-')}]")
        print(f"  Recall (Detection)  : {m['recall'] * 100:.2f}%  (CI: [{m['recall_ci_95'][0]*100:.1f}%, {m['recall_ci_95'][1]*100:.1f}%]) [Denom: {m.get('recall_denominator', '-')}]")
        print(f"  Specificity         : {m.get('specificity', 1.0) * 100:.2f}%  (CI: [{m.get('specificity_ci_95', (0,0))[0]*100:.1f}%, {m.get('specificity_ci_95', (0,0))[1]*100:.1f}%])")
        print(f"  False Positive Rate : {m['false_positive_rate'] * 100:.2f}%  (CI: [{m['false_positive_rate_ci_95'][0]*100:.1f}%, {m['false_positive_rate_ci_95'][1]*100:.1f}%])")
        print(f"  False Negative Rate : {m['false_negative_rate'] * 100:.2f}%  (CI: [{m['false_negative_rate_ci_95'][0]*100:.1f}%, {m['false_negative_rate_ci_95'][1]*100:.1f}%])")
        print(f"  Accuracy (Decisive) : {m['accuracy'] * 100:.2f}%")
        print(f"  F1 Score            : {m['f1_score'] * 100:.2f}%")
        print("-" * 80)
        print("OPERATIONAL OUTCOMES (Denominator: All Submitted Samples N, Abstentions Count as Non-Decisive):")
        print(f"  Operational Accuracy: {op['operational_accuracy'] * 100:.2f}%  (CI: [{op['operational_accuracy_ci_95'][0]*100:.1f}%, {op['operational_accuracy_ci_95'][1]*100:.1f}%])")
        print(f"  Coverage            : {op['coverage'] * 100:.2f}%")
        print(f"  Abstention Rate     : {op['abstention_rate'] * 100:.2f}%")
        print(f"  Mean Engine Coverage: {ac['mean_engine_coverage'] * 100:.2f}%")
        print("-" * 80)
        print("RISK SCORE DISTRIBUTIONS:")
        b_sd = sd["benign_risk_scores"]
        m_sd = sd["malicious_risk_scores"]
        print(f"  Benign    - Mean: {b_sd.get('mean', 0.0):<5} | Median: {b_sd.get('median', 0.0):<5} | Std: {b_sd.get('std', 0.0):<5} | Range: [{b_sd.get('min', 0.0)}, {b_sd.get('max', 0.0)}]")
        print(f"  Malicious - Mean: {m_sd.get('mean', 0.0):<5} | Median: {m_sd.get('median', 0.0):<5} | Std: {m_sd.get('std', 0.0):<5} | Range: [{m_sd.get('min', 0.0)}, {m_sd.get('max', 0.0)}]")
        print("-" * 80)
        print("PERFORMANCE BY CATEGORY:")
        print(f"  {'Category':<32} {'Total':<6} {'TP':<4} {'FP':<4} {'TN':<4} {'FN':<4} {'Inc':<4} {'Mean Score'}")
        for cat, cdata in eval_data["performance_by_category"].items():
            print(f"  {cat:<32} {cdata['total']:<6} {cdata['tp']:<4} {cdata['fp']:<4} {cdata['tn']:<4} {cdata['fn']:<4} {cdata['inconclusive']:<4} {cdata['mean_risk_score']:<5}")
        print("=" * 80 + "\n")


async def main():
    parser = argparse.ArgumentParser(description="Thelix AI Risk Engine Evaluation Runner")
    parser.add_argument("--split", choices=["eval", "tuning", "holdout", "all"], default="eval", help="Dataset split to evaluate")
    parser.add_argument("--dataset", type=str, default=None, help="Custom dataset path")
    parser.add_argument("--output", type=str, default=None, help="Output JSON results path")
    args = parser.parse_args()

    runner = EvaluationRunner(dataset_path=args.dataset)
    results = await runner.run_evaluation(split=args.split)
    runner.print_report(results)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        print(f"Wrote full evaluation results to {args.output}")


if __name__ == "__main__":
    asyncio.run(main())
