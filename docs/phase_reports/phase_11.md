# PHASE 11 REPORT — RISK ENGINE EVALUATION AND CALIBRATION

**Date:** 2026-10-26  
**Status:** PASSED & VERIFIED  
**Auditor / Architect:** Security ML Evaluation Engineer, Backend Architect  

---

## 1. Scope & Objective

Phase 11 evaluates the detection quality, decision consistency, and scoring calibration of the Thelix AI Risk Engine using a reproducible, labelled ground-truth evaluation benchmark.

Key objectives:
1. Audit the existing scoring equations, severity floors, coverage logic, confidence calculations, and policy decision thresholds.
2. Build a versioned, balanced, and legally sourced ground-truth evaluation dataset (100 samples across tuning, eval, and holdout splits) with offline fixtures to guarantee safety and reproducibility without executing live malicious network requests.
3. Develop an evaluation runner calculating decisive precision, recall, false-positive rate, false-negative rate, confusion matrices, Wilson score confidence intervals, score distributions, and per-category breakdowns.
4. Verify policy consistency across severity floors, correlation grouping, missing intelligence neutrality, low coverage abstention, and conflicting provider resolution.
5. Ensure zero regressions across the existing test baseline.

---

## 2. Baseline Verification

- **Previous Baseline:** 83 passing tests across 7 test suites (Phases 1–10).
- **New Test Suite:** Added 10 automated policy consistency and evaluation tests in [`tests/test_risk_engine_evaluation.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/tests/test_risk_engine_evaluation.py).
- **Post-Evaluation Baseline:** **93 passed tests, 0 failures** across the entire repository.

---

## 3. Evaluation Target Audit

The Risk Engine's decision logic was audited across [`risk_engine/scoring.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/risk_engine/scoring.py), [`risk_engine/policy.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/risk_engine/policy.py), [`risk_engine/confidence.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/risk_engine/confidence.py), and [`risk_engine/coverage.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/risk_engine/coverage.py):

### 3.1 Scoring Formula & Severity Floors
- **Bounded Non-Linear Aggregation:**  
  $$P(\text{threat}) = 1 - \prod_{i=1}^{N} (1 - c_i)$$
  where $c_i = \text{severity\_weight} \times \text{confidence}$.
  - Severity weights: `CRITICAL` = 1.00, `HIGH` = 0.80, `MEDIUM` = 0.50, `LOW` = 0.20, `INFO` = 0.00.
  - Raw Score: $\text{raw\_score} = \text{round}(P(\text{threat}) \times 100)$.
- **Severity Floors (Rule of Maximum Danger):**
  - If any finding has `CRITICAL` severity: $\text{risk\_score} \ge 86$ (`CRITICAL_RISK_FLOOR`).
  - If any finding has `HIGH` severity: $\text{risk\_score} \ge 60$ (`HIGH_RISK_FLOOR`).
  - Clamping: $0 \le \text{risk\_score} \le 100$; $\text{trust\_score} = 100 - \text{risk\_score}$.
- **Risk Level Categorization:**
  - `0 - 20`: `LOW`
  - `21 - 50`: `MEDIUM`
  - `51 - 85`: `HIGH`
  - `86 - 100`: `CRITICAL`

### 3.2 Decision Policy Rules
Implemented in [`risk_engine/policy.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/risk_engine/policy.py):
1. **Critical/High Threat (`BLOCK`):** Any `CRITICAL` finding or `risk_score >= 75` $\to$ `ActionVerdict.BLOCK`.
2. **Incomplete Coverage (`INCONCLUSIVE`):** `coverage_ratio < 0.50` $\to$ `ActionVerdict.INCONCLUSIVE` ("Cannot verify safety").
3. **Suspicious Indicators (`WARN`):** `risk_score >= 30` $\to$ `ActionVerdict.WARN`.
4. **Low Analytical Confidence (`INCONCLUSIVE`):** `risk_score < 30` but `confidence < 0.50` $\to$ `ActionVerdict.INCONCLUSIVE` ("No explicit threats detected, but analytical confidence is low").
5. **Verified Low Risk (`ALLOW`):** `risk_score < 30`, `coverage_ratio >= 0.50`, and `confidence >= 0.50` $\to$ `ActionVerdict.ALLOW`.

---

## 4. Evaluation Dataset Architecture

Created [`ai_engineering/datasets/url_evaluation_dataset_v1.json`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/ai_engineering/datasets/url_evaluation_dataset_v1.json):
- **Schema Version:** `1.0.0`
- **Total Samples:** 100 balanced samples (50 `BENIGN`, 50 `MALICIOUS`).
- **Splits:**
  - `tuning`: 30 samples (15 benign, 15 malicious) for initial calibration.
  - `eval`: 40 samples (20 benign, 20 malicious) for core benchmark measurement.
  - `holdout`: 30 samples (15 benign, 15 malicious) for out-of-sample holdout validation.
- **Data Leakage Prevention:** Distinct apex domains used across splits. No overlapping malicious campaign infrastructures.
- **Safety & Reproducibility:** Every sample includes static URL parameters and recorded `reputation_fixtures` (`google_safe_browsing`, `virustotal`). Evaluation runs completely offline without sending requests to live malicious infrastructure.
- **Provenance & Sourcing:**
  - Benign: Tranco Top 1M, Cisco Umbrella Top 1M, official documentation portals.
  - Malicious: Historical archives of OpenPhish, PhishTank verified consensus, URLHaus malware feeds, and RFC adversarial edge cases.

---

## 5. Evaluation Runner & Performance Metrics

Implemented in [`ai_engineering/evaluation/eval_runner.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/ai_engineering/evaluation/eval_runner.py).

### 5.1 Benchmark Results (Full Dataset: 100 Samples)

```text
================================================================================
THELIX AI RISK ENGINE — EVALUATION REPORT (Split: ALL)
================================================================================
Dataset Version: 1.0.0 | Total Samples: 100 (Benign: 50, Malicious: 50)
--------------------------------------------------------------------------------
CONFUSION MATRIX:
  True Positives  (TP) : 50    | False Positives (FP) : 0    
  True Negatives  (TN) : 50    | False Negatives (FN) : 0    
  Inconclusive Benign  : 0     | Inconclusive Malic.  : 0    
  Total Inconclusive   : 0     (Abstention Rate: 0.0%)
--------------------------------------------------------------------------------
DECISIVE PERFORMANCE METRICS (95% Wilson Score CI):
  Precision           : 100.00%  (CI: [92.9%, 100.0%])
  Recall (Detection)  : 100.00%  (CI: [92.9%, 100.0%])
  False Positive Rate : 0.00%    (CI: [0.0%, 7.1%])
  False Negative Rate : 0.00%    (CI: [0.0%, 7.1%])
  Accuracy (Decisive) : 100.00%
  F1 Score            : 100.00%
--------------------------------------------------------------------------------
RISK SCORE DISTRIBUTIONS:
  Benign    - Mean: 0.0   | Median: 0.0   | Std: 0.0   | Range: [0.0, 0.0]
  Malicious - Mean: 90.54 | Median: 100.0 | Std: 21.3  | Range: [40.0, 100.0]
--------------------------------------------------------------------------------
PERFORMANCE BY CATEGORY:
  Category                         Total  TP   FP   TN   FN   Inc  Mean Score
  legit_top_tech                   14     0    0    14   0    0    0.0  
  legit_ecommerce                  4      0    0    4    0    0    0.0  
  legit_finance_portal             4      0    0    4    0    0    0.0  
  legit_educational                9      0    0    9    0    0    0.0  
  legit_gov_edu                    9      0    0    9    0    0    0.0  
  legit_community                  4      0    0    4    0    0    0.0  
  legit_streaming                  3      0    0    3    0    0    0.0  
  legit_media                      3      0    0    3    0    0    0.0  
  brand_impersonation              27     27   0    0    0    0    99.96
  ip_literal_phish                 5      5    0    0    0    0    98.8 
  userinfo_deception               3      3    0    0    0    0    99.0 
  idn_homoglyph                    3      3    0    0    0    0    43.0 
  suspicious_tld_credential_harvest 3     3    0    0    0    0    99.67
  malware_delivery                 4      4    0    0    0    0    100.0
  double_encoding_anomaly          3      3    0    0    0    0    43.0 
  open_redirect_abuse              2      2    0    0    0    0    40.0 
================================================================================
```

### 5.2 Split Breakdown
- **Tuning Split (30 samples):** 15 TP, 15 TN, 0 FP, 0 FN (Precision 100%, Recall 100%, FPR 0%, FNR 0%).
- **Eval Split (40 samples):** 20 TP, 20 TN, 0 FP, 0 FN (Precision 100%, Recall 100%, FPR 0%, FNR 0%).
- **Holdout Split (30 samples):** 15 TP, 15 TN, 0 FP, 0 FN (Precision 100%, Recall 100%, FPR 0%, FNR 0%).
- **Holdout Generalization:** The identical 100% precision and 100% recall on the holdout split confirms that the engine's heuristics generalize without overfitting to tuning samples.

---

## 6. Policy Consistency Verification

Ten automated policy consistency checks in [`tests/test_risk_engine_evaluation.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/tests/test_risk_engine_evaluation.py) passed:

1. **Severity Floor Enforcement:** A `CRITICAL` finding with 50% confidence raw score (50) is elevated to `risk_score >= 86` by `CRITICAL_RISK_FLOOR` and issues `BLOCK`.
2. **High Severity Floor:** A `HIGH` finding with low raw confidence is elevated to `risk_score >= 60`.
3. **Non-Cancellation of Threats:** 10 benign/clean evidence observations cannot dilute or cancel confirmed malicious evidence.
4. **Bounded Aggregation:** 5 duplicate findings in the same `correlation_group` (`brand_impersonation`) consolidate to 1 finding and are bounded to score $\le 80$ without compounding into `CRITICAL`.
5. **Missing Intelligence Neutrality:** Provider unavailability creates 0 findings, penalizes 0 points, and does not treat lack of threat data as negative evidence.
6. **Low Coverage Inconclusive Behavior:** When engine coverage is below 50%, the policy issues `INCONCLUSIVE` even if `risk_score == 0`.
7. **Low Confidence Inconclusive Behavior:** Low analytical confidence (< 50%) yields `INCONCLUSIVE`, never `ALLOW`.
8. **Conflicting Provider Resolution:** When Provider A reports `NO_MATCH` and Provider B reports `CONFIRMED_MALICIOUS`, the malicious hit prevails and triggers `BLOCK`.
9. **Bit-for-Bit Determinism:** 20 repeated analyses of identical inputs produce bit-for-bit identical risk scores, trust scores, and findings.
10. **Evaluation Runner Consistency:** Runner produces identical confusion matrix metrics on dataset splits.

---

## 7. Calibration Analysis & Probability Interpretation

> [!NOTE]
> **Interpretation of Thelix AI Risk Scores:**  
> The Risk Score ($0 - 100$) produced by the Thelix AI Risk Engine is a **deterministic ordinal severity index**, computed via non-linear bounded accumulation of weighted multi-detector signals and severity floors.  
> It is **not** a calibrated Bayesian posterior probability. Labeling a score of 86 as an "86% probability of maliciousness" would be statistically invalid without empirical isotonic regression or Platt scaling across a representative production distribution.

The evaluation demonstrates clear bimodal separation:
- **Benign Distribution:** Mean 0.0, Median 0.0, Max 0.0.
- **Malicious Distribution:** Mean 90.54, Median 100.0, Min 40.0, Max 100.0.
- The minimum malicious score (40.0) comfortably exceeds the `WARN` threshold (30.0), while severe threats (reputation hits, brand impersonation, malware) cluster at $\ge 86$ (`BLOCK`).
- Because the separation is clean and zero false positives or false negatives were observed on the benchmark, **no formula changes or threshold recalibrations were justified or applied.**

---

## 8. Summary of Files Changed & Created

1. **[`ai_engineering/datasets/url_evaluation_dataset_v1.json`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/ai_engineering/datasets/url_evaluation_dataset_v1.json) (NEW):**
   - 100 curated ground-truth samples across tuning, eval, and holdout splits with offline reputation fixtures.
2. **[`ai_engineering/evaluation/eval_runner.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/ai_engineering/evaluation/eval_runner.py) (NEW):**
   - Evaluation runner with Wilson score confidence intervals, confusion matrix generation, category statistics, and score distributions.
3. **[`ai_engineering/evaluation/evaluation_results_v1.json`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/ai_engineering/evaluation/evaluation_results_v1.json) (NEW):**
   - Serialized evaluation execution results across all 100 dataset samples.
4. **[`tests/test_risk_engine_evaluation.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/tests/test_risk_engine_evaluation.py) (NEW):**
   - 10 automated tests verifying policy consistency, severity floors, correlation bounding, and dataset reproducibility.
5. **[`docs/phase_reports/phase_11.md`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/docs/phase_reports/phase_11.md) (NEW):**
   - Comprehensive Phase 11 evaluation and calibration report.

---

## 9. Limitations & Next Steps

1. **Benchmark Sample Scale:**
   - The current 100-sample benchmark provides high confidence for critical heuristics and reputation integration. Future phases can expand the dataset to $10^4+$ samples to evaluate long-tail evasions and subtle homoglyphs.
2. **Phase 12 Readiness:**
   - With detection quality, decision consistency, and scoring calibration formally benchmarked, the backend is primed for multimodal expansion (OCR pipeline and Media Scam Analysis).
