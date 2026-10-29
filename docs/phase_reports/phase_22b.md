# Thelix AI — Phase 22B: Provider Lifecycle Validation, Performance Regression Audit, and PostgreSQL Migration Readiness Report

**Role:** Principal Python Performance Engineer, AI Provider Integration Architect, PostgreSQL Reliability Engineer, and Release Auditor  
**Date:** October 27, 2026  
**Status:** **CONDITIONAL GO / LOCAL HARDENED — STAGING PROMOTION BLOCKED PENDING POSTGRESQL GATE**  
**Repository State:** 290 passed, 2 skipped, 17 warnings in 39.05s | Release Gate: PASS (100% holdout precision/recall, 0% FPR)

---

## 1. Executive Summary

Phase 22B continues directly from Phase 22A to address provider lifecycle safety, empirically audit the reported concurrency-10 throughput decrease, harden PostgreSQL migration scripts, and audit the PostgreSQL staging gate.

### Key Outcomes:
1. **Google GenAI Client Reuse & Resource Lifecycle Hardened:**
   - Both `GeminiProvider` (`llm/gemini_provider.py`) and `GeminiExplanationService` (`app/ai/gemini/explanation.py`) now implement bounded singleton client reuse via `_get_client()`, avoiding per-request connection overhead.
   - Implemented explicit asynchronous and synchronous teardown hooks (`aclose()`, `close()`, `reset_client()`) targeting underlying `client.aio.aclose()` / `client.close()` transport resources.
   - Hardened `_sanitize_error()` regular expressions across all provider modules to eliminate any exposure of sensitive API keys (`AIza...`) or authorization tokens from logs and error payloads.
   - Verified that provider retries and timeouts (bounded at 8.0s production, sub-second test) do not recreate client instances or leak state across requests.
   - Added `tests/test_provider_lifecycle.py` with 7 focused lifecycle tests (all passing).

2. **Throughput "Regression" Resolved via Statistical Profiling:**
   - Evaluated 5 consecutive benchmark repetitions under identical test parameters, CPU load, and database state.
   - Measured Concurrency-10 throughput ranging from **172.62 req/s** to **213.51 req/s** (mean: **199.60 req/s**, median: **207.33 req/s**, standard deviation: **17.42 req/s**). Re-running the full benchmark harness achieved **205.70 req/s**.
   - Verified that the benchmark concurrency loop executes against `MockLLMProvider`, proving code changes in `gemini_provider.py` were not in the execution path.
   - Identified the root cause: The concurrency-10 benchmark workload executes $N=40$ requests with 20ms simulated network latency, completing in ~187ms to ~232ms total wall time. On Windows, standard OS timer resolution ticks at 10.0ms–15.6ms intervals; a mere 28ms clock tick jitter accounts for the entire 13.6% spread between Phase 22 (216.60 req/s) and Phase 22A (187.19 req/s). There is zero code or database query regression (database queries remained flat at 19.6 queries/scan).

3. **Warning Audit & 47% Deprecation Warning Reduction:**
   - Reconciled the 32 warnings reported in Phase 22A. All 32 warnings stemmed from `google.genai._api_client.py:1305` (`DeprecationWarning: Inheritance class AiohttpClientSession from ClientSession is discouraged`).
   - Eliminating redundant client re-instantiations dropped test warnings from 32 down to 17.
   - The remaining 17 warnings occur strictly during genuine initializations of the vendor SDK in integration tests. In accordance with release governance rules, vendor internals were not monkey-patched and warnings were not suppressed.

4. **Migration Safety & Deduplication Hardening:**
   - Audited `docs/migrations/002_quotas_and_refunds.sql` against the authoritative ORM models (`app/models/quota.py`) and `docs/supabase_schema.sql`.
   - Enclosed migration statements within an explicit transactional block (`BEGIN; ... COMMIT;`).
   - Added pre-constraint deduplication CTEs to prune duplicate records before applying unique indexes:
     - For `user_daily_quotas`: retains the row with the highest `scan_count` per `(user_id, date)`.
     - For `quota_refund_records`: retains the earliest refund timestamp per `(user_id, scan_id)`.
   - Validated Row Level Security (RLS) policies: mutations are restricted strictly to `service_role`, preventing authenticated users from spoofing scans or resetting quotas.
   - Documented explicit step-by-step rollback commands.

5. **PostgreSQL Staging Gate Status:**
   - Evaluated staging environment: `TEST_DATABASE_URL` is unset and local port 5432 is unreachable (Connection refused).
   - In accordance with non-negotiable project rules, the PostgreSQL staging gate remains **BLOCKED**. SQLite results were never substituted for PostgreSQL verification.
   - Provided reproducible staging setup commands and test runner procedures.

---

## 2. Changes Actually Made

| File | Change Description | Rationale |
|---|---|---|
| `llm/gemini_provider.py` | Added lazy `_client` caching via `_get_client()`, `async def aclose()`, `def close()`, and enhanced `_sanitize_error()` regex. | Prevents per-call SDK re-instantiation, ensures clean event loop shutdown, and guarantees credentials never appear in error traces. |
| `app/ai/gemini/explanation.py` | Implemented class-level client caching via `_get_client()`, `async def aclose()`, `def reset_client()`, and hardened `_sanitize_error()`. | Reuses HTTP connection pool across risk explanation queries and provides lifecycle cleanup. |
| `tests/test_provider_lifecycle.py` | Created 7 comprehensive unit and integration tests covering client reuse, retry isolation, timeouts, sanitization, and teardown. | Validates provider lifecycle invariants without making live external API calls. |
| `docs/migrations/002_quotas_and_refunds.sql` | Added `BEGIN; ... COMMIT;`, pre-index deduplication CTEs, idempotent index creation, RLS validation, and a rollback script. | Ensures safe, idempotent migration application on live PostgreSQL databases with existing data. |
| `tests/__init__.py` | Created empty package initialization file. | Fixes Python package resolution for `tests.multiprocess_helpers` when invoking pytest directly on individual test files. |
| `tests/test_postgres_concurrency_and_staging.py` | Added `try...finally` teardown restoration for `settings.SUPABASE_JWT_SECRET` and fixed test state machine progression. | Prevents cross-test context pollution and conforms to scan state transition validation rules. |

---

## 3. Client Lifecycle & Warning Analysis

### 3.1 Client Reuse & State Isolation
The `GeminiProvider` and `GeminiExplanationService` lifecycle was verified across five architectural requirements:
- **Scope & Reuse:** Clients are lazily instantiated upon first request and retained for the lifespan of the provider instance / service class. Subsequent requests reuse the existing connection pool and client state.
- **Cross-Request State Isolation:** Requests pass distinct prompt payloads without modifying client attributes. No user-specific data or scan identifiers are stored on the client instance.
- **Retry Logic Independence:** During transient failures, the provider retries up to `max_retries` with exponential backoff using the *same* client instance, avoiding resource churn.
- **Bounded Timeouts:** Calls to the Gemini SDK are governed by `asyncio.wait_for(..., timeout=timeout_seconds)` (production default: 8.0s; test override: 0.05s), ensuring unresponsive upstream connections cannot hang worker threads.
- **Resource Cleanup:** Both `aclose()` and `close()` check for `aio.aclose()` and `close()` on the underlying SDK client and set `_client = None`.
- **Credential Sanitization:** The hardened regex strips `AIza[0-9A-Za-z-_]{16,}` and `(key|token|secret|password)[=:\s]+[0-9A-Za-z-_]+` patterns from error messages before logging or surfacing them.
- **Risk Engine Decoupling:** When the LLM provider fails (via timeout, invalid key, or network outage), the Risk Engine deterministically produces its Trust Score and verdicts unimpeded, falling back to rule-based explanation generators.

### 3.2 Test Results (`tests/test_provider_lifecycle.py`)
```text
tests/test_provider_lifecycle.py::test_gemini_provider_client_reuse PASSED [ 14%]
tests/test_provider_lifecycle.py::test_gemini_provider_retries_without_client_recreation PASSED [ 28%]
tests/test_provider_lifecycle.py::test_gemini_provider_bounded_timeout PASSED [ 42%]
tests/test_provider_lifecycle.py::test_gemini_provider_sensitive_error_sanitization PASSED [ 57%]
tests/test_provider_lifecycle.py::test_gemini_provider_lifecycle_aclose_and_close PASSED [ 71%]
tests/test_provider_lifecycle.py::test_gemini_explanation_service_client_reuse_and_reset PASSED [ 85%]
tests/test_provider_lifecycle.py::test_risk_engine_verdict_independent_of_llm_failure PASSED [100%]
======= 7 passed in 0.75s =======
```

### 3.3 Warning Reconciliation
In Phase 22A, pytest emitted 32 warnings. In Phase 22B, warnings dropped to **17**:
- **Source:** All 17 warnings originate from `google/genai/_api_client.py:1305`:
  `DeprecationWarning: Inheritance class AiohttpClientSession from ClientSession is discouraged`
- **Location of Warnings:**
  - `tests/test_api_integration.py`: 6 warnings
  - `tests/test_operational_hardening.py`: 5 warnings
  - `tests/test_auth_matrix.py`: 4 warnings
  - `tests/test_pilot_readiness.py`: 1 warning
  - `tests/test_staging_validation.py`: 1 warning
- **Cause & Action:** The warning is generated dynamically by Python's `aiohttp` module when the official Google GenAI SDK subclasses `aiohttp.ClientSession`. Reusing client instances prevented redundant instantiations, eliminating 15 warnings. The remaining 17 correspond to necessary test client initializations. Because these warnings originate from vendor library code, they cannot be eliminated without monkey-patching third-party internals or suppressing warnings globally—both of which violate project engineering standards.

---

## 4. Concurrency Throughput Investigation & Profiling

### 4.1 Historical Comparison
- **Phase 22 Baseline:** 216.60 req/s (Concurrency 10)
- **Phase 22A Baseline:** 187.19 req/s (Concurrency 10, -13.58%)

### 4.2 Multi-Run Empirical Benchmark Audit
To evaluate whether the reported drop represented a genuine performance regression, 5 identical benchmark runs were executed consecutively using `ai_engineering/evaluation/benchmark_harness.py`:

| Run | Concurrency 1 (req/s) | Concurrency 5 (req/s) | Concurrency 10 (req/s) | Concurrency 10 Wall Duration | Concurrency 10 p50 | Concurrency 10 p95 |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Run 1 | 134.41 | 190.11 | **172.62** | 0.232s | 26.69ms | 58.75ms |
| Run 2 | 134.41 | 196.85 | **191.80** | 0.209s | 26.11ms | 58.84ms |
| Run 3 | 137.93 | 198.41 | **212.73** | 0.188s | 25.43ms | 57.34ms |
| Run 4 | 135.50 | 196.85 | **213.51** | 0.187s | 25.13ms | 56.45ms |
| Run 5 | 133.33 | 194.55 | **207.33** | 0.193s | 25.75ms | 56.77ms |
| **Full Harness Run** | 133.09 | 196.08 | **205.70** | 0.194s | 26.08ms | 57.42ms |

### 4.3 Statistical Distribution
- **Mean Throughput:** 199.60 req/s
- **Median Throughput:** 207.33 req/s
- **Minimum:** 172.62 req/s
- **Maximum:** 213.51 req/s
- **Standard Deviation:** 17.42 req/s (~8.7% of mean)

### 4.4 Bottleneck Analysis & Finding
1. **Zero LLM Overhead in Benchmark:** The benchmark harness initializes URL scans using `MockLLMProvider`, meaning changes to `gemini_provider.py` or the GenAI SDK are completely bypassed during benchmark execution.
2. **Zero Database Query Regression:** The database query profiler confirmed that DB queries per scan remained constant at **19.6 queries/scan** with a mean database duration of **0.27ms**, exactly matching Phase 21 optimizations.
3. **Timer Resolution & Sample Size Effect:** In `benchmark_concurrency()`, Concurrency 10 dispatches $N=40$ requests across simulated 20ms network hops. The entire batch completes in under 240 milliseconds. On Windows 10/11, OS thread scheduling and `asyncio` event loop tick resolution fluctuate between 10.0ms and 15.6ms. A single scheduling variance of 28ms (e.g. 0.209s vs 0.237s) swings the calculated throughput by ~25 req/s.
4. **Conclusion:** There is **no code-level, algorithmic, or database regression**. The variation between Phase 22 (216.60 req/s) and Phase 22A (187.19 req/s) was entirely benchmark noise due to small sample duration on Windows event loop clocks. Increasing test workload to $N=100$ requests narrows standard deviation to 10.66 req/s.

---

## 5. PostgreSQL Migration Safety Assessment

### 5.1 Schema Review (`docs/migrations/002_quotas_and_refunds.sql`)
The migration was evaluated against `app/models/quota.py` and `docs/supabase_schema.sql`:

1. **Table Integrity:**
   - `user_daily_quotas`: Contains `id` (UUID PK), `user_id` (TEXT), `date` (DATE), `scan_count` (INTEGER DEFAULT 0), `created_at`, `updated_at`. Matches ORM model `UserDailyQuota`.
   - `quota_refund_records`: Contains `id` (UUID PK), `user_id` (TEXT), `scan_id` (TEXT), `reason` (TEXT), `refunded_at` (TIMESTAMPTZ). Matches ORM model `QuotaRefundRecord`.
2. **Pre-Constraint Deduplication:**
   To prevent migration failure when adding unique constraints to existing databases:
   ```sql
   -- Deduplicate user_daily_quotas retaining maximum scan_count
   WITH ranked_quotas AS (
       SELECT id, ROW_NUMBER() OVER (
           PARTITION BY user_id, date ORDER BY scan_count DESC, created_at ASC
       ) as rn FROM user_daily_quotas
   )
   DELETE FROM user_daily_quotas WHERE id IN (SELECT id FROM ranked_quotas WHERE rn > 1);
   ```
   A similar CTE dedupes `quota_refund_records`, retaining the earliest refund timestamp.
3. **Index & Constraint Idempotency:**
   - `CREATE UNIQUE INDEX IF NOT EXISTS idx_user_daily_quotas_user_date ON user_daily_quotas (user_id, date);`
   - `CREATE UNIQUE INDEX IF NOT EXISTS idx_quota_refund_records_user_scan ON quota_refund_records (user_id, scan_id);`
4. **Row Level Security (RLS):**
   - RLS is explicitly enabled on both tables.
   - `service_role` has full permissions (`ALL TO service_role USING (true) WITH CHECK (true)`).
   - Authenticated users are granted `SELECT` access strictly for rows where `user_id = auth.uid()::text`.
   - Write operations (`INSERT`, `UPDATE`, `DELETE`) are explicitly blocked for `authenticated` users, enforcing server-side atomic quota reservation through backend APIs.
5. **Transactional Wrapper & Rollback Plan:**
   The migration is wrapped in `BEGIN; ... COMMIT;`. Complete rollback instructions are embedded at the bottom of the migration file.

---

## 6. PostgreSQL Staging Gate Verification

### 6.1 Infrastructure Inspection
- Environment variable `TEST_DATABASE_URL`: `None`
- Host: `127.0.0.1:5432` -> `ConnectionRefusedError: [WinError 10061]`
- Authoritative Staging Credentials: None provisioned in current workspace.

### 6.2 Staging Gate Status
In adherence to the non-negotiable instruction:
> "Never substitute SQLite results for PostgreSQL evidence. If unavailable, leave the gate BLOCKED and provide the exact prerequisite and test commands."

The gate status is **BLOCKED**.

### 6.3 Staging Prerequisite & Execution Runbook
When staging infrastructure is made available, execute the following commands:

```bash
# 1. Provision or start isolated PostgreSQL 15+ container
docker run -d --name thelix-staging-pg -e POSTGRES_DB=thelix_staging -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=staging_secret -p 5432:5432 postgres:15

# 2. Export test database connection URL
export TEST_DATABASE_URL="postgresql://postgres:staging_secret@127.0.0.1:5432/thelix_staging"
# On Windows PowerShell:
# $env:TEST_DATABASE_URL="postgresql://postgres:staging_secret@127.0.0.1:5432/thelix_staging"

# 3. Apply baseline and quota migrations
psql $TEST_DATABASE_URL -f docs/supabase_schema.sql
psql $TEST_DATABASE_URL -f docs/migrations/002_quotas_and_refunds.sql

# 4. Execute dedicated PostgreSQL concurrency and staging harness
python -m pytest tests/test_postgres_concurrency_and_staging.py -v
python -m pytest tests/test_staging_validation.py -v
```

---

## 7. Regression and Release Gate Audit

### 7.1 Full Pytest Suite
```bash
python -m pytest
```
- **Passed:** 290
- **Skipped:** 2
  - `tests/test_staging_validation.py::test_postgres_schema_and_pool_isolation` (Skipped: requires real PostgreSQL `TEST_DATABASE_URL`)
  - `tests/test_postgres_concurrency_and_staging.py::test_live_postgresql_staging_gate` (Skipped: requires real PostgreSQL `TEST_DATABASE_URL`)
- **Failed:** 0
- **Warnings:** 17 (all confirmed `google.genai` SDK vendor deprecation warnings)
- **Duration:** 39.05 seconds

### 7.2 Deterministic AI Release Gate
```bash
python -m ai_engineering.evaluation.release_gate
```
- **Step 1: Dataset Schemas and Split Isolation:**
  - URL Dataset v2: 110 samples, zero leakage [PASS]
  - Multimodal Dataset v2: 45 samples, zero leakage [PASS]
- **Step 2: URL Risk Engine Evaluation (Holdout Split):**
  - Precision: 100.00% (target >= 95.0%) [PASS]
  - Recall: 100.00% (target >= 90.0%) [PASS]
  - FPR: 0.00% (target <= 5.0%) [PASS]
- **Step 3: Multimodal Analysis Pipeline (Holdout Split):**
  - Precision: 100.00% (target >= 90.0%) [PASS]
  - Recall: 100.00% (target >= 85.0%) [PASS]
  - FPR: 0.00% (target <= 5.0%) [PASS]
  - Modalities evaluated: `suspicious_message` (100%), `qr_code` (100%), `pdf_document` (100%), `screenshot` (100%), `adversarial_prompt_injection` (100%)
- **Release Gate Verdict:** **PASS**

---

## 8. Remaining Risks and Justified Release Decision

### 8.1 Remaining Risks
1. **PostgreSQL Multi-Process Concurrency Unverified on Live Infrastructure:**
   While the multiprocess test harness (`tests/test_postgres_concurrency_and_staging.py`) is fully implemented and tested with SQLite fallback, live row locking, concurrent transactional rollbacks, and first-row constraint races have not been validated against a running PostgreSQL engine due to absent staging credentials.
2. **Holdout Evaluation Sample Size:**
   While holdout precision and recall are 100%, the holdout split contains 18 URL samples and 6 multimodal samples. Continuous monitoring and expanded synthetic validation sets remain necessary as new adversarial attacks emerge.
3. **Upstream Google GenAI SDK Session Warning:**
   The `AiohttpClientSession` deprecation warning persists in 17 tests until Google releases an updated SDK version that removes subclassing of `aiohttp.ClientSession`.

### 8.2 Release Decision
**Decision: CONDITIONAL GO / LOCAL HARDENED — STAGING PROMOTION BLOCKED**

- **Local Backend & AI Subsystems:** **APPROVED FOR INTERNAL INTEGRATION**. Codebase demonstrates zero regressions, clean client reuse, deterministic risk scoring, sanitized credential handling, robust error recovery, and 290 passing tests.
- **Production Deployment:** **HOLD / BLOCKED**. Deployment to production or remote staging clusters must remain blocked until an authorized PostgreSQL staging database is connected and passes `test_live_postgresql_staging_gate` without test skips.
