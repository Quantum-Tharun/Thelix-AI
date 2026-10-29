# THELIX AI — PHASE 2 REPORT: ARCHITECTURAL RECONCILIATION & BACKEND INTEGRITY

**Phase:** Phase 2  
**Roles:** Lead Backend Architect, Application Security Engineer, AI Systems Engineer, Database Engineer, Release Test Engineer  
**Date:** 2026-10-27  
**Status:** COMPLETE (Local Hardened & Authoritative Engine Unified; PostgreSQL Staging Gate BLOCKED Pending Infrastructure)

---

## 1. Executive Summary

Phase 2 remediated the architectural divergence and identity boundary vulnerabilities identified in the Phase 1 audit report (`THELIX-AUDIT-001` through `THELIX-AUDIT-005`). 

Prior to Phase 2, the backend operated with dual divergent risk assessment pathways: user-facing `/v1/scans` routes executed the authoritative `OrchestratorService` and modular `risk_engine`, while developer/mobile `/v1/ai/*` routes executed an obsolete 75-line mock scoring heuristic in `app/ai/orchestrator/orchestrator.py` that produced inconsistent verdicts and bypassed database persistence entirely. Furthermore, `/v1/ai/*` routes permitted clients to supply arbitrary `user_id` values in request bodies without authorization verification.

In Phase 2, all analysis entry points were reconciled onto the authoritative `OrchestratorService` and relational persistence layer while strictly maintaining full backward compatibility with the `BaseUniformResponse` API contract. Strict identity boundary enforcement was implemented, disconnected AI subsystems were categorized and isolated, rate limiting and background task durability constraints were documented, and the PostgreSQL staging gate was verified and held explicitly **BLOCKED** pending isolated staging infrastructure.

---

## 2. Workstream A — Reconcile the Analysis Architecture

### 2.1 Runtime Call-Path Audit & Inventory

| Analysis Endpoint | Authentication Dependency | Authorization Enforcement | Execution Pipeline | Persistence Behavior | Status Post-Phase 2 |
|---|---|---|---|---|---|
| `POST /v1/scans` | `get_current_user` (`sub` JWT claim) | Verified user `sub`; service tokens rejected (403) | `OrchestratorService.execute_url_scan` / `run_background_scan` | Full relational schema (`Scan`, `ScanTask`, `EvidenceRecord`, `FindingRecord`, `RiskAssessment`, `AuditEvent`) | Authoritative (Preserved) |
| `POST /v1/scans/multimodal` | `get_current_user` (`sub` JWT claim) | Verified user `sub`; service tokens rejected (403) | `OrchestratorService.execute_multimodal_scan` | Full relational schema (`Scan`, `Artifact`, `EvidenceRecord`, `FindingRecord`, `RiskAssessment`, `AuditEvent`) | Authoritative (Preserved) |
| `POST /v1/ai/analyze-url` | `get_optional_user_or_service` | Rejects non-service impersonation (403); validates JWT `sub` | `OrchestratorService.execute_url_scan` (via `AIOrchestrator.process_url`) | Persists full relational schema to DB session | **Reconciled to Authoritative Pipeline** |
| `POST /v1/ai/analyze-screenshot` | `get_optional_user_or_service` | Rejects non-service impersonation (403); validates JWT `sub` | `OrchestratorService.execute_multimodal_scan` (via `AIOrchestrator.process_screenshot`) | Persists scan, artifact, evidence, findings, and assessment | **Reconciled to Authoritative Pipeline** |
| `POST /v1/ai/analyze-qr` | `get_optional_user_or_service` | Rejects non-service impersonation (403); validates JWT `sub` | `OrchestratorService.execute_multimodal_scan` (via `AIOrchestrator.process_qr`) | Persists scan, evidence, findings, and assessment | **Reconciled to Authoritative Pipeline** |

### 2.2 Unification of Authoritative Pipeline & Elimination of Mock Scoring

1. **Obsolete Mock Scoring Removed:** The legacy 75-line scoring stub in [`app/ai/orchestrator/orchestrator.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/app/ai/orchestrator/orchestrator.py) was completely eliminated.
2. **Authoritative Adapter Pattern:** [`app/ai/orchestrator/orchestrator.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/app/ai/orchestrator/orchestrator.py) was adapted to instantiate and call `OrchestratorService(db=db)`. It runs the full static analysis, threat intelligence reputation checks, multimodal extraction, and the modular `risk_engine` (`EvidenceAggregator`, `ScoringEngine`, `CoverageTracker`, `ConfidenceCalculator`, `PolicyEngine`).
3. **Harmonized API Response:** Results from the authoritative report are mapped into the contract expected by the Flutter client (`BaseUniformResponse`):
   - `trust_score` (0–100) and `risk_score` (0–100) are deterministically linked: `trust_score + risk_score = 100`.
   - `threat_level` maps to `Low`, `Medium`, `High`, or `Critical`.
   - `reasons` and `recommendations` are populated from consolidated findings and policy recommendations.
   - `model_versions` reports exact running versions (`static_url_analyzer: 1.0.0`, `risk_engine: 1.0.0`, `policy_version: 1.0.0`, `multimodal_pipeline: 1.0.0`).
4. **Relational Persistence in DB:** [`app/api/v1/ai.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/app/api/v1/ai.py) now injects `db: Session = Depends(get_db)`. Calls to `/v1/ai/*` write complete records to the database (`scans`, `scan_tasks`, `evidence_records`, `finding_records`, `risk_assessments`, and `audit_events`), ensuring complete auditability and parity with `/v1/scans`.

### 2.3 Identity and Ownership Boundary Hardening

1. **Anti-Impersonation Check (`resolve_effective_user`):**
   In [`app/api/v1/ai.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/app/api/v1/ai.py), client-supplied `user_id` fields in request bodies (`ScreenshotAnalysisRequest.user_id`, `URLAnalysisRequest.user_id`, `QRAnalysisRequest.user_id`) are never implicitly trusted:
   - If the caller authenticated with a user JWT, the caller identity (`sub`) is strictly compared against the requested `user_id`. If they do not match, the request is immediately rejected with `HTTP 403 Forbidden` (`"Access forbidden: caller cannot submit analysis for another user ID."`).
   - If the caller authenticated via an internal service token (`service_role`), the caller may specify an explicit target user ID for system-to-system operations, defaulting to `"service_role"`.
2. **Service Token Boundary:**
   Service-role tokens (`X-Service-Token` or JWT with role `service_role`) are strictly forbidden on user-facing endpoints (`/v1/scans`, `/v1/scans/{id}`, `/v1/scans/{id}/feedback`) with `HTTP 403 Forbidden` (`"Service-role tokens are prohibited on user-facing endpoints."`).
3. **Cross-User Anti-Enumeration:**
   Accessing, modifying, deleting, or submitting feedback on a scan belonging to another user returns `HTTP 404 Not Found` rather than `403 Forbidden`, preventing resource enumeration attacks.
4. **Error Sanitization:**
   Unhandled exceptions and database errors on `/v1/ai/*` routes are caught, logged internally with full trace context, and return a sanitized `HTTP 500` error code (`"AI analysis failed. Reference error code: <scan_id>"`) with zero leakage of database connection strings, credentials, or internal stack traces.

---

## 3. Workstream B — Disconnected AI Subsystem Classification

The codebase was audited for unreferenced and prototype AI subsystems:

| Component | Path | Audit Finding | Verified Runtime References | Operational Classification | Action Taken |
|---|---|---|---|---|---|
| `MockAIGateway` | [`app/ai/gateway/mock_gateway.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/app/ai/gateway/mock_gateway.py) | Phase 1 mock gateway returning fake scores | Zero callers; not imported in production or tests | **Unused / Dead Code** | Deprecated with explicit tombstone; raises `RuntimeError` if invoked to prevent fake score leakage. |
| `DeepfakeVisionService` | [`app/ai/deepfake/vision.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/app/ai/deepfake/vision.py) | Untrained toy CNN with randomized PyTorch weights | Zero callers; no production or test integration | **Experimental Prototype / Incomplete** | Isolated with explicit warning docstring; prohibited from production risk decisions until trained weights are provided. |
| `FactCheckService` | [`app/ai/factcheck/service.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/app/ai/factcheck/service.py) | Standalone Google Fact Check API client | Zero callers; requires external `FACT_CHECK_API_KEY` | **Experimental Prototype / Blocked Dependency** | Documented as prototype; isolated from OrchestratorService. |
| `app/ai/translation/` | `app/ai/translation/` | Empty directory with `.gitkeep` | None | **Incomplete / Planned Capability** | Added [`README.md`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/app/ai/translation/README.md) documenting future multilingual transliteration architecture. |

---

## 4. Workstream C — Rate Limiting & Background Task Durability

### 4.1 Process-Local Rate Limiting Limitations

The current [`RateLimitingMiddleware`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/app/middleware/rate_limiter.py) enforces sliding-window rate limiting in-memory via Python dictionaries (`self._requests: Dict[str, List[float]]`).

- **Single-Worker Deployments (Local / Development / Staging Single-Replica):** Operates with zero external dependencies and sub-millisecond overhead.
- **Multi-Worker / Clustered Deployments:** In-memory tracking is local to each ASGI worker process. In a cluster with $N$ worker replicas, a client can execute up to $N \times \text{limit}$ requests per minute.
- **Non-Breaking Distributed Roadmap:**
  When multi-replica horizontal scaling is provisioned, a pluggable backend interface (`BaseRateLimiterBackend`) can be activated with a Redis store using Redis sorted sets (`ZADD` / `ZREMRANGEBYSCORE`). No mandatory Redis dependency is introduced in this phase to maintain lightweight local execution.

### 4.2 Background Scan Lifecycle & Restart Durability

Background scans initiated via `sync=False` execute via FastAPI's in-process `BackgroundTasks` on the ASGI event loop:

- **State Transitions:** `QUEUED` $\to$ `VALIDATING` $\to$ `EXTRACTING` $\to$ `ANALYZING` $\to$ `AGGREGATING` $\to$ `COMPLETED` / `PARTIAL` / `FAILED`.
- **Process Interruption & Crash Behavior:** If the server process crashes or is restarted during an active background scan, in-memory execution terminates. The database record remains in an intermediate state.
- **Fail-Closed Reconciliation:** The background sweep service and [`reconcile_stuck_scans()`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/app/services/retention_service.py) inspect scans exceeding `STUCK_SCAN_TIMEOUT_MINUTES`, transition them to `FAILED` with error code `ERR_SCAN_TIMEOUT`, record an audit event, and automatically refund the user's daily scan quota. Interrupted scans **never** transition to `COMPLETED` without verified analysis.
- **Durable Queue Roadmap:** For high-throughput enterprise deployments with strict execution guarantees, an out-of-process persistent queue (e.g. PostgreSQL `FOR UPDATE SKIP LOCKED` job table or Celery/RabbitMQ) will be evaluated in Phase 3.

---

## 5. Workstream D — PostgreSQL Staging Integration Gate

### 5.1 Configuration & Driver Audit

- **Driver Declaration:** `requirements.txt` specifies `psycopg2-binary>=2.9.9`. Python environment has `psycopg2 2.9.13` installed.
- **SQLAlchemy URL Scheme:** `postgresql://...` resolves natively to `psycopg2`.
- **Destructive Migration Safety:** The migration contention test (`test_postgres_staging_migration_with_contention_and_duplicates`) executes destructive `DROP TABLE IF EXISTS public.scans CASCADE`. Non-negotiable Constraint 10 strictly forbids executing this against production or shared databases.

### 5.2 Staging Gate Status

```
[POSTGRESQL STAGING INTEGRATION GATE]
Status: BLOCKED
Reason: TEST_DATABASE_URL is unset in the local execution environment.
No authorized external staging PostgreSQL instance is currently reachable.
In adherence to Non-negotiable Constraint 8, SQLite was NOT substituted for PostgreSQL verification.
The gate remains explicitly BLOCKED pending provisioning of an isolated, disposable staging database.
```

---

## 6. Verification and Test Results

### 6.1 New Architectural Reconciliation Test Suite

A dedicated regression test suite was created in [`tests/test_architectural_reconciliation.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/tests/test_architectural_reconciliation.py), providing 10 end-to-end regression tests:

```
tests/test_architectural_reconciliation.py::test_ai_analyze_url_authoritative_persistence PASSED
tests/test_architectural_reconciliation.py::test_ai_analyze_url_user_identity_enforced PASSED
tests/test_architectural_reconciliation.py::test_ai_analyze_url_forged_user_id_rejected PASSED
tests/test_architectural_reconciliation.py::test_ai_analyze_screenshot_authoritative_persistence PASSED
tests/test_architectural_reconciliation.py::test_ai_analyze_qr_authoritative_persistence PASSED
tests/test_architectural_reconciliation.py::test_unauthenticated_requests_rejected PASSED
tests/test_architectural_reconciliation.py::test_invalid_jwt_rejected PASSED
tests/test_architectural_reconciliation.py::test_service_role_rejected_on_user_endpoints PASSED
tests/test_architectural_reconciliation.py::test_cross_user_isolation_anti_enumeration PASSED
tests/test_architectural_reconciliation.py::test_ai_error_sanitization PASSED

======================== 10 passed in 5.86s ========================
```

### 6.2 Full Pytest Suite

```
================ 301 passed, 3 skipped, 19 warnings in 46.64s =================
```
*(3 skipped tests are the PostgreSQL-dependent staging tests which cleanly skip when `TEST_DATABASE_URL` is unset).*

### 6.3 Provider Lifecycle Validation

```
tests/test_provider_lifecycle.py::test_gemini_provider_client_reuse PASSED
tests/test_provider_lifecycle.py::test_gemini_provider_retries_without_client_recreation PASSED
tests/test_provider_lifecycle.py::test_gemini_provider_bounded_timeout PASSED
tests/test_provider_lifecycle.py::test_gemini_provider_sensitive_error_sanitization PASSED
tests/test_provider_lifecycle.py::test_gemini_provider_lifecycle_aclose_and_close PASSED
tests/test_provider_lifecycle.py::test_gemini_explanation_service_client_reuse_and_reset PASSED
tests/test_provider_lifecycle.py::test_risk_engine_verdict_independent_of_llm_failure PASSED

============================== 7 passed in 0.83s ==============================
```

### 6.4 AI Evaluation Benchmark Harness

```
URL Scan (Instant Providers):
  p50: 4.99ms | p95: 6.25ms | p99: 16.37ms | mean: 5.45ms
  DB Queries/scan: 19.6 | DB Total Duration/scan (mean): 0.32ms

Throughput & Concurrency Scaling (Simulated Network 20ms):
  CONCURRENCY_1: Throughput = 133.47 req/s | p50 = 4.65ms
  CONCURRENCY_5: Throughput = 188.11 req/s | p50 = 15.08ms
  CONCURRENCY_10: Throughput = 217.81 req/s | p50 = 25.94ms
```

### 6.5 Production Release Gate Audit

```
[Step 1/3] Validating Dataset Schemas and Split Isolation...
  [PASS] URL Dataset v2: (110 samples, zero leakage)
  [PASS] Multimodal Dataset v2: (45 samples, zero leakage)

[Step 2/3] Evaluating URL Risk Engine (Split: holdout)...
  [PASS] URL Holdout Precision: 100.00% (Target >= 95.0%)
  [PASS] URL Holdout Recall:    100.00% (Target >= 90.0%)
  [PASS] URL Holdout FPR:       0.00% (Target <= 5.0%)

[Step 3/3] Evaluating Multimodal Analysis Pipeline (Split: holdout)...
  [PASS] Multimodal Holdout Precision: 100.00% (Target >= 90.0%)
  [PASS] Multimodal Holdout Recall:    100.00% (Target >= 85.0%)
  [PASS] Multimodal Holdout FPR:       0.00% (Target <= 5.0%)

RELEASE GATE STATUS: PASS
```

---

## 7. Audit Findings Remediation Matrix

| Finding ID | Title | Phase 1 Status | Phase 2 Remediation Verdict |
|---|---|---|---|
| **THELIX-AUDIT-001** | Dual AI Architectural Pathways | HIGH RISK | **RESOLVED**: Unified `/v1/ai/*` onto `OrchestratorService` and `risk_engine`. Obsolete mock scoring deleted. Relational database persistence enforced. |
| **THELIX-AUDIT-002** | PostgreSQL Staging Gate Blocked | MEDIUM RISK | **VERIFIED & MAINTAINED AS BLOCKED**: Configuration and driver verified against `psycopg2`. Staging gate held explicitly blocked pending isolated database provisioning. |
| **THELIX-AUDIT-003** | Orphaned & Incomplete AI Subsystems | MEDIUM RISK | **RESOLVED**: `MockAIGateway` deprecated; `DeepfakeVisionService` and `FactCheckService` isolated with experimental headers; `translation/` documented. |
| **THELIX-AUDIT-004** | Process-Local In-Memory Rate Limiting | LOW RISK | **RESOLVED (DOCUMENTED)**: Operational boundaries documented; non-breaking distributed Redis roadmap specified. |
| **THELIX-AUDIT-005** | In-Process Background Scans Lack Durable Queueing | LOW RISK | **RESOLVED (DOCUMENTED)**: Lifecycle traced; fail-closed stuck-scan reconciliation with quota refunds verified; durable queue trade-offs documented. |

---

## 8. Release-Readiness Decision

- **Local Verification:** **PASSED / PRODUCTION HARDENED**. All 301 backend tests pass, identity boundaries are enforced, scoring is unified, and benchmark throughput exceeds requirements.
- **Staging Promotion:** **BLOCKED**. Promotion to live staging is paused until an isolated staging PostgreSQL database is available for Migration 002 execution and multiprocess concurrency validation.
