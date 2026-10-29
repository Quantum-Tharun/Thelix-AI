# Thelix AI — Phase 18 Report: Operational Deployment Hardening and Pilot Launch Verification

**Role:** System Architect, Application Security Engineer, DevSecOps Engineer, and AI Infrastructure Engineer  
**Date:** October 26, 2026  
**Status:** **CONDITIONAL GO (Invite-Only Pilot Launch)**  
**Target Release Gate:** PASS  

---

## Executive Summary

Phase 18 conducted an empirical, code-level operational security and infrastructure hardening audit of the Thelix AI platform. Development phases 1–17 established a solid threat detection baseline with 231 passing tests, a deterministic Risk Engine, multimodal analysis pipelines, automated release gates, and basic pilot gating. 

Phase 18 systematically resolved the remaining operational deployment risks identified in real-world infrastructure audits:
1. **Reverse-Proxy Trust Boundary Hardening**: Eliminating client IP spoofing and rate-limit evasion by restricting `X-Forwarded-For` header parsing strictly to explicitly configured trusted ingress proxies (`TRUSTED_PROXIES`).
2. **Streaming Request Body Size Enforcement**: Implementing a pure ASGI middleware (`RequestSizeLimiterMiddleware`) that tracks cumulative incoming bytes across streaming chunks, terminating oversized chunked or misreported requests with HTTP 413 before unbounded server memory buffering occurs.
3. **Database Quota Integrity & Refund Safety**: Replacing in-process-only quota incrementing with an atomic database-level conditional update SQL pattern (`UPDATE user_daily_quotas SET scan_count = scan_count + 1 WHERE ... AND scan_count < limit`), and ensuring rejected scans or runtime execution failures do not burn daily user quota.
4. **Supabase JWT & Pilot Enrollment Matrix**: Eliminating ambiguous pilot allowlist matches by normalizing zero-width confusable Unicode characters and strictly requiring explicit email verification signals (`email_verified=True` or `email_confirmed_at`). Missing verification claims are rejected with HTTP 403.
5. **Modern Gemini SDK Migration**: Migrating from the legacy, deprecated `google-generativeai` library to the official `google-genai` SDK (v2.33.0), implementing bounded `asyncio.wait_for` timeouts, sanitizing credentials and API keys from error logging, and eliminating all upstream deprecation warnings.
6. **Operational Runbooks & In-Process Task Boundaries**: Documenting backup/restore procedures, migration rollbacks, emergency scan kill-switches, and clarifying the operational boundary between in-process `BackgroundTasks` and durable enterprise queues.

---

## 1. Baseline vs. Final Verification Results

| Verification Item | Phase 17 Reported Baseline | Phase 18 Final Verified | Status / Change |
|---|---|---|---|
| **Pytest Test Suite** | 231 passed, 0 failed, 2 warnings | **248 passed, 0 failed, 0 warnings** | **+17 new operational hardening tests; 0 warnings** |
| **Upstream SDK Warnings** | 2 deprecation warnings (`google.generativeai`) | **0 warnings** | **ELIMINATED** (migrated to `google-genai`) |
| **URL Dataset v2 Schema** | 110 samples, leakage-free | 110 samples, leakage-free | **PASS** (`VALID_AND_LEAKAGE_FREE`) |
| **Multimodal Dataset v2 Schema** | 45 samples, leakage-free | 45 samples, leakage-free | **PASS** (`VALID_AND_LEAKAGE_FREE`) |
| **URL Eval Split (N=45)** | 100% Prec, 100% Rec, 0% FPR | 100% Prec, 100% Rec, 0% FPR | **PASS** |
| **Multimodal Eval Split (N=18)** | 100% Prec, 100% Rec, 0% FPR | 100% Prec, 100% Rec, 0% FPR | **PASS** |
| **AI Release Gate (Holdout URL)** | 100% Prec, 100% Rec, 0% FPR | 100% Prec, 100% Rec, 0% FPR | **PASS** (Thresholds: Prec>=95%, Rec>=90%, FPR<=5%) |
| **AI Release Gate (Holdout MM)** | 100% Prec, 100% Rec, 0% FPR | 100% Prec, 100% Rec, 0% FPR | **PASS** (Thresholds: Prec>=90%, Rec>=85%, FPR<=5%) |
| **Application Startup** | Clean import | Clean import | **VERIFIED** (Python 3.11, zero warnings) |
| **Sandbox Execution** | Disabled (`SAFE_LOCAL_SANDBOX_ENABLED=False`) | Disabled (`SAFE_LOCAL_SANDBOX_ENABLED=False`) | **VERIFIED FAIL-CLOSED** |

---

## 2. Deliverable Status Matrix

| Stage | Focus Area | Status | Implementation Details |
|---|---|---|---|
| **Stage A** | Repository Baseline Truth | **TESTED** | Baseline reproduced: 231 tests passing, release gate passing, 2 warnings recorded. |
| **Stage B** | Production Config & Ingress | **IMPLEMENTED & TESTED** | `TRUSTED_PROXIES` setting; client IP anti-spoofing; HSTS and CSP headers in pilot/prod. |
| **Stage C** | Atomic Quota & Database Integrity | **IMPLEMENTED & TESTED** | Atomic database conditional update SQL; quota refund on failure; SQLite verified. PostgreSQL **DOCUMENTED**. |
| **Stage D** | Request & Upload Resource Safety | **IMPLEMENTED & TESTED** | Pure ASGI `RequestSizeLimiterMiddleware` (10MB streaming chunk cap); PIL image limit preserved. |
| **Stage E** | Supabase JWT & Pilot Verification | **IMPLEMENTED & TESTED** | Explicit `email_verified` / `email_confirmed_at` required; zero-width confusable normalization; role isolation. |
| **Stage F** | Gemini SDK Modernization | **IMPLEMENTED & TESTED** | Upgraded to `google-genai>=2.0.0`; async bounded timeouts; API key redaction in logs/errors. |
| **Stage G** | Observability & Recovery | **IMPLEMENTED & TESTED** | Credential sanitization in health/ready; documented `BackgroundTasks` vs durable queue semantics. |
| **Stage H** | Operational Runbooks & Recovery | **DOCUMENTED** | Backup/restore, migration rollback, emergency kill switch, credential rotation, and incident triage runbooks. |
| **Stage I** | Independent Regression & Gate | **TESTED** | Full 248 test suite, dataset validation, eval runners, release gate, clean startup all passed. |
| **Stage J** | Final Reporting & Decision | **IMPLEMENTED** | Phase 18 comprehensive report authored with justified pilot decision. |

---

## 3. Detailed Technical Findings and Remediations

### Stage B — Production Ingress, Reverse-Proxy Trust, and Anti-Spoofing
- **Finding (B-1: Client IP Spoofing via Unchecked Forwarded Headers)**: Previous rate-limiting logic extracted client IP addresses directly from `X-Forwarded-For` without verifying whether the immediate peer connecting to the FastAPI application was an authorized reverse proxy. An untrusted attacker could send arbitrary `X-Forwarded-For: 1.1.1.1` headers to evade per-IP rate limiting or frame other users.
- **Remediation**:
  - Added `TRUSTED_PROXIES: str = ""` setting to [`app/config.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/app/config.py) with a parsed set property `parsed_trusted_proxies`.
  - Updated [`app/middleware/rate_limiter.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/app/middleware/rate_limiter.py): `_extract_client_id` now checks if the direct peer IP (`request.client.host`) is present in `parsed_trusted_proxies`. If not present, `X-Forwarded-For` is strictly ignored, falling back safely to the direct connecting peer IP. When behind a trusted proxy (e.g. AWS ALB, Cloudflare), the first public hop is extracted.
- **Finding (B-2: Ingress Security Headers Missing in Pilot/Production)**: Response headers lacked HSTS and content security restrictions when running in pilot or production modes.
- **Remediation**:
  - Updated [`app/middleware/observability.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/app/middleware/observability.py) to automatically inject:
    - `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
    - `X-Content-Type-Options: nosniff`
    - `X-Frame-Options: DENY`
    - `Content-Security-Policy: default-src 'none'; frame-ancestors 'none';`
  - HSTS is conditionally omitted in `ENVIRONMENT="development"` to avoid breaking local localhost workflows.
- **Finding (B-3: Health and Readiness Information Leakage)**:
  - Verified that `/health`, `/health/live`, `/health/ready`, and `/readiness` expose no database connection strings, passwords, internal network topologies, or hostnames.

### Stage C — Atomic Quota and Database Concurrency Integrity
- **Finding (C-1: In-Process Thread Lock Inadequate for Multi-Process Deployments)**: `ScanRepository.reserve_daily_scan_quota` previously relied on an in-memory `threading.Lock()`. In a multi-worker production environment (e.g., Gunicorn with Uvicorn workers), separate processes do not share threading locks, creating a potential race condition where concurrent requests could exceed `PILOT_MAX_SCANS_PER_USER_PER_DAY`.
- **Remediation**:
  - Hardened [`ScanRepository.reserve_daily_scan_quota`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/app/repositories/scan_repository.py): Implemented an atomic database-level conditional update SQL statement:
    ```python
    updated = self.db.query(UserDailyQuota).filter(
        UserDailyQuota.user_id == user_id,
        UserDailyQuota.date_key == date_key,
        UserDailyQuota.scan_count < limit,
    ).update(
        {
            UserDailyQuota.scan_count: UserDailyQuota.scan_count + 1,
            UserDailyQuota.updated_at: datetime.now(timezone.utc),
        },
        synchronize_session=False,
    )
    self.db.commit()
    return updated > 0
    ```
  - Added concurrency collision handling with transactional rollback if two processes simultaneously attempt initial row creation on the unique index `ix_user_daily_quota_unique`.
- **Finding (C-2: Quota Burn on Malformed or Rejected Payloads)**: In `create_multimodal_scan`, quota reservation was executed before input validation. Submitting an invalid `input_type` or an empty request body burned one daily scan slot.
- **Remediation**:
  - In [`app/api/v1/scans.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/app/api/v1/scans.py), split pilot checks into permission verification (`check_quota=False`) and atomic quota reservation. Quota is now reserved **only after** input validation (valid input type, file size bounds, non-empty payload) succeeds.
  - Implemented automatic quota refunding via `repo.refund_daily_scan_quota(user_id, date_key)` in the exception handlers of both `create_scan` and `create_multimodal_scan` so runtime processing errors do not penalize users.
- **Infrastructure Limitation**: Cross-process concurrency was verified under SQLite in local tests. Isolated multi-process PostgreSQL verification is marked **DOCUMENTED** because PostgreSQL was not installed locally.

### Stage D — Streaming Request Body Size Enforcement
- **Finding (D-1: Vulnerability to Chunked Transfer and Misreported Content-Length)**: Starlette and FastAPI read the `Content-Length` header for initial body sizing. However, chunked transfer encoding (`Transfer-Encoding: chunked`) omits the `Content-Length` header entirely, and malicious clients can declare a small `Content-Length` (e.g. 100 bytes) while streaming gigabytes of data.
- **Remediation**:
  - Created [`app/middleware/request_size_limiter.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/app/middleware/request_size_limiter.py) implementing `RequestSizeLimiterMiddleware`.
  - The middleware intercepts ASGI `receive()` events, tracking cumulative bytes across all streaming chunks. The moment cumulative bytes exceed `MAX_UPLOAD_SIZE_BYTES` (10MB), it immediately halts stream reception and returns HTTP 413 `Payload Too Large` with JSON details and security headers.
  - Pre-validates `Content-Length` if present to fail fast on declared oversized payloads.
  - Registered as the outermost request processing middleware in [`app/main.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/app/main.py).

### Stage E — Supabase JWT & Pilot Identity Allowlist Matrix
- **Finding (E-1: Ambiguous Email Verification Claims in Allowlist Check)**: Previous logic allowed pilot enrollment if an email was listed in `PILOT_ALLOWED_EMAILS` without rigorously checking whether the Supabase authentication provider had verified the email address. An attacker signing up with an unconfirmed target email could gain unauthorized pilot access.
- **Remediation**:
  - Hardened `enforce_pilot_access_and_quota` in [`app/api/v1/scans.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/app/api/v1/scans.py):
    - Strictly defaults `email_is_verified = False`.
    - Verification is only granted if `claims.get("email_verified") is True`, `claims.get("email_confirmed_at")` contains a valid non-empty confirmation timestamp, or `user_metadata.get("email_verified") is True`.
    - Missing or null verification claims are treated as unverified, raising HTTP 403 Forbidden.
- **Finding (E-2: Unicode Confusable / Zero-Width Characters in Allowlist)**:
  - Added canonical email normalization: stripped zero-width spaces, joiners, and byte order marks (`\u200b-\u200d\ufeff`), trimmed whitespace, and converted to lowercase.
- **Finding (E-3: Service Role Isolation)**:
  - Verified that tokens with `service_role` claims are rejected on user-facing scan routes with HTTP 403, and normal user tokens are rejected on administrative maintenance routes (`/v1/maintenance/*`) with HTTP 403.

### Stage F — Modern Gemini SDK (`google-genai`) Migration
- **Finding (F-1: Deprecated `google-generativeai` SDK and Warning Noise)**: The codebase previously used `google-generativeai==0.3.2`, which issued upstream deprecation warnings and lacked official support for modern GenAI client concurrency patterns.
- **Remediation**:
  - Installed official `google-genai==2.33.0` and updated [`requirements.txt`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/requirements.txt) to `google-genai>=2.0.0`.
  - Migrated [`app/ai/gemini/explanation.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/app/ai/gemini/explanation.py) to use `from google import genai; from google.genai import types` with `client.aio.models.generate_content`.
  - Migrated [`llm/gemini_provider.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/llm/gemini_provider.py) to the new `genai.Client` and `types.GenerateContentConfig` architecture.
  - Added strict `asyncio.wait_for` timeouts to prevent hanging client connections.
  - Added `_sanitize_error` regular expressions to strip Google API keys (`AIza...`) and credentials from error messages and logs.
  - Preserved deterministic fallback: if Gemini fails, times out, or returns invalid schemas, the static deterministic Risk Engine decision is strictly preserved. The LLM has zero authority to override risk scores or allow malicious targets.
  - Completely eliminated all upstream deprecation warnings across the test suite (0 warnings).

### Stage G — Observability and BackgroundTasks Operational Boundaries
- **Clarification on FastAPI `BackgroundTasks` vs Durable Queues**:
  - In-process FastAPI `BackgroundTasks` execute within the same Python worker memory space as the HTTP server.
  - **Operational Constraint**: If a worker process terminates abruptly (OOM, SIGKILL, pod restart), queued in-process background tasks are lost.
  - The built-in stuck-scan reconciliation routine recovers orphaned scan records in the database (`ERR_SCAN_TIMEOUT`), but **does not provide durable distributed queue semantics** (such as message persistence, dead-letter exchanges, or cross-node retries).
  - For the limited, invite-only pilot (low concurrency, trusted users), this architectural simplicity avoids operational dependencies on Redis/Celery/RabbitMQ. For full commercial scale, a durable queue is mandatory and documented in the roadmap.

---

## 4. Operational Runbooks (Stage H)

### 4.1 Database Backup and Restore Responsibilities
- **Hosting Boundary**: Managed Supabase PostgreSQL or cloud-managed RDS/Cloud SQL.
- **Backup Schedule**: Automated daily full snapshots with point-in-time recovery (PITR) enabled for 7 days.
- **Pre-Migration Snapshot**: A manual snapshot must be initiated immediately before executing any database migration:
  ```bash
  # Supabase CLI snapshot
  supabase db dump --data-only -f backup_pre_phase18.sql
  ```
- **Restore Procedure**:
  1. Terminate active application backend instances to stop incoming writes.
  2. Restore the point-in-time snapshot to an isolated staging instance.
  3. Validate database schema integrity and row counts (`scans`, `assessments`, `findings`, `user_daily_quotas`).
  4. Repoint application connection strings (`DATABASE_URL`) to the restored database and restart backend.

### 4.2 Migration Rollback Strategy
- **Alembic / Schema Rollbacks**: All schema migrations must provide an idempotent downgrade script.
- **Rollback Execution**:
  ```bash
  # Revert single migration
  alembic downgrade -1
  ```
- **Entity Rollback for `user_daily_quotas`**:
  If the `user_daily_quotas` table must be reverted:
  ```sql
  DROP INDEX IF EXISTS ix_user_daily_quota_unique;
  DROP TABLE IF EXISTS user_daily_quotas;
  ```

### 4.3 Emergency Scan Kill-Switch Procedure
If a critical vulnerability, threat intelligence provider malfunction, or scanning flood occurs, operations can immediately suspend scanning via environment configuration without redeploying code:
1. **Kill Switch Activation**:
   Set `PILOT_MODE_ENABLED=True` and `PILOT_ALLOWED_EMAILS=""` (or remove all user emails). All scan submissions immediately fail fast with HTTP 403 Forbidden.
2. **Alternative Gateway Disabling**:
   Set `SAFE_LOCAL_SANDBOX_ENABLED=False` (already permanently disabled by policy) and remove third-party API keys (`VIRUSTOTAL_API_KEY=""`, `SAFE_BROWSING_API_KEY=""`). The system safely drops into deterministic static analysis mode.

### 4.4 Credential Rotation Procedures
- **Supabase JWT Secret**:
  1. Generate a new cryptographically secure 256-bit secret.
  2. Configure Supabase Auth with the new secret and update `SUPABASE_JWT_SECRET` in production secrets manager (e.g. AWS Secrets Manager, Infisical).
  3. Perform a zero-downtime rolling restart of backend workers. Existing user sessions will be prompted to re-authenticate.
- **Threat Intel & LLM Keys (`GEMINI_API_KEY`, `VIRUSTOTAL_API_KEY`, `SAFE_BROWSING_API_KEY`)**:
  1. Generate new API keys in respective cloud provider consoles.
  2. Update environment secrets and trigger rolling restart.
  3. Revoke legacy keys once new keys are confirmed active via `/health/ready`.

### 4.5 Security Incident Triage Workflow
1. **Alert Ingestion**: Observability alarms trigger on elevated 5xx errors, rate-limiting spikes (>100 RPM), or unauthorized access bursts.
2. **Target Isolation**: Retrieve audit timeline via `GET /v1/scans/{scan_id}/events` to inspect immutable scan transitions.
3. **Data Purge**: If an uploaded artifact contains sensitive user material or a privacy incident is reported, execute user purge via `DELETE /v1/maintenance/users/{user_id}/data` with service-role credentials.

---

## 5. Reverse-Proxy Ingress Architecture

```
Internet Clients
      │
      ▼
Cloudflare / AWS ALB (Trusted Ingress Proxy)
  - Enforces TLS 1.3 / HTTPS termination
  - Strips untrusted X-Forwarded-For headers from external clients
  - Sets X-Forwarded-For: <Client_IP>
      │
      ▼ (VPC Private Subnet / Ingress Firewall)
Thelix AI Backend (FastAPI + Uvicorn)
  - Ingress Middleware checks request.client.host against TRUSTED_PROXIES
  - If direct peer is in TRUSTED_PROXIES -> Trusts X-Forwarded-For
  - If direct peer is NOT in TRUSTED_PROXIES -> Discards header, uses direct peer IP
  - RequestSizeLimiterMiddleware checks cumulative streaming bytes (<= 10MB)
  - RateLimitingMiddleware enforces sliding-window limit per verified client IP
  - ObservabilityMiddleware enforces HSTS, CSP, X-Frame-Options, X-Content-Type-Options
```

**Required Production Configuration**:
```env
ENVIRONMENT=pilot
TRUSTED_PROXIES=10.0.0.1,10.0.0.2,172.16.0.0/12
MAX_UPLOAD_SIZE_BYTES=10485760
PILOT_MODE_ENABLED=True
PILOT_ALLOWED_EMAILS=pilot-tester-1@thelix.ai,pilot-tester-2@thelix.ai
PILOT_MAX_SCANS_PER_USER_PER_DAY=10
SAFE_LOCAL_SANDBOX_ENABLED=False
```

---

## 6. Files Changed in Phase 18

| File Path | Description of Changes |
|---|---|
| [`requirements.txt`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/requirements.txt) | Migrated `google-generativeai>=0.3.2` to official `google-genai>=2.0.0`. |
| [`app/config.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/app/config.py) | Added `TRUSTED_PROXIES` setting and `parsed_trusted_proxies` property. |
| [`app/middleware/rate_limiter.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/app/middleware/rate_limiter.py) | Enforced trusted proxy verification before reading `X-Forwarded-For`. |
| [`app/middleware/observability.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/app/middleware/observability.py) | Added HSTS and strict CSP injection in pilot and production environments. |
| [`app/middleware/request_size_limiter.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/app/middleware/request_size_limiter.py) | **New file**: Pure ASGI streaming body size limiter tracking cumulative chunk bytes. |
| [`app/main.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/app/main.py) | Registered `RequestSizeLimiterMiddleware`; added `/readiness` route alias. |
| [`app/api/v1/scans.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/app/api/v1/scans.py) | Enforced explicit `email_verified` / `email_confirmed_at` check; canonical zero-width confusable normalization; deferred quota reservation after validation; added quota refunds. |
| [`app/repositories/scan_repository.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/app/repositories/scan_repository.py) | Implemented atomic database conditional update SQL for `reserve_daily_scan_quota` and rollback handling. |
| [`app/ai/gemini/explanation.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/app/ai/gemini/explanation.py) | Modernized to `google.genai` SDK with bounded `asyncio.wait_for` and sanitized error logging. |
| [`llm/gemini_provider.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/llm/gemini_provider.py) | Modernized to `google.genai` SDK with bounded timeouts and API key redaction in errors. |
| [`tests/test_pilot_readiness.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/tests/test_pilot_readiness.py) | Updated `make_pilot_headers` helper to default `email_verified=True`. |
| [`tests/test_operational_hardening.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/tests/test_operational_hardening.py) | **New file**: 17 focused operational hardening tests covering Stages B through G. |

---

## 7. Test Execution and Verification Commands

All verifications were executed directly against the local repository:

1. **Full Pytest Suite**:
   ```bash
   python -m pytest
   # Output: 248 passed in 8.29s (0 failures, 0 warnings)
   ```
2. **Focused Operational Hardening Suite**:
   ```bash
   python -m pytest tests/test_operational_hardening.py
   # Output: 17 passed in 3.67s (0 failures, 0 warnings)
   ```
3. **URL Evaluation Dataset Validator**:
   ```bash
   python -m ai_engineering.evaluation.dataset_validator ai_engineering/datasets/url_evaluation_dataset_v2.json
   # Output: VALID_AND_LEAKAGE_FREE (110 samples, zero leakage)
   ```
4. **Multimodal Evaluation Dataset Validator**:
   ```bash
   python -m ai_engineering.evaluation.dataset_validator ai_engineering/datasets/multimodal_evaluation_dataset_v2.json
   # Output: VALID_AND_LEAKAGE_FREE (45 samples, zero leakage)
   ```
5. **URL Evaluation Runner (Eval Split)**:
   ```bash
   python -m ai_engineering.evaluation.eval_runner --split eval
   # Output: Precision=100.0%, Recall=100.0%, FPR=0.0% (N=45)
   ```
6. **Multimodal Evaluation Runner (Eval Split)**:
   ```bash
   python -m ai_engineering.evaluation.multimodal_eval_runner --split eval
   # Output: Precision=100.0%, Recall=100.0%, FPR=0.0% (N=18)
   ```
7. **Production AI Release Gate (Holdout Split)**:
   ```bash
   python -m ai_engineering.evaluation.release_gate
   # Output: RELEASE GATE STATUS: PASS (Holdout URL: 100% Prec/Rec; Holdout MM: 100% Prec/Rec)
   ```
8. **Application Startup Verification**:
   ```bash
   python -c "from app.main import app; print('Application imported cleanly without errors or warnings')"
   # Output: Application imported cleanly without errors or warnings
   ```

---

## 8. Remaining Risks and Blockers

1. **Local PostgreSQL Concurrency Verification (BLOCKED by Infrastructure)**:
   - A multi-process PostgreSQL integration test could not be run because PostgreSQL and `psycopg2`/`asyncpg` were not installed in the local environment.
   - While SQLite verified the atomic conditional update logic, a staging environment PostgreSQL concurrency stress test must be executed prior to public release.
2. **In-Process Task Loss on Worker Restarts (DOCUMENTED Limitation)**:
   - FastAPI `BackgroundTasks` are not durable across server restarts or OOM events. The stuck-scan reconciliation routine cleans up database records, but dropped tasks do not automatically re-execute. This is acceptable for the invite-only pilot but requires Celery/Redis for commercial scale.
3. **Sandbox Browser Worker Remains Fail-Closed (DOCUMENTED Operational Policy)**:
   - `SAFE_LOCAL_SANDBOX_ENABLED=False` remains strictly enforced. No untrusted URL is launched in an arbitrary local browser environment.

---

## 9. Final Launch Recommendation

### **Recommendation: CONDITIONAL GO (Invite-Only Pilot Launch)**

The backend, AI gateway, deterministic Risk Engine, and operational ingress components meet the rigorous standards required for an invite-only pilot.

**Prerequisites to be verified upon cloud deployment**:
1. Deploy behind a managed reverse proxy (Cloudflare or AWS ALB) with HTTPS termination and configure `TRUSTED_PROXIES` with the reverse proxy private CIDR block.
2. Confirm the managed PostgreSQL database is provisioned with automated daily backups and point-in-time recovery enabled.
3. Populate `PILOT_ALLOWED_EMAILS` with only verified tester accounts.
4. Maintain `SAFE_LOCAL_SANDBOX_ENABLED=False` in all pilot environment configurations.
