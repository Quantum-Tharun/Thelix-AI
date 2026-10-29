# PHASE 16 REPORT — CONTROLLED PILOT READINESS AND DEPLOYMENT SAFETY

**Date:** 2026-10-26  
**Status:** PASSED & VERIFIED  
**Role:** Senior Backend Architect, DevSecOps Engineer, Privacy Engineer, Reliability Engineer  

---

## 1. Executive Summary & Verification Baseline

Phase 16 transitions the Thelix AI backend from a feature-complete development prototype into a safe, controlled pilot deployment. The core objective is establishing operational boundaries, secret hygiene, privacy and data retention guarantees, fail-safe recovery mechanisms, and access controls for authorized pilot users—**without claiming general production readiness prematurely**.

### 1.1 Baseline Audit & Actual Verification
- **Verified Starting Baseline:** **188 passing tests, 0 failures, 2 upstream deprecation warnings** (in 7.64s).
- **Evaluation Release Gate Starting Baseline:** **PASS** (`python -m ai_engineering.evaluation.release_gate`).
- **Initial Deployment Audit Findings:**
  1. *Unsafe Sandbox Default:* `SAFE_LOCAL_SANDBOX_ENABLED` was set to `True` in `app/config.py`, violating the project requirement that local sandboxing remain fail-closed (`False`) until genuine OS-level or containerized isolation exists.
  2. *Credential Leak in Template:* `.env.example` contained a committed test Gemini API key token on line 17 (`AQ.Ab8RN6...`) which was immediately sanitized.
  3. *Unenforced Production Configuration:* `app/config.py` permitted placeholder secrets (`your-super-secret-key`, `thelix-internal-token-change-in-prod`), missing JWT secrets, and wildcard CORS (`*`) without validation in production.
  4. *Information Disclosure in Health Probes:* `/health/ready` returned `{str(e)}` in HTTP 503 error responses during database failures, potentially disclosing raw database hostnames, ports, and connection strings to untrusted callers.
  5. *Unbounded Retention:* Artifacts and scan records lacked automated lifecycle cleanup and TTL enforcement.
  6. *In-Process Background Task Drop Risk:* FastAPI in-process `BackgroundTasks` cannot survive worker restarts; orphaned in-flight scans had no automated recovery or timeout reconciliation mechanism.

### 1.2 Verification Post-Implementation
- **Total Test Suites:** 22 test files.
- **Total Tests Passing:** **206 passed, 0 failures, 2 upstream deprecation warnings** in 7.34s (`python -m pytest`).
- **New Tests Authored:** 18 comprehensive tests in [`tests/test_pilot_readiness.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/tests/test_pilot_readiness.py).
- **Automated Production Release Gate:** **PASS** (`python -m ai_engineering.evaluation.release_gate`).
  - URL Holdout Precision: 100.0%, Recall: 100.0%, FPR: 0.0%.
  - Multimodal Holdout Precision: 100.0%, Recall: 100.0%, FPR: 0.0%.

---

## 2. Deployment Architecture & Operational Model

```
                    Internet / Mobile & Web Clients
                                   │
                                   ▼
             ┌───────────────────────────────────────────┐
             │       Reverse Proxy / Cloud Ingress       │
             │   (Cloudflare / AWS ALB / Nginx / Caddy)   │
             │   - TLS 1.3 Termination (HTTPS)           │
             │   - IP & WAF Protection                   │
             │   - Forwards X-Forwarded-For, Proto       │
             └─────────────────────┬─────────────────────┘
                                   │ (HTTP / Unix Socket)
                                   ▼
             ┌───────────────────────────────────────────┐
             │         ASGI Application Server           │
             │    Uvicorn / Gunicorn (UvicornWorker)     │
             │                                           │
             │   ┌───────────────────────────────────┐   │
             │   │ ObservabilityMiddleware           │   │
             │   │ - Request ID (X-Request-ID)       │   │
             │   │ - Latency timing (X-Process-Time) │   │
             │   │ - Security Headers (HSTS, DENY)   │   │
             │   │ - Path secret/token masking       │   │
             │   └─────────────────┬─────────────────┘   │
             │                     ▼                     │
             │   ┌───────────────────────────────────┐   │
             │   │ RateLimitingMiddleware            │   │
             │   │ - Sliding-window IP/User limiter  │   │
             │   └─────────────────┬─────────────────┘   │
             │                     ▼                     │
             │   ┌───────────────────────────────────┐   │
             │   │ FastAPI Endpoints (/v1/...)       │   │
             │   │ - /v1/scans (URL & Multimodal)    │   │
             │   │ - /v1/maintenance                 │   │
             │   │ - /health, /health/ready          │   │
             │   └─────────────────┬─────────────────┘   │
             │                     ▼                     │
             │   ┌───────────────────────────────────┐   │
             │   │ Pilot Safety Gate                 │   │
             │   │ - Email/UID allowlist check       │   │
             │   │ - Daily quota counter (50/day)    │   │
             │   └─────────────────┬─────────────────┘   │
             │                     ▼                     │
             │   ┌───────────────────────────────────┐   │
             │   │ RiskEngine & Multimodal Pipeline  │   │
             │   │ - Fail-closed sandbox controller  │   │
             │   │ - Deterministic Scoring Engine    │   │
             │   └───────────────────────────────────┘   │
             └─────────────────────┬─────────────────────┘
                                   │
                                   ▼
             ┌───────────────────────────────────────────┐
             │             Persistence Layer             │
             │   - PostgreSQL Database (Supabase)        │
             │   - TLS Connection (sslmode=require)      │
             │   - Connection Pool (pool_size=10, max=20)│
             └───────────────────────────────────────────┘
```

### 2.1 Supported Deployment Model
- **Process Model:** ASGI service executed under `uvicorn app.main:app --host 0.0.0.0 --port 8000 --proxy-headers --forwarded-allow-ips='*'` behind a hardened reverse proxy.
- **Worker Configuration:** Multi-worker deployment via Gunicorn: `gunicorn -w 4 -k uvicorn.workers.UvicornWorker -b 0.0.0.0:8000 app.main:app`.
- **TLS & HTTPS:** Reverse proxy must terminate TLS and enforce HTTP Strict Transport Security (HSTS). The application middleware automatically injects `Strict-Transport-Security: max-age=31536000; includeSubDomains` when `ENVIRONMENT=production`.
- **Database Prerequisites:** PostgreSQL 14+ (managed Supabase instance or RDS) with SSL connection. Tables initialized via schema migrations or startup lifespan. SQLite is restricted to local development and in-memory testing.

---

## 3. Environment Separation & Configuration Specification

### 3.1 Environment Separation Matrix
[`app/config.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/app/config.py) enforces strict configuration validation during startup:

| Setting Parameter | Development Default | Pilot Mode Requirement | Production Requirement | Validation Failure Action |
|---|---|---|---|---|
| `ENVIRONMENT` | `"development"` | `"pilot"` | `"production"` | Controls validation profile. |
| `DEBUG` | `False` | `False` | `False` | `ConfigurationError` if `True` in pilot/prod. |
| `SECRET_KEY` | `"your-super-secret-key"` | Cryptographic token (>= 32 chars) | Cryptographic token (>= 32 chars) | `ConfigurationError` if default or < 32 chars. |
| `INTERNAL_SERVICE_TOKEN` | `"thelix-internal-token-change-in-prod"` | Secret token (>= 16 chars) | Secret token (>= 16 chars) | `ConfigurationError` if default or < 16 chars. |
| `SUPABASE_JWT_SECRET` | `""` (dev mock allowed) | Valid HS256 secret (>= 16 chars) | Valid HS256 secret (>= 16 chars) | `ConfigurationError` if unconfigured. |
| `ALLOWED_ORIGINS` | `"*"` | Explicit domains (no wildcard `*`) | Explicit domains (no wildcard `*`) | `ConfigurationError` if `*` is present. |
| `SAFE_LOCAL_SANDBOX_ENABLED` | `False` | `False` (Mandatory fail-closed) | `False` (Mandatory fail-closed) | `ConfigurationError` if `True` in pilot/prod. |
| `DATABASE_URL` | `sqlite:///./thelix.db` | PostgreSQL connection URL | PostgreSQL connection URL | `ConfigurationError` if SQLite in production. |
| `PILOT_MODE_ENABLED` | `False` | `True` | `False` (General availability) | Governs pilot enrollment gating. |
| `PILOT_ALLOWED_EMAILS` | `""` | Comma-separated allowlist | N/A | Restricts scan execution to pilot users. |
| `PILOT_MAX_SCANS_PER_USER_PER_DAY` | `50` | `50` | `500` (or tiered subscription) | Returns 429 Too Many Requests if exceeded. |
| `SCAN_RETENTION_DAYS` | `30` | `30` | Configurable (e.g. 30–90 days) | Automated retention threshold. |
| `ARTIFACT_RETENTION_DAYS` | `7` | `7` | Configurable (e.g. 7–30 days) | Automated artifact pruning threshold. |
| `AUDIT_LOG_RETENTION_DAYS` | `90` | `90` | Compliance retention (>= 90 days) | Preserves security audit logs. |

### 3.2 Secret Sanitization in Logs
[`Settings.sanitize_for_logging()`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/app/config.py) strips all API keys, bearer tokens, JWT secrets, and database credentials before emitting configuration records to logs or monitoring diagnostics:
- Database URLs are scrubbed: `postgresql://user:password@host/db` $\rightarrow$ `postgresql://user:[REDACTED]@host/db`.
- API keys and tokens are replaced with length-annotated tokens: `***[CONFIGURED: len=39]***` or `[UNSET]`.

---

## 4. Privacy, Data Retention, & Lifecycle Management

[`app/services/retention_service.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/app/services/retention_service.py) implements automated lifecycle rules:

### 4.1 Data Entity Lifecycles
| Data Entity | Retention Period | Storage Location | Cleanup Mechanism | Privacy Invariant |
|---|---|---|---|---|
| **Binary Artifacts** (Screenshots, PDFs) | **7 days** | Disk / Object Storage | `cleanup_expired_artifacts()` | Physical files and DB records deleted. |
| **Scan Records & Findings** | **30 days** | PostgreSQL `scans` table | `cleanup_expired_scans()` | Deleted. Audit events unlinked and preserved. |
| **Raw Extracted OCR Text** | Lifecycle of scan | Memory / DB `evidence` | Truncated to 200 chars in `raw_target` | Minimally retained. Redacted on request. |
| **Security Audit Logs** | **90 days** | PostgreSQL `audit_events` | `cleanup_expired_audit_events()` | Immutable compliance log. Retained longer than scans. |
| **User Feedback** | **30 days** | PostgreSQL `scan_feedback` | Cascaded on scan deletion | Only stores rating & comments; no raw message PII. |
| **Temporary Scratch Files** | **1 hour (TTL)** | OS temp directories | `cleanup_temp_files()` | Disposable sandbox directories removed. |

### 4.2 Audit Trail Preservation During Expiry
When scans reach their 30-day retention threshold, `cleanup_expired_scans(preserve_audit_events=True)` uncouples the associated audit events before deletion:
- `event.scan_id` is set to `NULL`.
- `event.details_json["original_scan_id_hash"]` retains an 8-character prefix hash for correlation.
- `event.details_json["scan_retention_purged_at"]` records the timestamp of data destruction.
- The parent scan row and all associated evidence, findings, and assessments are permanently deleted.
- **Benefit:** Non-repudiation audit trails (e.g. proof that a malicious domain was blocked at a specific time) remain legally verifiable without retaining user PII or sensitive targets.

### 4.3 GDPR Right-to-be-Forgotten Purge
`RetentionService.purge_user_data(user_id)` provides an authorized data wipe endpoint:
- Permanently deletes all `scans`, `artifacts`, `evidence`, `findings`, `risk_assessments`, and `feedback` belonging to `user_id`.
- Anonymizes `user_id` on surviving audit records to `"ANONYMIZED_USER"`, preserving log sequence integrity without tracking personal identity.

### 4.4 Third-Party Provider Disclosure Boundaries
To prevent surveillance or unauthorized data sharing, the backend enforces strict egress disclosure boundaries:
1. **Google Safe Browsing & VirusTotal:** Only the SHA-256 hash or domain name is transmitted. User identity, user tokens, HTTP headers, request context, and uploaded files are **never** transmitted to threat intelligence feeds.
2. **Gemini LLM:** Transmits only sanitized threat context and rule explanations. Auth tokens, user IDs, and raw sensitive headers are excluded from prompts.
3. **Local Gemma (Ollama):** Operates on-premises; zero network egress.

---

## 5. Operational Monitoring & Failure Recovery

### 5.1 Monitoring and Observability Features
- **Correlation Request IDs:** Every inbound request is assigned a unique `X-Request-ID` (or adopts incoming headers) propagated through logs, database audit records, and client response headers.
- **Latency Tracking:** Emits `X-Process-Time` response header and logs execution duration for all endpoints.
- **Standard Security Response Headers:**
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `X-XSS-Protection: 1; mode=block`
  - `Referrer-Policy: strict-origin-when-cross-origin`
  - `Strict-Transport-Security: max-age=31536000; includeSubDomains` (Production)
- **Sanitized Health Probes:**
  - `/health` and `/health/live`: Lightweight process liveness verification.
  - `/health/ready`: Verifies database connectivity, RiskEngine policy version, pilot mode state, rate limiter state, and external provider availability. If the database is unreachable, returns `503 Service Unavailable` with sanitized detail `Service unavailable: Database unreachable` without leaking internal database credentials or stack traces.

### 5.2 Failure Recovery Matrix
| Failure Scenario | System Behavior | Detection & Recovery Mechanism | Error Code |
|---|---|---|---|
| **Database Outage** | Health probe reports 503; API gracefully rejects requests. | Readiness probe failure; internal log with traceback; sanitized response detail. | `HTTP 503` |
| **Threat Intelligence Timeout** | Safe Browsing / VirusTotal times out after 3.0s. | Risk Engine catches timeout, logs warning, and completes assessment using deterministic static heuristics. Scan succeeds. | `ERR_THREAT_INTEL_TIMEOUT` |
| **LLM Explanation Timeout** | Gemini API times out after 20.0s. | `ExplanationGenerator` falls back to deterministic rule-based template explanation. Scan succeeds with deterministic score. | `ERR_LLM_TIMEOUT` |
| **Invalid / Expired Token** | Caller provides invalid or expired Supabase JWT. | `SupabaseAuthVerifier` rejects token with 401 Unauthorized; development bypass prohibited in pilot/production. | `HTTP 401` |
| **Oversized Upload / Payload** | Client attempts to upload file > 10MB or text > 500k chars. | Stream bounded read stops at 10MB + 1 byte; returns 413 Content Too Large; memory immediately reclaimed. | `HTTP 413` |
| **Server Restart During Background Scan** | Application process terminates while background scans are `QUEUED` or `PROCESSING`. | `reconcile_stuck_scans(timeout_minutes=15)` identifies orphaned non-terminal scans, transitions status to `FAILED`, and records `SCAN_TIMEOUT_RECONCILED` audit event. | `ERR_SCAN_TIMEOUT` |

> [!WARNING]
> **In-Process Task Limitation:** FastAPI in-process `BackgroundTasks` execute inside the application process memory. If the container or server restarts while a scan is in progress, the task is killed and cannot resume automatically. In Phase 16, `RetentionService.reconcile_stuck_scans()` ensures stuck scans are safely marked `FAILED` rather than hanging indefinitely. For large-scale production, a durable message queue (Celery + Redis or AWS SQS) must be introduced.

---

## 6. Controlled Pilot Access Safety Controls

### 6.1 Pilot Policy Enforcement
When `PILOT_MODE_ENABLED=True`:
1. **User Allowlist Check:**
   - Evaluates caller claims (`email` or `sub` UID) against `settings.parsed_pilot_allowed_emails`.
   - If user is not enrolled, immediately rejects with `403 Forbidden`: `Access denied: User account is not enrolled in the limited pilot program.`
2. **Daily Scan Quota Caps:**
   - Tracks total scans created by the user within the current UTC day via `ScanRepository.count_user_scans_since()`.
   - If user exceeds `PILOT_MAX_SCANS_PER_USER_PER_DAY` (default: 50), rejects with `429 Too Many Requests`: `Daily pilot scan quota exceeded (maximum 50 scans per day).`
3. **Operational Maintenance Gate:**
   - Maintenance endpoints under `/v1/maintenance/*` require either `X-Service-Token` matching `INTERNAL_SERVICE_TOKEN` or a verified Supabase `service_role` credential. Regular authenticated users are blocked with 403 Forbidden.

### 6.2 Incident Response & Rollback Procedures
- **Suspected False Positive / Missed Threat Procedure:**
  1. User submits feedback via `POST /v1/scans/{scan_id}/feedback` with rating `false_positive` or `false_negative`.
  2. Security team retrieves audit events and deterministic evidence via `GET /v1/scans/{scan_id}/events` and `GET /v1/scans/{scan_id}/report`.
  3. If static heuristic misclassification is identified, add test case to evaluation dataset (`ai_engineering/datasets/`) and calibrate rule weights.
  4. Run automated release gate to verify no regression before deployment.
- **Rollback Procedure:**
  - If a fatal error occurs in pilot deployment, immediately revert the container image or Git commit to the previous known stable release (Phase 15).
  - Database schema changes in Phase 16 are backwards-compatible (non-destructive column defaults and foreign key nullability).

---

## 7. Go / No-Go Pilot Verification Checklist

| Control Requirement | Verification Status | Implementation Evidence | Operational Limitation / Condition |
|---|---|---|---|
| **Regression Test Suite** | **VERIFIED** | 206 passing tests across 22 test files (`python -m pytest`). | Local Python 3.11 execution. |
| **AI Evaluation Release Gate** | **VERIFIED** | 100% Precision and 100% Recall on holdout datasets (`python -m ai_engineering.evaluation.release_gate`). | Synthetic benchmark datasets v2. |
| **Safe Fail-Closed Sandbox** | **VERIFIED** | `SAFE_LOCAL_SANDBOX_ENABLED=False` default; tested in `test_sandbox.py`. | Genuine containerized sandbox deferred to Phase 17. |
| **Strict Config Validation** | **VERIFIED** | Rejects insecure keys, wildcard CORS, debug mode in prod; tested in `test_pilot_readiness.py`. | Verified in memory; must set actual secrets in production. |
| **Secret Sanitization in Logs** | **VERIFIED** | `sanitize_for_logging()` masks API keys, passwords, connection strings. | Verified in `test_pilot_readiness.py`. |
| **Sanitized Health Endpoints** | **VERIFIED** | `/health` and `/health/ready` omit secrets and internal tracebacks. | Verified in `test_pilot_readiness.py`. |
| **Data Retention Pruning** | **VERIFIED** | `RetentionService` cleans artifacts (7d), scans (30d), temp files (1h). | Verified in `test_pilot_readiness.py`. Scheduled cron needed. |
| **Audit Trail Preservation** | **VERIFIED** | Expired scans delete private targets while uncoupling audit records. | Verified in `test_pilot_readiness.py`. |
| **GDPR User Data Purge** | **VERIFIED** | `purge_user_data()` erases user scans and pseudonymizes audit records. | Verified in `test_pilot_readiness.py`. |
| **Stuck Scan Recovery** | **VERIFIED** | `reconcile_stuck_scans()` marks orphaned scans as `FAILED` (`ERR_SCAN_TIMEOUT`). | Verified in `test_pilot_readiness.py`. |
| **Pilot User Allowlist** | **VERIFIED** | Unauthorized users receive 403 Forbidden; enrolled users proceed. | Verified in `test_pilot_readiness.py`. |
| **Daily Pilot Scan Caps** | **VERIFIED** | Exceeding 50 scans/day returns 429 Too Many Requests. | Verified in `test_pilot_readiness.py`. |
| **Maintenance Route Auth** | **VERIFIED** | `/v1/maintenance/*` restricted to internal service tokens. | Verified in `test_pilot_readiness.py`. |
| **HTTPS / Reverse Proxy** | **DOCUMENTED** | Documented Nginx/ALB configuration, TLS termination, HSTS headers. | Requires hosting infrastructure deployment. |
| **External Alerting** | **DOCUMENTED** | Documented Prometheus, Sentry, CloudWatch alerting requirements. | Requires external APM / monitoring setup. |
| **Durable Asynchronous Queue** | **DOCUMENTED** | Documented background task limitations; recommended Celery/Redis. | In-process background tasks used for pilot only. |

---

## 8. Pilot Recommendation & Next Steps

### Recommendation: **GO FOR CONTROLLED PILOT**
The Thelix AI backend satisfies all architectural, security, reliability, and privacy requirements for an invite-only pilot deployment with authorized users. The system is hardened against accidental information disclosure, fail-closed against untrusted browser execution, rate-limited against abuse, and protected with automated data retention lifecycles.

### Conditions Before Opening to Wider Audiences:
1. **OS-Level Container Sandboxing:** Retain `SAFE_LOCAL_SANDBOX_ENABLED=False` until microVM or gVisor sandbox workers are deployed.
2. **Durable Task Queue:** Introduce Redis/Celery before scaling beyond 100 concurrent pilot users.
3. **External Monitoring:** Connect Sentry for error tracking and Prometheus/Grafana for real-time latency dashboards.
