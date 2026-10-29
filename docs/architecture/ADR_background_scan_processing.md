# Architecture Decision Note: Reliable Background Scan Processing and Recovery Strategy

**Document ID:** ADR-2026-001  
**Status:** PROPOSED / ADOPTED IN HYBRID OUTBOX RECONCILIATION  
**Deciders:** System Architect, Principal Backend Reliability Engineer, Database Integration Specialist  
**Context:** Thelix AI Asynchronous Scan Execution, Worker Restarts, Quota Preservation, and Crash Recovery  

---

## 1. Context and Problem Statement

When clients submit targets for deep analysis with browser sandboxing (`enable_sandbox=True` and `sync=False`), the backend responds with HTTP 202 Accepted and executes the scan asynchronously.
In the initial development phase, background scans were dispatched via in-process `fastapi.BackgroundTasks` / `asyncio.create_task`. While functional for single-node development, this pattern presents specific reliability risks under production deployment:
1. **Process Restarts & Deployments:** In-flight tasks executed in process memory are terminated without cleanup if a worker process crashes, is recycled by Uvicorn/Gunicorn, or is replaced during rolling container deployments.
2. **Scan State Inconsistency:** Scans interrupted mid-flight remain permanently in non-terminal states (`QUEUED`, `VALIDATING`, `EXTRACTING`, `PROCESSING`, `ANALYZING`, `AGGREGATING`) unless active reconciliation exists.
3. **Daily Quota Burn:** Unenrolled or pilot users who had daily quota decremented on submission would permanently lose their quota allocation for interrupted scans unless refund semantics are transactional and idempotent.
4. **Dual-Write Hazard:** If database persistence and external queue publishing are performed independently without a transactional boundary, database rollback after queueing (or queue failure after database commit) leads to phantom jobs or dropped requests.

---

## 2. Evaluation of Architectural Options

We evaluated three viable engineering options against strict operational criteria:
- **Zero Job Loss:** Ability to survive process death and resume/reconcile.
- **Idempotency & Quota Safety:** Guarantee against double-refunds or duplicate terminal overwrites.
- **Dependency Overhead:** Infrastructure requirements (PostgreSQL, Redis, RabbitMQ).
- **Client Contract Stability:** Preserves HTTP 202 Accepted response schema and `/v1/scans/{scan_id}` polling.

| Evaluation Dimension | Option A: In-Process `BackgroundTasks` + Stuck-Scan Reconciliation | Option B: Relational Transactional Outbox Pattern | Option C: Dedicated Distributed Queue (Celery / ARQ / Redis Streams) |
|---|---|---|---|
| **Persistence Boundary** | Relational DB + In-Memory Task | **Atomically written inside same DB transaction as Scan** | External broker (separate TCP roundtrip; dual-write risk) |
| **Recovery Mechanism** | Periodic reconciliation via `/v1/maintenance/reconcile-stuck` | Polling worker loop with `SELECT ... FOR UPDATE SKIP LOCKED` | Broker ack/nack and dead-letter queue (DLQ) |
| **Failure Mode on Worker Crash** | Scan marks `FAILED (ERR_SCAN_TIMEOUT)` after timeout; quota refunded | In-progress task picked up by surviving worker or retried | Worker re-queued via unacked message visibility timeout |
| **Infrastructure Prerequisites** | None (pure Python + SQLite/PostgreSQL) | None (uses existing PostgreSQL database and `scan_tasks` table) | Managed Redis cluster or RabbitMQ broker required |
| **Operational Complexity** | Low (requires 5-minute cron/scheduler) | Low-Medium (single database management, clean observability) | High (broker monitoring, serialization, worker fleet lifecycle) |
| **Duplicate Delivery Safety** | Guaranteed by unique `scan_id` & immutable terminal states | Guaranteed by database row locking & status transition guards | Requires manual application-level deduplication layer |

---

## 3. Decision: Phase 4 Hybrid Outbox & Authoritative Reconciliation Architecture

We adopt **Option B (Relational Transactional Outbox Pattern)** anchored by the existing `scan_tasks` and `scans` tables, reinforced by the proven **Authoritative Reconciliation Mechanism (`RetentionService.reconcile_stuck_scans`)**.

### 3.1 Architectural Principles:
1. **Single Transaction Boundary:** When an asynchronous scan is accepted, the `Scan` record (status `QUEUED`), the initial audit event (`SCAN_QUEUED`), and the quota reservation are committed in a single atomic database transaction before HTTP 202 Accepted is emitted.
2. **Deterministic State Machine Invariants:**
   - Terminal states (`COMPLETED`, `PARTIAL`, `FAILED`, `REJECTED`, `CANCELLED`) are strictly immutable. Once a scan reaches a terminal state, subsequent transitions are rejected at the database query level (`WHERE status NOT IN ('COMPLETED', 'PARTIAL', 'FAILED', 'REJECTED', 'CANCELLED')`).
   - Every state transition must satisfy the `VALID_STATUS_TRANSITIONS` matrix.
3. **Atomic Quota Reservation and Refund Idempotency:**
   - Quota reservation is strictly bounded by conditional SQL: `UPDATE user_daily_quotas SET scan_count = scan_count + 1 WHERE scan_count < limit`.
   - Quota refunds are recorded with an explicit unique constraint on `QuotaRefundRecord.scan_id`. Multiple refund attempts for the same scan are rejected, preventing negative counters.
4. **Authoritative Stuck-Scan Reconciliation:**
   - Any scan remaining non-terminal beyond `STUCK_SCAN_TIMEOUT_MINUTES` (default 15 minutes) is transitioned to `FAILED` with code `ERR_SCAN_TIMEOUT`.
   - The reconciliation process executes an atomic conditional update:
     `UPDATE scans SET status='FAILED', completed_at=:now WHERE id=:id AND status NOT IN ('COMPLETED', 'PARTIAL', 'FAILED', 'REJECTED', 'CANCELLED')`.
   - If `updated == 0`, the scan completed concurrently on another worker; reconciliation skips without modifying the scan or refunding quota.
   - If `updated == 1`, the scan was genuinely stalled; the daily quota is refunded to the user, and an audit event `SCAN_TIMEOUT_RECONCILED` is logged.

### 3.2 Recovery & Maintenance Runbook:
- **API Server Process:**
  `uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4`
  The API writes the `Scan` record (`status='QUEUED'`) and outbox `ScanTask` (`status='PENDING'`) atomically before returning HTTP 202 Accepted.
- **Durable Worker Daemon Process:**
  `python -m app.worker --poll-interval 2.0 --lease-seconds 300`
  Runs independently of the API web workers. Claims tasks using `SELECT ... FOR UPDATE SKIP LOCKED` (PostgreSQL) or atomic conditional updates (SQLite), executes the scan orchestrator, records latency, handles bounded retries, and releases leases upon completion.
- **Scheduled Reconciliation Task (Operator Responsibility):**
  An automated external scheduler (e.g., Kubernetes CronJob, AWS EventBridge, or Linux systemd timer) executes:
  `curl -X POST -H "Authorization: Bearer <service_token>" http://api:8000/v1/maintenance/reconcile-stuck`
  every 5 minutes.
  Reconciliation skips any scan whose task is actively leased by a live worker.

---

## 4. Consequences and Compatibility

- **Positive:** No new external broker (such as Celery or RabbitMQ) is required; deployment dependencies remain minimal and robust.
- **Positive:** Public API contracts (`/v1/scans` POST returning 202 Accepted) remain 100% backward-compatible.
- **Positive:** Quotas, terminal states, and audit trails remain strictly consistent under arbitrary worker restarts and concurrency.
- **Prerequisite for Production:** Running `python -m app.worker` as an independent service in Docker/Kubernetes, and configuring automated 5-minute scheduling of `/v1/maintenance/reconcile-stuck`.

