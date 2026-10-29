# THELIX AI — BACKEND ARCHITECTURE & SPECIFICATION

**Role:** Principal Backend Architect, Senior Python AI/ML Engineer, Application Security Engineer  
**Status:** Implemented, Corrected & Verified (49/49 Tests Passing)  
**Version:** 2.0.0  
**Date:** 2026-10-26  

---

## 1. Executive Summary & Architectural Decisions

This document establishes the corrected technology architecture for **Thelix AI**, transitioning the system from container-dependent prototypes to a production-grade, modular, locally runnable backend.

### Key Architectural Decisions:
1. **Supabase Auth for Identity:**
   - Client requests are authenticated via Supabase JWT access tokens (`Authorization: Bearer <token>`).
   - Tokens are cryptographically validated against `SUPABASE_JWT_SECRET` (HS256) verifying signature, expiration (`exp`), audience (`aud` including `authenticated` and `service_role`), and issuer.
   - User identity is **strictly derived from the verified token claim (`sub`)**. Untrusted client headers or body-supplied user IDs are never used for identity or authorization.
   - No separate, conflicting local `users` table is maintained. Database entities reference Supabase `auth.users(id)` directly.
2. **Supabase PostgreSQL for Persistence:**
   - Scan records, tasks, evidence, findings, risk assessments, audit events, feedback, and staged artifacts are persisted with full relational integrity.
   - Row Level Security (RLS) policies are enforced at the database layer (`auth.uid() = user_id`) to ensure strict tenant isolation.
   - Service-role credentials (`SUPABASE_SERVICE_ROLE_KEY`) are kept server-side only.
3. **FastAPI Modular Backend:**
   - Clean, versioned REST endpoints (`/v1/scans/*` and backward-compatible `/v1/ai/*`).
   - Non-blocking asynchronous processing via `BackgroundTasks` for dynamic sandbox and multi-source scans (returns `202 Accepted` immediately).
4. **Deterministic Risk Engine (Core Authority):**
   - Scoring, confidence assessment, coverage calculation, and policy decisions are 100% deterministic, testable, and rule-governed.
   - The LLM never determines whether a target is safe and cannot override risk decisions.
5. **Safe Local Sandbox (No Docker Required):**
   - Playwright Chromium and headless HTTP workers run locally with strict application-level SSRF mitigations, DNS rebinding defenses, hop-by-hop redirect verification, and resource limits.
   - Features a fail-closed switch (`SAFE_LOCAL_SANDBOX_ENABLED=False`) when local host isolation is inadequate.
6. **Gemini as Testing-Only LLM Explainer:**
   - Configurable via `LLM_PROVIDER=gemini`, `GEMINI_MODEL=gemini-1.5-flash` (or `gemini-pro`).
   - Strictly acts as an interpreter of user context and explainer of verified findings.
   - Wrapped by a defensive output validator with fallback to deterministic explanations if unavailable.

---

## 2. Complete System Architecture & Data Flow

```mermaid
flowchart TD
    subgraph ClientPresentation [Client & Native Layer]
        FlutterApp[Flutter Mobile App / Web UI]
        NativeCapture[Android Screen Capture / Accessibility]
    end

    subgraph AuthSubsystem [Supabase Identity & Security Gate]
        SupabaseAuth[Supabase Auth Service]
        TokenVerifier[SupabaseAuthVerifier (JWT HS256)]
        IdentityExtractor[Extract Verified 'sub' UUID]
    end

    subgraph APILayer [FastAPI Application Boundary]
        ScanAPI["/v1/scans (Client Workflow API)"]
        AICompatAPI["/v1/ai (Service Gateway API)"]
        AsyncDispatcher[BackgroundTasks Worker Pool]
    end

    subgraph OrchestrationSubsystem [Scan Orchestrator & State Machine]
        Orchestrator[OrchestratorService]
        StateMachine["Lifecycle State Machine (QUEUED -> VALIDATING -> EXTRACTING -> ANALYZING -> AGGREGATING -> COMPLETED)"]
    end

    subgraph CoreEngines [Inspection & Assessment Subsystems]
        subgraph RiskEngineSubsystem [Deterministic Risk Engine]
            InputValidator[InputValidator]
            URLNormalizer[URLNormalizer]
            StaticAnalyzer[StaticURLAnalyzer]
            ReputationAnalyzer[ReputationAnalyzer]
            EvidenceAggregator[EvidenceAggregator]
            ScoringEngine[ScoringEngine]
            ConfidenceTracker[ConfidenceCalculator]
            CoverageTracker[CoverageTracker]
            PolicyEngine[PolicyEngine]
            ReportBuilder[ReportBuilder]
        end

        subgraph LocalSandboxSubsystem [Local Inspection Sandbox]
            NetPolicy[NetworkPolicy (SSRF Defense)]
            TargetValidator[TargetValidator]
            DNSResolver[DNS Rebinding Defense]
            RedirectValidator[Hop-by-Hop RedirectValidator]
            ResourceLimits[ResourceLimits Enforcer]
            BrowserWorker[Playwright / Async HTTP Worker]
            DOMCollector[DOM & Header EvidenceCollector]
        end

        subgraph LLMSubsystem [LLM Explainer & Context Subsystem]
            ContextInterpreter[ContextInterpreter]
            OutputValidator[Defensive OutputValidator]
            ExplanationGen[ExplanationGenerator]
            ProviderInterface["LLMProvider (Gemini / Mock)"]
        end
    end

    subgraph PersistenceLayer [Supabase PostgreSQL & Storage]
        ScanRepo[ScanRepository]
        PostgresDB[(Supabase PostgreSQL + RLS)]
        SupabaseStorage[Supabase Object Storage / Artifacts]
    end

    FlutterApp -- "1. Authenticate" --> SupabaseAuth
    SupabaseAuth -- "2. Access Token (JWT)" --> FlutterApp
    FlutterApp -- "3. POST /v1/scans (Bearer JWT)" --> TokenVerifier
    TokenVerifier -- "4. Validated Claims" --> IdentityExtractor
    IdentityExtractor -- "5. Verified user_id" --> ScanAPI

    ScanAPI -- "6. Asynchronous Dispatch (202 Accepted)" --> AsyncDispatcher
    AsyncDispatcher --> Orchestrator
    Orchestrator --> StateMachine

    Orchestrator -- "Static Checks & Heuristics" --> RiskEngineSubsystem
    Orchestrator -- "Controlled Fetch (if enabled)" --> LocalSandboxSubsystem
    Orchestrator -- "Context Interpretation & Findings Explanation" --> LLMSubsystem
    
    RiskEngineSubsystem -- "Deterministic Verdict" --> Orchestrator
    Orchestrator -- "Persist State, Findings, Report, Audit" --> ScanRepo
    ScanRepo --> PostgresDB
```

---

## 3. Repository Structure & Module Standards

The backend is organized into clean, single-responsibility modules:

```text
Thelix AI/
├── app/
│   ├── main.py                  # FastAPI application entry point, lifecycle, CORS
│   ├── config.py                # Environment configuration & pydantic settings
│   ├── api/
│   │   ├── deps.py              # Auth & database dependency injection
│   │   └── v1/
│   │       ├── scans.py         # Full scan workflow (create, list, get, report, feedback, delete)
│   │       ├── ai.py            # Backward-compatible AI gateway endpoints (/v1/ai/*)
│   │       └── router.py        # Central API router
│   ├── auth/
│   │   ├── supabase.py          # Supabase JWT token verification, claim parsing
│   │   └── security.py          # FastAPI dependencies (get_current_user_id, service_role)
│   ├── database/
│   │   └── session.py           # SQLAlchemy session setup, engine configuration
│   ├── models/
│   │   ├── entities.py          # Declarative relational models (scans, tasks, evidence, reports)
│   │   └── enums.py             # Enums: ScanStatus, ThreatLevel, ActionVerdict, etc.
│   ├── schemas/
│   │   ├── scan.py              # Pydantic request/response schemas for scans
│   │   └── report.py            # Structured report schemas
│   ├── repositories/
│   │   └── scan_repository.py   # Data access layer for scans, evidence, reports, audit logs
│   ├── services/
│   │   └── orchestrator_service.py # Core scan coordination and lifecycle management
│   └── middleware/
│       └── observability.py     # Request ID correlation, latency tracking, audit logging
├── risk_engine/
│   ├── __init__.py              # Public interface for the Risk Engine
│   ├── engine.py                # Facade orchestrating analysis and report building
│   ├── input_validator.py       # Syntax, scheme, and length validation
│   ├── url_normalizer.py        # Canonicalization, IDN punycode, encoding normalization
│   ├── static_analyzer.py       # Lexical, structural, and homograph threat indicators
│   ├── reputation_analyzer.py   # Domain reputation, Safe Browsing & intelligence adapter
│   ├── evidence.py              # Strongly-typed Evidence and Finding models
│   ├── evidence_aggregator.py   # Finding correlation and deduplication
│   ├── scoring.py               # Deterministic non-linear risk and trust calculation
│   ├── confidence.py            # Evidence confidence and reliability evaluator
│   ├── coverage.py              # Security check coverage tracker
│   ├── policy.py                # Action verdict evaluator (ALLOW, WARN, INCONCLUSIVE, BLOCK)
│   ├── report_builder.py        # Final security report generation
│   └── exceptions.py            # Risk engine exceptions
├── sandbox/
│   ├── __init__.py              # Public interface for inspection sandbox
│   ├── controller.py            # Inspection controller with fail-closed security switch
│   ├── network_policy.py        # IP classification, RFC 1918, link-local, cloud metadata defense
│   ├── target_validator.py      # Pre-flight host & scheme validation
│   ├── redirect_validator.py    # Per-hop redirect inspection against SSRF pivoting
│   ├── resource_limits.py       # Timeouts, payload sizes, and hop bounds
│   ├── evidence_collector.py    # DOM, response header, and security artifact extractor
│   └── browser_worker.py        # Headless inspection worker (HTTP / Playwright)
├── llm/
│   ├── __init__.py              # Public interface for LLM subsystem
│   ├── schemas.py               # Interpretation and explanation schemas
│   ├── provider.py              # Abstract base provider & mock provider
│   ├── gemini_provider.py       # Google GenAI Gemini integration (gemini-1.5-flash)
│   ├── context_interpreter.py   # User context indicator extractor
│   ├── explanation_generator.py # Plain-language findings explainer
│   └── output_validator.py      # XSS, prompt injection, and JSON schema sanitizer
├── docs/
│   ├── backend_architecture.md  # This document
│   └── supabase_schema.sql      # Production PostgreSQL schema and RLS policies
├── tests/
│   ├── test_risk_engine.py      # 16 Risk Engine unit tests
│   ├── test_sandbox.py          # 9 Sandbox & SSRF security tests
│   ├── test_llm.py              # 7 LLM & output validation tests
│   ├── test_supabase_auth.py    # 7 Supabase JWT verification tests
│   └── test_api_integration.py  # 10 API, async processing, and tenant isolation tests
├── requirements.txt             # Verified Python dependencies
└── .env.example                 # Example configuration environment variables
```

---

## 4. Supabase Integration Architecture

### 4.1 Authentication & Token Verification (`app/auth/supabase.py`)
- **JWT Cryptographic Verification:** All incoming requests to protected routes must supply `Authorization: Bearer <token>`.
- **Validation Pipeline:**
  1. Token is decoded using the secret key (`SUPABASE_JWT_SECRET`).
  2. Algorithm is constrained strictly to `HS256`.
  3. Signature, expiration (`exp`), and audience (`aud`) are verified. The audience must include `authenticated` or `service_role`.
  4. The subject claim (`sub`) must be a valid UUID representing the user identity.
- **Identity Derivation:** The user's ID is extracted directly from the verified `sub` claim. Client-supplied headers (e.g. `X-User-ID`) or request body properties are ignored.
- **Service Role Support:** Internal administrative workflows can authenticate using `X-Service-Token: <SUPABASE_SERVICE_ROLE_KEY>`, which validates server-side without exposing keys to clients.

### 4.2 Database Persistence & Row Level Security (`docs/supabase_schema.sql`)
The persistence model eliminates redundant user management by referencing `auth.users(id)`:

```sql
-- Schema excerpt: Scans table bound to Supabase auth.users
CREATE TABLE public.scans (
    scan_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    target TEXT NOT NULL,
    input_type VARCHAR(32) NOT NULL DEFAULT 'url',
    status VARCHAR(32) NOT NULL DEFAULT 'QUEUED',
    enable_sandbox BOOLEAN NOT NULL DEFAULT FALSE,
    context_notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- Row Level Security (RLS) enforcement
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can only view their own scans"
    ON public.scans FOR SELECT
    USING (auth.uid() = user_id);

CREATE POLICY "Users can only insert their own scans"
    ON public.scans FOR INSERT
    WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can only delete their own scans"
    ON public.scans FOR DELETE
    USING (auth.uid() = user_id);
```

Similar RLS policies protect `scan_tasks`, `evidence`, `findings`, `risk_assessments`, `scan_feedback`, `audit_events`, and `artifacts`.

---

## 5. Deterministic Risk Engine Specification

The Risk Engine evaluates input data through deterministic rules, generating reproducible risk scores, trust scores, and policy decisions.

### 5.1 Scoring Formula & Aggregation
- **Risk Score Range:** `[0, 100]` where `0` is completely safe and `100` is critical danger.
- **Trust Score:** `100 - Risk Score`.
- **Severity Weights:**
  - `CRITICAL`: `0.90` (Active phishing, known malware, credential harvesting)
  - `HIGH`: `0.65` (Brand impersonation, IP literal target, malicious redirect)
  - `MEDIUM`: `0.35` (Suspicious TLD, double percent-encoding, deceptive subdomains)
  - `LOW`: `0.15` (HTTP without TLS, excessive subdomains)
  - `INFO`: `0.00` (Neutral observations)
- **Contribution Model:**
  $$c_i = w(\text{severity}_i) \times \text{confidence}_i$$
- **Bounded Non-linear Accumulation:**
  $$\text{Raw Score} = 100 \times \left(1 - \prod_{i=1}^{n} (1 - c_i)\right)$$
- **Rule of Maximum Danger (Floors):**
  - Any confirmed `CRITICAL` finding sets a minimum floor of **Risk Score $\ge 86$**.
  - Any confirmed `HIGH` finding sets a minimum floor of **Risk Score $\ge 60$**.
  - Benign observations never subtract from or dilute malicious findings.

### 5.2 Conflict Resolution Matrix
When contradictory evidence arises (e.g. static domain analysis is clean, but context or DOM structure contains high-risk login forms):
1. **Safety does not override malice:** A "safe" Google Safe Browsing result cannot cancel an IDN homograph attack or a verified phishing credential harvester.
2. **Missing data is not safety:** An unreachable reputation API or failed DNS lookup decreases **Coverage**; it never reduces the Risk Score.
3. **Incomplete coverage defaults to caution:** If coverage is below `50%` and no critical threats are found, the action verdict is `INCONCLUSIVE`, never `ALLOW`.

### 5.3 Policy Decision Engine
| Risk Score | Coverage | Confidence | Action Verdict | Rationale |
|---|---|---|---|---|
| $\ge 75$ or Critical Finding | Any | Any | **BLOCK** | Verified threat detected; immediate block recommended |
| $51 - 74$ | Any | Any | **BLOCK** | Substantial risk indicators present |
| $21 - 50$ | $\ge 50\%$ | Any | **WARN** | Suspicious characteristics identified; proceed with caution |
| $\le 20$ | $< 50\%$ | Any | **INCONCLUSIVE** | Incomplete check execution; safety cannot be guaranteed |
| $\le 20$ | $\ge 50\%$ | $< 50\%$ | **INCONCLUSIVE** | Confidence too low to grant clean bill of health |
| $\le 20$ | $\ge 50\%$ | $\ge 50\%$ | **ALLOW** | All security checks executed and verified clean |

---

## 6. Local Sandbox Architecture & Security Boundary

Dynamic inspection of untrusted targets is supported locally without Docker, using strict application-level guardrails.

### 6.1 Security Controls (`sandbox/`)
1. **Target Pre-Flight Validation:** Schemes are restricted to `http` and `https`. Hostnames are normalized and validated against IP literal heuristics.
2. **SSRF & Network Boundary Defense (`sandbox/network_policy.py`):**
   - Loopback (`127.0.0.0/8`, `::1`) blocked.
   - RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) blocked.
   - Link-local subnets (`169.254.0.0/16`, `fe80::/10`) blocked.
   - Cloud metadata IPs (`169.254.169.254`, `metadata.google.internal`) blocked.
   - IPv4-mapped IPv6 addresses (`::ffff:127.0.0.1`) detected and blocked.
3. **DNS Resolution & Rebinding Defense:**
   - Pre-flight DNS resolution validates all resolved A and AAAA records against network policy.
   - Any destination resolving to private/loopback/metadata IP spaces is aborted before socket connection.
4. **Hop-by-Hop Redirect Validation (`sandbox/redirect_validator.py`):**
   - Auto-redirects in HTTP clients are disabled.
   - Each redirect hop is manually intercepted and re-validated against the full SSRF network policy to prevent pivoting into internal networks.
   - Redirect chain is capped at 5 hops.
5. **Resource Limits:**
   - 10-second inspection timeout.
   - 5 MB maximum response payload.
   - Process and worker memory constraints.

### 6.2 Security Limitations & Fail-Closed Policy
> [!CAUTION]
> **Security Boundary Limitation:**  
> Application-level URL and DNS validation in Python does **not** constitute an operating-system-level security boundary. A local subprocess sharing the host network and kernel cannot guarantee protection against zero-day browser sandbox escapes or sophisticated DNS rebinding TOCTOU race conditions.
>
> To ensure enterprise safety:
> - The sandbox includes `SAFE_LOCAL_SANDBOX_ENABLED=False` by default in sensitive environments.
> - When disabled, any attempt to run live browser dynamic inspection **fails closed safely**, falling back to static URL analysis and reputation checks without executing live code.

---

## 7. Replaceable Gemini Testing Integration

The LLM subsystem (`llm/`) integrates Google Gemini as a testing and explanation layer:

### 7.1 Provider Configuration
```env
LLM_PROVIDER=gemini
GEMINI_MODEL=gemini-1.5-flash
GEMINI_API_KEY=your-gemini-api-key
```

### 7.2 Strict Operational Guardrails
- **LLM May:**
  - Parse user context (e.g., "Received SMS claiming my bank account is locked") to extract candidate brand names, claimed urgency, and purported domains.
  - Generate plain-language summaries of verified findings and risk scores.
  - Suggest actionable advice (e.g., "Do not enter your password; contact your bank directly").
- **LLM Must Not:**
  - Decide whether a URL is malicious or safe.
  - Override, alter, or dilute the deterministic Risk Engine score.
  - Fabricate reputation, blacklist, or threat intelligence hits.
  - Execute arbitrary tools, system commands, or external network requests.
- **Defensive Output Sanitization:** All LLM responses are processed through `OutputValidator` to enforce JSON schema conformance, strip HTML/script tags, and thwart prompt injection attacks.
- **Graceful Fallback:** If the Gemini API experiences network timeouts, quota exhaustion, or returns malformed data, the system falls back seamlessly to deterministic, template-based explanations.

---

## 8. API Specification & Lifecycle Management

### 8.1 API Surface
| Endpoint | Method | Status Code | Auth Required | Description |
|---|---|---|---|---|
| `/health` | GET | 200 | No | Health check, service status |
| `/v1/scans` | POST | 202 / 201 | Yes (JWT) | Create scan (202 for async sandbox, 201 for sync) |
| `/v1/scans` | GET | 200 | Yes (JWT) | List authenticated user's scan history |
| `/v1/scans/{id}` | GET | 200 | Yes (JWT) | Retrieve scan status, metadata, and progress |
| `/v1/scans/{id}/report` | GET | 200 | Yes (JWT) | Retrieve finalized structured security report |
| `/v1/scans/{id}/events` | GET | 200 | Yes (JWT) | Retrieve scan audit log events |
| `/v1/scans/{id}` | DELETE | 204 | Yes (JWT) | Delete scan and associated staged artifacts |
| `/v1/scans/{id}/feedback` | POST | 201 | Yes (JWT) | Submit user feedback (`helpful`, `false_positive`) |
| `/v1/scans/uploads` | POST | 201 | Yes (JWT) | Stage file/image artifact for future analysis |
| `/v1/ai/analyze-url` | POST | 200 | Service/User | Backward-compatible frontend contract endpoint |

### 8.2 Asynchronous Execution Architecture
To prevent HTTP client timeouts during deep browser inspection (which can take 5–15 seconds):
1. `POST /v1/scans` immediately creates a scan record in the database with status `QUEUED`.
2. Returns `202 Accepted` with `scan_id` and initial status.
3. Dispatches analysis via FastAPI's `BackgroundTasks` running in an isolated execution thread with its own database session.
4. Clients poll `GET /v1/scans/{id}` or retrieve the final report via `GET /v1/scans/{id}/report`.
5. Synchronous execution is supported for lightweight or automated test runs via `"sync": true`.

---

## 9. Local Development & Setup Instructions (No Docker)

### Prerequisites
- Python 3.11+
- Git

### Step-by-Step Local Setup

1. **Clone and Enter Repository:**
   ```bash
   git clone https://github.com/your-org/thelix-ai.git
   cd thelix-ai
   ```

2. **Create and Activate Virtual Environment:**
   ```bash
   # Windows PowerShell
   python -m venv venv
   .\venv\Scripts\Activate.ps1

   # Linux / macOS
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install Dependencies:**
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

4. **Install Playwright Browsers (for dynamic inspection):**
   ```bash
   playwright install chromium
   ```

5. **Configure Environment:**
   Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```
   Set your Supabase configuration:
   ```env
   ENVIRONMENT=development
   SUPABASE_URL=https://your-project.supabase.co
   SUPABASE_KEY=your-supabase-anon-key
   SUPABASE_SERVICE_ROLE_KEY=your-supabase-service-role-key
   SUPABASE_JWT_SECRET=your-supabase-jwt-secret
   DATABASE_URL=sqlite:///./thelix.db  # Or postgresql://... for Supabase Postgres
   LLM_PROVIDER=gemini
   GEMINI_MODEL=gemini-1.5-flash
   GEMINI_API_KEY=your-api-key-here
   SAFE_LOCAL_SANDBOX_ENABLED=true
   ```

6. **Run the Backend Locally:**
   ```bash
   uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
   ```
   Interactive Swagger documentation will be available at `http://127.0.0.1:8000/docs`.

7. **Execute the Full Test Suite:**
   ```bash
   pytest tests/ -v
   ```

---

## 10. Test Verification Results

All 49 unit, integration, and security tests execute cleanly across 5 targeted test suites:

| Test Suite | Total Tests | Passed | Failed | Key Capabilities Verified |
|---|---|---|---|---|
| `tests/test_risk_engine.py` | 16 | 16 | 0 | Input validation, normalization, IDN homographs, brand subdomains, double encoding, evidence deduplication, coverage constraints |
| `tests/test_sandbox.py` | 9 | 9 | 0 | SSRF blocking (localhost, RFC 1918, link-local, cloud metadata, IPv6 mapped IPv4), redirect hop limits, DNS rebinding |
| `tests/test_llm.py` | 7 | 7 | 0 | Prompt injection defense, script sanitization, JSON schema extraction, provider fallback, explanation generator |
| `tests/test_supabase_auth.py` | 7 | 7 | 0 | JWT HS256 validation, expired token rejection, tampered signature rejection, audience checks, user identity derivation |
| `tests/test_api_integration.py` | 10 | 10 | 0 | Health check, sync scans, async 202 scans, tenant isolation, cross-user 404 enforcement, feedback, uploads, backward compatibility |
| **Total** | **49** | **49** | **0** | **100% Pass Rate** |

---

## 11. Security Audit & Residual Risks

1. **Local Sandbox Network Egress:**
   - *Mitigation:* Multi-stage IP classification, DNS pre-flight checks, and hop-by-hop redirect tracking.
   - *Limitation:* Does not replace OS kernel network namespaces or Linux `seccomp`/`cgroups`.
   - *Recommendation for Production:* In cloud staging/production environments, execute the Playwright browser worker in an isolated, unprivileged microVM or ephemeral container with strict firewall egress filtering.
2. **Database Migrations:**
   - *Mitigation:* `docs/supabase_schema.sql` provides the complete schema and RLS policies.
   - *Recommendation:* Incorporate Alembic or Supabase CLI (`supabase db push`) into CI/CD pipelines to track migrations version by version.
3. **LLM Token Costs & Quotas:**
   - *Mitigation:* LLM calls are cached, optional, and only invoked when context analysis or user-facing narrative explanations are requested.
