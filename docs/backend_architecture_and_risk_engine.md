# Thelix AI - Backend Architecture, Risk Engine & AI Integration

**Author:** Principal Backend Architect, Senior Python AI Engineer, Application Security Engineer  
**Version:** 1.0.0  
**Date:** 2026-10-26  
**Status:** Implemented & Verified  

---

## 1. Executive Summary

This document details the production-grade implementation of the **Thelix AI Backend Architecture, Deterministic Risk Engine, Isolated Inspection Sandbox, Replaceable LLM Integration, and Database Persistence Layer**.

The architecture adheres to strict security, separation-of-concerns, and testability principles:
1. **Deterministic Core:** The Risk Engine calculates reproducible risk scores, trust scores, and policy decisions using non-linear bounded aggregation with hard safety constraints.
2. **LLM as Explainer, Never Sole Authority:** The LLM translates verified technical findings into plain-language guidance, and extracts candidate context indicators; it never decides whether a target is safe.
3. **SSRF & Sandbox Isolation:** Dynamic inspection enforces rigorous network policies, preventing access to loopback, RFC 1918 private ranges, link-local addresses, and cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`).
4. **Relational Persistence & Auditability:** Durable PostgreSQL/SQLite persistence records full scan lifecycles (`QUEUED` → `VALIDATING` → `EXTRACTING` → `ANALYZING` → `AGGREGATING` → `COMPLETED`/`PARTIAL`/`REJECTED`/`FAILED`), atomic evidence, findings, and immutable audit logs.
5. **Full Backward Compatibility:** Retains all existing `/v1/ai/*` contracts expected by team frontend modules while providing rich `/v1/scans/*` client APIs.

---

## 2. System Architecture & Component Map

```mermaid
flowchart TD
    subgraph ClientLayer [Client & Presentation Layer]
        UserApp[Flutter Client / Web Dashboard]
        WorkerClient[Internal Service Workers]
    end

    subgraph APILayer [FastAPI Application Boundary]
        AuthGate[Auth & Ownership Guard]
        ScanRouter["/v1/scans (Client Workflow)"]
        AIRouter["/v1/ai (Service Gateway)"]
        ObsMiddleware[Observability Middleware]
    end

    subgraph OrchestrationLayer [Scan Orchestrator & State Machine]
        Orchestrator[OrchestratorService]
        LifecycleStateMachine[QUEUED -> VALIDATING -> EXTRACTING -> ANALYZING -> AGGREGATING -> COMPLETED]
    end

    subgraph Subsystems [Engine Subsystems]
        subgraph RiskEngineSubsystem [Risk Engine]
            Validator[InputValidator]
            Normalizer[URLNormalizer]
            StaticAnalyzer[StaticURLAnalyzer]
            ReputationAnalyzer[ReputationAnalyzer]
            Aggregator[EvidenceAggregator]
            Scorer[ScoringEngine]
            ConfidenceCalc[ConfidenceCalculator]
            CoverageTracker[CoverageTracker]
            PolicyEngine[PolicyEngine]
            ReportBuilder[ReportBuilder]
        end

        subgraph SandboxSubsystem [Isolated Sandbox]
            NetPolicy[NetworkPolicy (SSRF Defense)]
            TargetVal[TargetValidator]
            RedirectVal[RedirectValidator]
            BrowserWorker[BrowserWorker]
            EvidenceCollector[SandboxEvidenceCollector]
        end

        subgraph LLMSubsystem [LLM Integration]
            ContextInterpreter[ContextInterpreter]
            OutputValidator[OutputValidator]
            ExplanationGen[ExplanationGenerator]
            ProviderInterface[LLMProvider (Gemini / Mock)]
        end
    end

    subgraph PersistenceLayer [Data Layer]
        ScanRepo[ScanRepository]
        RelationalDB[(PostgreSQL / SQLite)]
    end

    UserApp --> AuthGate
    WorkerClient --> AuthGate
    AuthGate --> ScanRouter
    AuthGate --> AIRouter
    ScanRouter --> Orchestrator
    AIRouter --> Orchestrator

    Orchestrator --> LifecycleStateMachine
    Orchestrator --> RiskEngineSubsystem
    Orchestrator --> SandboxSubsystem
    Orchestrator --> LLMSubsystem
    Orchestrator --> ScanRepo
    ScanRepo --> RelationalDB
```

---

## 3. Risk Engine Specification

### 3.1 Scoring Algorithm & Principles
- **Separation of Concepts:**
  - **Severity:** Potential impact if finding is true (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
  - **Confidence:** Epistemic certainty of the observation (`0.0` - `1.0`).
  - **Source Reliability:** Trustworthiness of the detector (`0.0` - `1.0`).
  - **Coverage:** Completeness of intended security checks (`0.0` - `1.0`).
  - **Risk Score:** Deterministic output bounded between `0` and `100`.
  - **Trust Score:** `100 - Risk Score`.
- **Contribution Model:**
  $$c_i = \text{severity\_weight} \times \text{confidence}$$
- **Bounded Non-linear Aggregation:**
  $$\text{Raw Risk} = 100 \times \left(1 - \prod_{i=1}^{n} (1 - c_i)\right)$$
- **Rule of Maximum Danger (Floors):**
  - Confirmed `CRITICAL` threat (e.g. threat intel signature, malicious form action): **Risk Score $\ge 86$** (Critical).
  - Confirmed `HIGH` threat (e.g. brand impersonation, IP host): **Risk Score $\ge 60$** (High).
  - Benign indicators cannot cancel out strong malicious evidence.
  - Unavailable checks are never treated as negative evidence.

### 3.2 Decision Policy
| Risk Score | Coverage | Confidence | Action Verdict | Rationale |
|---|---|---|---|---|
| Any | Any | Any | **BLOCK** | Critical finding present or Risk Score $\ge 75$ |
| Low ($\le 20$) | Poor ($< 50\%$) | Any | **INCONCLUSIVE** | Safety cannot be verified due to incomplete check execution |
| Low ($\le 20$) | $\ge 50\%$ | Low ($< 50\%$) | **INCONCLUSIVE** | Target unverified in threat databases; insufficient certainty |
| Medium ($21-50$) | $\ge 50\%$ | Any | **WARN** | Suspicious lexical/DOM indicators detected |
| Low ($\le 20$) | $\ge 50\%$ | $\ge 50\%$ | **ALLOW** | No security threats identified across completed checks |

---

## 4. Isolated Sandbox & SSRF Defense

Dynamic inspection of untrusted targets occurs behind strict network isolation:
- **SSRF Mitigations (`sandbox/network_policy.py`):**
  - Loopback addresses (`127.0.0.0/8`, `::1`) are strictly blocked.
  - RFC 1918 private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) are blocked.
  - Link-local addresses (`169.254.0.0/16`, `fe80::/10`) are blocked.
  - Cloud metadata endpoints (`169.254.169.254`, `fd00:ec2::254`, `metadata.google.internal`) are blocked.
  - IPv4-mapped IPv6 addresses (`::ffff:127.0.0.1`) are detected and blocked.
- **DNS Rebinding Protection:** Resolves and validates all A/AAAA records before socket creation.
- **Per-Hop Redirect Validation (`sandbox/redirect_validator.py`):** Manual hop-by-hop verification prevents open redirects from pivoting into prohibited internal IP spaces.
- **Resource Limits:** Execution capped at 10s, max 5 redirect hops, 5MB body limit.

---

## 5. API Surface

### 5.1 Client-Facing Scan Endpoints
- `POST /v1/scans`: Initiates security scan with optional context and sandbox controls.
- `GET /v1/scans`: Lists authenticated user's scan history.
- `GET /v1/scans/{id}`: Returns scan status and metadata.
- `GET /v1/scans/{id}/report`: Returns the finalized `SecurityReport`.
- `GET /v1/scans/{id}/events`: Returns audit log entries for full lifecycle transparency.
- `DELETE /v1/scans/{id}`: Deletes scan and associated artifacts (enforces ownership).
- `POST /v1/scans/{id}/feedback`: Records user accuracy ratings (`helpful`, `false_positive`, `false_negative`).
- `POST /v1/scans/uploads`: Stages inspection artifacts with SHA-256 verification.

### 5.2 Backward-Compatible AI Gateway Endpoints
- `POST /v1/ai/analyze-url`: Returns `BaseUniformResponse` matching Flutter contracts.
- `POST /v1/ai/analyze-screenshot`: Screenshot OCR and vision analysis.
- `POST /v1/ai/analyze-qr`: QR code payload decoding and routing.

---

## 6. Test Suite & Verification Results

All 39 unit and integration tests execute successfully:

```text
tests/test_api_integration.py (7 passed)
  - test_health_endpoint
  - test_create_and_retrieve_url_scan
  - test_cross_user_scan_access_forbidden
  - test_malformed_url_rejection
  - test_upload_artifact
  - test_delete_scan
  - test_backward_compatibility_v1_ai_analyze_url

tests/test_risk_engine.py (16 passed)
  - test_valid_https_url
  - test_valid_http_url
  - test_empty_input
  - test_unsupported_scheme
  - test_malformed_url
  - test_null_byte_injection
  - test_excessively_long_url
  - test_ip_literal_hostname
  - test_userinfo_trick
  - test_misleading_brand_subdomain
  - test_idn_homograph_attack
  - test_suspicious_tld
  - test_double_percent_encoding
  - test_open_redirect_parameters
  - test_evidence_deduplication_and_correlation
  - test_poor_coverage_yields_inconclusive_never_allow

tests/test_sandbox.py (9 passed)
  - test_network_policy_blocks_localhost
  - test_network_policy_blocks_rfc1918_private_ips
  - test_network_policy_blocks_cloud_metadata
  - test_network_policy_blocks_link_local
  - test_network_policy_blocks_ipv4_mapped_ipv6
  - test_target_validator_blocks_internal_hosts
  - test_redirect_validator_blocks_pivoting_to_prohibited_targets
  - test_redirect_validator_enforces_hop_limit
  - test_sandbox_controller_blocks_ssrf_without_crashing

tests/test_llm.py (7 passed)
  - test_output_validator_parses_json_markdown
  - test_output_validator_sanitizes_script_tags
  - test_output_validator_rejects_malformed_json
  - test_context_interpreter_mock_provider
  - test_context_interpreter_fallback
  - test_explanation_generator_mock_provider
  - test_explanation_generator_fallback

======================= 39 passed in 2.88s =======================
```

---

## 7. Residual Risks & Future Roadmap

1. **Kernel/Network-Level Egress Enforcement:**
   - *Current Status:* Enforced at application layer via socket DNS inspection and IP range classification.
   - *Production Recommendation:* Add container/OS level egress firewall rules (e.g. Linux iptables/nftables or AWS Security Groups) to prevent kernel-level bypasses.
2. **Headless Browser Worker Isolation:**
   - *Current Status:* Async HTTP client worker with manual redirect tracking and BeautifulSoup DOM parsing.
   - *Production Recommendation:* For full JavaScript rendering / DOM execution, deploy Playwright Chromium inside a separate, unprivileged, scratch-container worker without host filesystem or credential mounts.
3. **Database Migration Pipeline:**
   - *Current Status:* SQLAlchemy `Base.metadata.create_all()` handles automatic table provisioning.
   - *Production Recommendation:* Initialize Alembic for versioned database schema migration tracking across staging and production PostgreSQL instances.
