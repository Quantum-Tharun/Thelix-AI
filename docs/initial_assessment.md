# Initial Architecture and Implementation Assessment

**Project:** Thelix AI  
**Author:** Principal Backend Architect & System Lead  
**Date:** 2026-10-26  
**Status:** Completed  

---

## 1. Executive Summary

An in-depth inspection of the repository was performed across all directories, configuration files, existing schemas, service stubs, and dependencies.

The current repository represents the **Python FastAPI Backend and AI Subsystem** for Thelix AI. The repository does not host the Flutter client or Serverpod code (which reside in sibling repositories/modules managed by team members Sujith and Thichanya). Per Section 2 & 3 of the master prompt, the Python FastAPI architecture serves as the foundation for the application backend workflows, the deterministic Risk Engine, the sandbox inspection subsystem, and the AI integration layer.

---

## 2. Current Repository State & Inventory

### 2.1 Backend Framework and Entry Points
- **Framework:** FastAPI (`0.141.1`), Uvicorn (`0.54.0`), Starlette (`1.6.0`).
- **Entry point:** [`app/main.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/app/main.py), mounting `/v1/ai` routes and `ObservabilityMiddleware`.
- **Config:** [`app/config.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/app/config.py) using `pydantic-settings` (`BaseSettings`) reading from `.env`.

### 2.2 Existing AI & Risk Components
- **Existing Contracts:** [`app/schemas/ai_contracts.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/app/schemas/ai_contracts.py) defines `BaseUniformResponse`, `ScreenshotAnalysisRequest`, `URLAnalysisRequest`, `QRAnalysisRequest`.
- **Existing Risk Engine:** [`app/ai/risk/engine.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/app/ai/risk/engine.py) provides a basic additive heuristic scoring (0-100) without separation of confidence, coverage, or source reliability.
- **Existing AI Gateway & Orchestrator:** [`app/ai/gateway/gateway.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/app/ai/gateway/gateway.py) and [`app/ai/orchestrator/orchestrator.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/app/ai/orchestrator/orchestrator.py) route requests across sub-services.
- **Existing Intelligence Services:**
  - [`app/ai/url_intel/service.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/app/ai/url_intel/service.py): Google Safe Browsing v4 and VirusTotal v3 API callers. (Contains a runtime bug in method invocation and missing `asyncio` import).
  - [`app/ai/gemini/explanation.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/app/ai/gemini/explanation.py): Google Generative AI integration for narrative summaries.
  - [`app/ai/ocr/service.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/app/ai/ocr/service.py), [`app/ai/qr/service.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/app/ai/qr/service.py), [`app/ai/gemma/scam_nlp.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/app/ai/gemma/scam_nlp.py), [`app/ai/deepfake/vision.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/app/ai/deepfake/vision.py), [`app/ai/factcheck/service.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/app/ai/factcheck/service.py).
  - [`ai_engineering/services/screenshot_analyzer.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/ai_engineering/services/screenshot_analyzer.py): OpenCV preprocessing pipeline.

### 2.3 Gaps Identified Against Target Architecture
1. **Risk Engine Modularization:**
   - No normalization or static URL analysis (homograph/IDN detection, IP literals, userinfo tricks, suspicious TLDs, entropy, redirect evasion).
   - Scoring lacked explicit separation between **Severity**, **Confidence**, **Source Reliability**, and **Coverage**.
   - No formal Evidence and Findings model with cryptographic indicators and correlation groups.
   - Missing decision policy with hard fail-safes and explicit verdicts (`allow`, `warn`, `block`, `inconclusive`).
2. **Isolated Inspection Sandbox:**
   - Missing dedicated isolated sandbox environment for target URL inspection.
   - Missing network policy enforcement (SSRF protection, blocking RFC1918, link-local, cloud metadata `169.254.169.254`, DNS rebinding defense).
   - Missing redirect inspection and resource limits.
3. **LLM Provider Isolation & Prompt Defense:**
   - Gemini integration lacked structured schema validation and prompt-injection guardrails.
   - No pluggable provider interface for switching providers or running mock providers during testing.
4. **Persistence & Lifecycle:**
   - `app/database`, `app/models`, `app/repositories` contained only `.gitkeep`.
   - No relational persistence for scans, tasks, evidence, findings, and audit logs.
5. **API & Endpoints:**
   - Missing client-facing scan lifecycle endpoints (`POST /v1/scans`, `GET /v1/scans/{id}`, `GET /v1/scans/{id}/report`, `POST /v1/scans/{id}/feedback`, `POST /v1/uploads`).
   - Missing service authentication and correlation ID propagation.
6. **Testing:**
   - No automated test suite existed in the repository (`tests/` directory was absent).

---

## 3. Implementation Plan & Preservation Strategy

1. **Preserve Working Contracts:**
   - Retain existing `/v1/ai/analyze-*` endpoints and [`BaseUniformResponse`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/app/schemas/ai_contracts.py#L6-L19) schema to maintain full compatibility with frontend consumers.
   - Fix bugs in [`app/ai/url_intel/service.py`](file:///c:/Users/sthar/Downloads/PlayGround/Thelix%20AI/app/ai/url_intel/service.py).
2. **Phase 2 & 3: Risk Engine Package (`risk_engine/`):**
   - Implement typed evidence, findings, URL normalization, static security heuristics, reputation adapters, deterministic scoring engine, confidence & coverage calculators, decision policy, and report builder.
   - Implement comprehensive unit tests for all edge cases.
3. **Phase 4: Isolated Inspection Environment (`sandbox/`):**
   - Implement network isolation policy (SSRF defenses: IPv4/IPv6, link-local, loopback, AWS/GCP/Azure metadata, DNS rebinding mitigation), redirect validator, target validator, resource limits, and evidence collector.
4. **Phase 5: Replaceable LLM Integration (`llm/`):**
   - Implement structured output schemas, prompt injection mitigation, context interpreter, explanation generator, and Gemini provider.
5. **Phase 6: Orchestration, Database, & Persistence:**
   - Implement database connection engine, SQLAlchemy models (scans, tasks, evidence, findings, reports, audit events), repositories, and end-to-end scan orchestrator with state machine (`QUEUED` -> `VALIDATING` -> `EXTRACTING` -> `ANALYZING` -> `AGGREGATING` -> `COMPLETED`/`PARTIAL`/`FAILED`/`REJECTED`).
6. **Phase 7: Client-Facing API:**
   - Expose `/v1/scans`, `/v1/scans/{id}`, `/v1/scans/{id}/report`, `/v1/scans/{id}/events`, `/v1/scans/{id}/feedback`, `/v1/uploads` with JWT/API key authentication and correlation IDs.
7. **Phase 8: Verification & Hardening:**
   - Run complete test suite and document operational procedures and security considerations in `docs/`.
