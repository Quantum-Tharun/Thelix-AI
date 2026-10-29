"""
Orchestrator Service
Coordinates the end-to-end scan lifecycle, multi-engine parallel execution,
evidence collection, deterministic risk evaluation, and database persistence.
"""
from typing import Optional, Dict, Any, List
import uuid
import time
import asyncio
from datetime import datetime, timezone
import logging
from sqlalchemy.orm import Session

from app.models.entities import Scan
from app.repositories.scan_repository import ScanRepository
from risk_engine.engine import RiskEngine
from risk_engine.evidence import Evidence, Finding, ActionVerdict, RiskLevel, Severity
from risk_engine.url_normalizer import URLNormalizer, NormalizedURL
from risk_engine.exceptions import (
    ValidationError,
    MalformedURLException,
    UnsupportedSchemeException,
)
from risk_engine.report_builder import SecurityReport, ReportBuilder
from risk_engine.coverage import CoverageTracker
from risk_engine.confidence import ConfidenceCalculator
from risk_engine.policy import PolicyEngine
from risk_engine.scoring import ScoringEngine
from risk_engine.evidence_aggregator import EvidenceAggregator
from sandbox.controller import SandboxController
from sandbox.target_validator import TargetValidator
from llm.provider import LLMProvider, MockLLMProvider
from llm.gemini_provider import GeminiProvider
from llm.context_interpreter import ContextInterpreter
from llm.explanation_generator import ExplanationGenerator
from app.config import settings
from ai_engineering.multimodal.contracts import InputType, MultimodalAnalysisReport
from ai_engineering.multimodal.multimodal_orchestrator import MultimodalOrchestrator
import hashlib

logger = logging.getLogger("thelix.orchestrator")


class OrchestratorService:
    """
    Coordinates asynchronous execution of analysis tasks, transitions scan lifecycle states,
    and guarantees fail-safe evidence persistence.
    """

    def __init__(self, db: Session, llm_provider: Optional[LLMProvider] = None):
        self.db = db
        self.repo = ScanRepository(db)

        # Initialize LLM provider
        if llm_provider:
            self.llm_provider = llm_provider
        elif settings.LLM_PROVIDER == "gemini" and settings.GEMINI_API_KEY:
            self.llm_provider = GeminiProvider(
                api_key=settings.GEMINI_API_KEY,
                model_name=settings.GEMINI_MODEL,
                max_retries=settings.LLM_MAX_RETRIES,
            )
        else:
            self.llm_provider = MockLLMProvider()

        self.context_interpreter = ContextInterpreter(self.llm_provider)
        self.explanation_generator = ExplanationGenerator(self.llm_provider)
        self.sandbox_controller = SandboxController()
        self.risk_engine = RiskEngine()
        self.multimodal_orchestrator = MultimodalOrchestrator()

    async def execute_url_scan(
        self,
        target_url: str,
        user_id: str,
        scan_id: Optional[str] = None,
        context: Optional[str] = None,
        enable_sandbox: bool = True,
    ) -> SecurityReport:
        """
        Executes full URL scan lifecycle:
        QUEUED -> VALIDATING -> EXTRACTING -> ANALYZING -> AGGREGATING -> COMPLETED
        """
        scan_id = scan_id or str(uuid.uuid4())
        start_time = time.time()

        try:
            # 1. State: QUEUED
            self.repo.create_scan(
                scan_id=scan_id,
                user_id=user_id,
                input_type="url",
                raw_target=target_url,
                policy_version=RiskEngine.POLICY_VERSION,
                engine_versions=self.risk_engine.engine_versions,
            )
            self.repo.record_audit_event("SCAN_QUEUED", scan_id, user_id, {"target_url": target_url})

            # 2. State: VALIDATING
            try:
                norm: NormalizedURL = URLNormalizer.normalize(target_url)
            except (ValidationError, MalformedURLException, UnsupportedSchemeException) as e:
                self.repo.update_scan_status(scan_id, "REJECTED", completed_at=datetime.now(timezone.utc))
                self.repo.record_task(
                    scan_id=scan_id,
                    engine_name="url_normalizer",
                    status="FAILED",
                    error_code=e.code,
                    error_message=e.message,
                )
                report = await self.risk_engine.analyze_url(target_url, scan_id=scan_id)
                self._persist_report_entities(scan_id, report)
                return report

            self.repo.update_scan_status(scan_id, "VALIDATING", normalized_target=norm.normalized_url)

            # 3. State: EXTRACTING (Context interpretation)
            self.repo.update_scan_status(scan_id, "EXTRACTING")
            if context:
                ctx_start = time.time()
                interpretation = await self.context_interpreter.interpret(context)
                ctx_duration = int((time.time() - ctx_start) * 1000)
                self.repo.record_task(
                    scan_id=scan_id,
                    engine_name="context_interpreter",
                    status="COMPLETED",
                    latency_ms=ctx_duration,
                )

            # 4. State: ANALYZING
            self.repo.update_scan_status(scan_id, "ANALYZING")
            planned_checks = ["static_analysis"]
            completed_checks: List[str] = []
            failed_checks: List[str] = []
            skipped_checks: List[str] = []

            all_evidence: List[Evidence] = []
            all_findings: List[Finding] = []

            # Run Static Analysis & Sandbox Inspection concurrently where appropriate
            analysis_tasks = []

            # Task A: Risk Engine base analysis (Static + Reputation)
            async def run_risk_engine():
                t0 = time.time()
                try:
                    base_rep = await self.risk_engine.analyze_url(norm.normalized_url, scan_id=scan_id, normalized_url=norm)
                    dur = int((time.time() - t0) * 1000)
                    self.repo.record_task(
                        scan_id=scan_id,
                        engine_name="static_url_analyzer",
                        status="COMPLETED",
                        latency_ms=dur,
                    )
                    return base_rep
                except Exception as ex:
                    dur = int((time.time() - t0) * 1000)
                    self.repo.record_task(
                        scan_id=scan_id,
                        engine_name="static_url_analyzer",
                        status="FAILED",
                        latency_ms=dur,
                        error_message=str(ex),
                    )
                    return None

            # Task B: Isolated Sandbox Target Inspection (if target passes policy)
            async def run_sandbox_inspection():
                if not enable_sandbox:
                    skipped_checks.append("isolated_sandbox")
                    return [], [], {"skipped": True}

                planned_checks.append("isolated_sandbox")
                t0 = time.time()
                try:
                    sb_ev, sb_fn, sb_meta = await self.sandbox_controller.inspect_target(norm.normalized_url)
                    dur = int((time.time() - t0) * 1000)
                    status = "COMPLETED" if sb_meta.get("completed") else ("BLOCKED" if sb_meta.get("blocked") else "FAILED")
                    self.repo.record_task(
                        scan_id=scan_id,
                        engine_name="isolated_sandbox",
                        status=status,
                        latency_ms=dur,
                        error_message=sb_meta.get("error"),
                    )
                    if sb_meta.get("completed"):
                        completed_checks.append("isolated_sandbox")
                    else:
                        failed_checks.append("isolated_sandbox")
                    return sb_ev, sb_fn, sb_meta
                except Exception as ex:
                    dur = int((time.time() - t0) * 1000)
                    self.repo.record_task(
                        scan_id=scan_id,
                        engine_name="isolated_sandbox",
                        status="FAILED",
                        latency_ms=dur,
                        error_message=str(ex),
                    )
                    failed_checks.append("isolated_sandbox")
                    return [], [], {"error": str(ex)}

            # Run concurrent sub-tasks
            base_report, (sb_evidence, sb_findings, sb_meta) = await asyncio.gather(
                run_risk_engine(),
                run_sandbox_inspection()
            )

            if base_report:
                all_evidence.extend(base_report.evidence)
                all_findings.extend(base_report.findings)
                completed_checks.extend(base_report.checks_completed)
                failed_checks.extend(base_report.checks_failed)

            all_evidence.extend(sb_evidence)
            all_findings.extend(sb_findings)

            # 5. State: AGGREGATING
            self.repo.update_scan_status(scan_id, "AGGREGATING")

            # Deduplicate & consolidate
            deduped_ev, consolidated_fn = EvidenceAggregator.aggregate(all_evidence, all_findings)

            # Compute deterministic score
            risk_score, trust_score, risk_level, audit_meta = ScoringEngine.calculate_score(consolidated_fn)

            # Coverage evaluation
            coverage = CoverageTracker.evaluate(
                planned=planned_checks,
                completed=completed_checks,
                failed=failed_checks,
                skipped=skipped_checks,
            )

            # Confidence calculation
            confidence = ConfidenceCalculator.calculate(
                evidence=deduped_ev,
                findings=consolidated_fn,
                coverage_ratio=coverage.coverage_ratio,
            )

            # Policy decision
            action, policy_reason, recommendations = PolicyEngine.decide(
                risk_score=risk_score,
                confidence=confidence,
                coverage=coverage,
                findings=consolidated_fn,
            )

            # 6. Generate LLM Explanation
            exp_start = time.time()
            explanation_obj = await self.explanation_generator.generate_explanation(
                risk_score=risk_score,
                trust_score=trust_score,
                risk_level=risk_level,
                action=action,
                findings=consolidated_fn,
            )
            exp_duration = int((time.time() - exp_start) * 1000)
            self.repo.record_task(
                scan_id=scan_id,
                engine_name="explanation_generator",
                status="COMPLETED",
                latency_ms=exp_duration,
            )

            # Summary
            if action == ActionVerdict.BLOCK:
                summary = f"Dangerous target blocked (Trust Score: {trust_score}/100)."
            elif action == ActionVerdict.WARN:
                summary = f"Suspicious target: exercise caution (Trust Score: {trust_score}/100)."
            elif action == ActionVerdict.INCONCLUSIVE:
                summary = f"Assessment inconclusive: {policy_reason}"
            else:
                summary = f"No security threats identified (Trust Score: {trust_score}/100)."

            final_status = "PARTIAL" if failed_checks else "COMPLETED"

            # Build final report
            final_report = ReportBuilder.build(
                scan_id=scan_id,
                target_url=target_url,
                normalized_url=norm.normalized_url,
                scan_status=final_status.lower(),
                risk_score=risk_score,
                trust_score=trust_score,
                risk_level=risk_level,
                confidence=confidence,
                coverage=coverage,
                action=action,
                summary=summary,
                findings=consolidated_fn,
                evidence=deduped_ev,
                recommendations=recommendations,
                engine_versions=self.risk_engine.engine_versions,
                policy_version=RiskEngine.POLICY_VERSION,
                explanation=explanation_obj.plain_text_explanation,
            )

            # 7. Persist to Relational DB & Terminal State
            self._persist_report_entities(scan_id, final_report)
            self.repo.update_scan_status(scan_id, final_status, completed_at=datetime.now(timezone.utc))
            self.repo.record_audit_event(
                f"SCAN_{final_status}",
                scan_id,
                user_id,
                {
                    "risk_score": risk_score,
                    "trust_score": trust_score,
                    "action": action.value,
                    "duration_ms": int((time.time() - start_time) * 1000),
                }
            )

            return final_report
        except Exception as exc:
            logger.error(f"Scan {scan_id} failed with unhandled error: {exc}", exc_info=True)
            self.repo.fail_scan(
                scan_id=scan_id,
                error_code="SCAN_EXECUTION_ERROR",
                error_message=str(exc)[:500],
            )
            raise

    def _persist_report_entities(self, scan_id: str, report: SecurityReport):
        """Saves evidence, findings, and assessment to the database."""
        try:
            self.repo.save_evidence_and_findings(
                scan_id=scan_id,
                evidence_list=report.evidence,
                findings_list=report.findings,
            )
            self.repo.save_risk_assessment(
                scan_id=scan_id,
                risk_score=report.risk_score,
                trust_score=report.trust_score,
                risk_level=report.risk_level.value,
                confidence=report.confidence,
                coverage_ratio=report.coverage_ratio,
                recommended_action=report.recommended_action.value,
                summary=report.summary,
                explanation=report.explanation,
            )
        except Exception as e:
            logger.error(f"Failed to persist report entities for scan {scan_id}: {e}")

    @classmethod
    async def run_background_scan(
        cls,
        scan_id: str,
        target_url: str,
        user_id: str,
        context: Optional[str] = None,
        enable_sandbox: bool = True,
    ):
        """Asynchronously executes scan in dedicated background DB session with fail-safe recovery."""
        from app.database.session import SessionLocal
        db = SessionLocal()
        try:
            service = cls(db=db)
            await service.execute_url_scan(
                target_url=target_url,
                user_id=user_id,
                scan_id=scan_id,
                context=context,
                enable_sandbox=enable_sandbox,
            )
        except Exception as e:
            logger.error(f"Background scan execution failed for {scan_id}: {e}", exc_info=True)
            try:
                repo = ScanRepository(db)
                repo.fail_scan(
                    scan_id=scan_id,
                    error_code="BACKGROUND_SCAN_FAILED",
                    error_message=str(e)[:500],
                )
            except Exception as dbe:
                logger.error(f"Failed to record background scan failure in DB: {dbe}")
        finally:
            db.close()

    async def execute_multimodal_scan(
        self,
        input_type: str,
        user_id: str,
        content_bytes: Optional[bytes] = None,
        text_content: Optional[str] = None,
        filename: Optional[str] = None,
        scan_id: Optional[str] = None,
        context: Optional[str] = None,
    ) -> MultimodalAnalysisReport:
        """
        Executes multimodal scan across screenshots, QR codes, PDFs, documents, or message text.
        Persists scan record, artifacts, evidence, findings, and risk assessment in PostgreSQL.
        """
        scan_id = scan_id or str(uuid.uuid4())
        start_time = time.time()

        raw_target = filename or (text_content[:200] if text_content else input_type)

        try:
            # 1. State: QUEUED
            self.repo.create_scan(
                scan_id=scan_id,
                user_id=user_id,
                input_type=input_type,
                raw_target=raw_target,
                policy_version=RiskEngine.POLICY_VERSION,
            )
            self.repo.record_audit_event("SCAN_QUEUED", scan_id, user_id, {"input_type": input_type, "target": raw_target})

            # 2. Persist artifact record if binary file was uploaded
            if content_bytes:
                file_hash = hashlib.sha256(content_bytes).hexdigest()
                self.repo.add_artifact(
                    scan_id=scan_id,
                    artifact_type=input_type,
                    storage_path=f"staged://{scan_id}/{filename or 'payload'}",
                    mime_type=f"application/{input_type}",
                    file_size_bytes=len(content_bytes),
                    file_hash=file_hash,
                )

            # 3. State: PROCESSING
            self.repo.update_scan_status(scan_id, "PROCESSING")

            # 4. Execute Multimodal Orchestrator
            try:
                modality_enum = InputType(input_type)
            except ValueError:
                modality_enum = InputType.DOCUMENT_TEXT

            report = await self.multimodal_orchestrator.analyze(
                input_type=modality_enum,
                content_bytes=content_bytes,
                text_content=text_content,
                filename=filename,
                analysis_id=scan_id,
                context=context,
            )

            # 5. Persist Evidence, Findings, and Risk Assessment
            try:
                self.repo.save_evidence_and_findings(
                    scan_id=scan_id,
                    evidence_list=report.evidence,
                    findings_list=report.findings,
                )
                self.repo.save_risk_assessment(
                    scan_id=scan_id,
                    risk_score=report.risk_score,
                    trust_score=report.trust_score,
                    risk_level=report.risk_level.value,
                    confidence=report.confidence,
                    coverage_ratio=report.coverage_ratio,
                    recommended_action=report.recommended_action.value,
                    summary=report.summary,
                    explanation=None,
                )
            except Exception as e:
                logger.error(f"Failed to persist multimodal entities for scan {scan_id}: {e}")

            # 6. Final State: COMPLETED or PARTIAL
            final_status = "COMPLETED" if report.status.value == "completed" else "PARTIAL"
            self.repo.update_scan_status(
                scan_id=scan_id,
                status=final_status,
                completed_at=datetime.now(timezone.utc),
            )
            self.repo.record_audit_event(
                f"SCAN_{final_status}",
                scan_id,
                user_id,
                {
                    "input_type": input_type,
                    "risk_score": report.risk_score,
                    "action": report.recommended_action.value,
                    "duration_ms": int((time.time() - start_time) * 1000),
                }
            )

            return report
        except Exception as exc:
            logger.error(f"Multimodal scan {scan_id} failed: {exc}", exc_info=True)
            self.repo.fail_scan(
                scan_id=scan_id,
                error_code="MULTIMODAL_EXECUTION_ERROR",
                error_message=str(exc)[:500],
            )
            raise

