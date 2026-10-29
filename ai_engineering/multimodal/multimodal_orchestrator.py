"""
Unified Multimodal Threat Orchestrator
Coordinates multi-input ingestion (screenshots, QR codes, PDFs, documents, messages),
safe indicator extraction, deterministic scam analysis, URL reputation analysis,
and authoritative Risk Engine fusion.
"""
import uuid
import time
import asyncio
import logging
from typing import Optional, List, Dict, Any, Tuple

from ai_engineering.multimodal.contracts import (
    InputType,
    MultimodalStatus,
    MultimodalExtractionResult,
    MultimodalAnalysisReport,
)
from ai_engineering.ocr.ocr_pipeline import OCRPipeline
from ai_engineering.qr.qr_analyzer import QRAnalyzer
from ai_engineering.document_analysis.document_extractor import DocumentExtractor
from ai_engineering.text_analysis.scam_detector import ScamTextDetector

from risk_engine.engine import RiskEngine
from risk_engine.url_normalizer import URLNormalizer, NormalizedURL
from risk_engine.static_analyzer import StaticURLAnalyzer
from risk_engine.reputation_analyzer import ReputationAnalyzer, ReputationProvider
from risk_engine.evidence import Evidence, Finding, ActionVerdict, RiskLevel, Severity
from risk_engine.evidence_aggregator import EvidenceAggregator
from risk_engine.scoring import ScoringEngine
from risk_engine.coverage import CoverageTracker, CoverageAssessment
from risk_engine.confidence import ConfidenceCalculator
from risk_engine.policy import PolicyEngine
from risk_engine.report_builder import SecurityReport, ReportBuilder

logger = logging.getLogger("thelix.multimodal_orchestrator")


class MultimodalOrchestrator:
    """
    Coordinates extraction across modalities and fuses all findings into the shared Risk Engine.
    """
    ENGINE_VERSION = "1.0.0"

    def __init__(
        self,
        reputation_providers: Optional[List[ReputationProvider]] = None,
        enable_reputation: bool = True,
    ):
        self.ocr_pipeline = OCRPipeline()
        self.qr_analyzer = QRAnalyzer()
        self.document_extractor = DocumentExtractor()
        self.scam_detector = ScamTextDetector()
        self.risk_engine = RiskEngine(
            reputation_providers=reputation_providers,
            enable_reputation=enable_reputation,
        )
        self.reputation_analyzer = self.risk_engine.reputation_analyzer

    async def analyze(
        self,
        input_type: InputType,
        content_bytes: Optional[bytes] = None,
        text_content: Optional[str] = None,
        filename: Optional[str] = None,
        analysis_id: Optional[str] = None,
        context: Optional[str] = None,
    ) -> MultimodalAnalysisReport:
        """
        Executes complete multimodal analysis workflow and returns authoritative MultimodalAnalysisReport.
        """
        analysis_id = analysis_id or str(uuid.uuid4())
        start_time = time.time()

        all_evidence: List[Evidence] = []
        all_findings: List[Finding] = []
        limitations: List[str] = []
        detector_versions: Dict[str, str] = {
            "multimodal_orchestrator": self.ENGINE_VERSION,
            "risk_engine_policy": RiskEngine.POLICY_VERSION,
        }

        planned_checks = [f"extract_{input_type.value}"]
        completed_checks: List[str] = []
        failed_checks: List[str] = []
        skipped_checks: List[str] = []

        extracted_text: Optional[str] = None
        extracted_urls: List[str] = []

        # -------------------------------------------------------------
        # 1. Modality Extraction
        # -------------------------------------------------------------
        if input_type == InputType.SCREENSHOT:
            detector_versions["ocr_pipeline"] = OCRPipeline.ENGINE_VERSION
            if not content_bytes:
                return self._build_rejected_report(
                    analysis_id, input_type, "Missing image bytes for screenshot analysis"
                )
            extract_res = await asyncio.to_thread(self.ocr_pipeline.process_image, content_bytes, filename=filename)
            if not extract_res.success:
                failed_checks.append(planned_checks[0])
                limitations.extend(extract_res.limitations)
            else:
                completed_checks.append(planned_checks[0])
                extracted_text = extract_res.extracted_text
                extracted_urls = extract_res.extracted_urls
                limitations.extend(extract_res.limitations)

            # Dual-inspection: also extract and evaluate any QR codes present within the image
            try:
                qr_res, qr_ev, qr_fn = await asyncio.to_thread(self.qr_analyzer.analyze_image, content_bytes, filename=filename)
                if qr_res.extracted_urls or qr_fn:
                    extracted_urls.extend(qr_res.extracted_urls)
                    all_evidence.extend(qr_ev)
                    all_findings.extend(qr_fn)
            except Exception as qre:
                logger.debug(f"Optional QR check on screenshot skipped: {qre}")

        elif input_type == InputType.QR_CODE:
            detector_versions["qr_analyzer"] = QRAnalyzer.ENGINE_VERSION
            if not content_bytes:
                return self._build_rejected_report(
                    analysis_id, input_type, "Missing image bytes for QR code analysis"
                )
            extract_res, qr_ev, qr_fn = await asyncio.to_thread(self.qr_analyzer.analyze_image, content_bytes, filename=filename)
            all_evidence.extend(qr_ev)
            all_findings.extend(qr_fn)
            if not extract_res.success:
                failed_checks.append(planned_checks[0])
                limitations.extend(extract_res.limitations)
            else:
                completed_checks.append(planned_checks[0])
                extracted_text = extract_res.extracted_text
                extracted_urls = extract_res.extracted_urls
                limitations.extend(extract_res.limitations)

        elif input_type in (InputType.DOCUMENT_PDF, InputType.DOCUMENT_TEXT):
            detector_versions["document_extractor"] = DocumentExtractor.ENGINE_VERSION
            if not content_bytes:
                return self._build_rejected_report(
                    analysis_id, input_type, f"Missing document bytes for {input_type.value} analysis"
                )
            extract_res = await asyncio.to_thread(
                self.document_extractor.extract_from_bytes,
                content_bytes,
                filename=filename,
                force_type=input_type,
            )
            if not extract_res.success:
                failed_checks.append(planned_checks[0])
                limitations.extend(extract_res.limitations)
            else:
                completed_checks.append(planned_checks[0])
                extracted_text = extract_res.extracted_text
                extracted_urls = extract_res.extracted_urls
                limitations.extend(extract_res.limitations)

        elif input_type == InputType.MESSAGE_TEXT:
            detector_versions["scam_detector"] = ScamTextDetector.ENGINE_VERSION
            completed_checks.append(planned_checks[0])
            extracted_text = text_content or (content_bytes.decode("utf-8", errors="replace") if content_bytes else "")
            # Extract URLs from message text
            if extracted_text:
                extracted_urls = self.document_extractor._extract_urls(extracted_text)

        elif input_type == InputType.URL:
            # Direct URL input
            completed_checks.append(planned_checks[0])
            target_u = (text_content or "").strip()
            if target_u:
                extracted_urls = [target_u]
        else:
            return self._build_rejected_report(
                analysis_id, input_type, f"Unsupported input type: {input_type}"
            )

        # -------------------------------------------------------------
        # 2. Suspicious Message / Scam Text Analysis
        # -------------------------------------------------------------
        if extracted_text and extracted_text.strip():
            planned_checks.append("scam_text_analysis")
            detector_versions["scam_text_detector"] = ScamTextDetector.ENGINE_VERSION
            try:
                scam_ev, scam_fn = self.scam_detector.analyze_text(
                    extracted_text, associated_urls=extracted_urls
                )
                all_evidence.extend(scam_ev)
                all_findings.extend(scam_fn)
                completed_checks.append("scam_text_analysis")
            except Exception as e:
                logger.error(f"Scam text analysis failed: {e}")
                failed_checks.append("scam_text_analysis")

        # -------------------------------------------------------------
        # 3. Extracted URLs Analysis via Risk Engine & Threat Intel
        # -------------------------------------------------------------
        if extracted_urls:
            planned_checks.append("extracted_urls_analysis")
            url_checks_succeeded = True

            # Deduplicate extracted targets preserving order to avoid redundant lookups
            unique_urls = list(dict.fromkeys(extracted_urls))
            sem = asyncio.Semaphore(10)

            async def _analyze_extracted_target(u: str) -> Tuple[List[Evidence], List[Finding], bool]:
                async with sem:
                    u_evs: List[Evidence] = []
                    u_fns: List[Finding] = []
                    try:
                        norm: NormalizedURL = URLNormalizer.normalize(u)
                        st_ev, st_fn = StaticURLAnalyzer.analyze(norm)
                        u_evs.extend(st_ev)
                        u_fns.extend(st_fn)
                        if self.reputation_analyzer:
                            rep_ev, rep_fn, _ = await self.reputation_analyzer.analyze(norm)
                            u_evs.extend(rep_ev)
                            u_fns.extend(rep_fn)
                        return u_evs, u_fns, True
                    except Exception as e:
                        logger.warning(f"URL analysis failed for extracted target '{u}': {e}")
                        u_evs.append(Evidence(
                            indicator_type="malformed_extracted_url",
                            indicator_value_or_reference=u[:200],
                            source_engine="url_normalizer",
                            source_version="1.0.0",
                            observation={"error": str(e)},
                            reliability=0.90,
                            confidence=0.85,
                            correlation_group="deceptive_syntax",
                        ))
                        u_fns.append(Finding(
                            finding_code="FIND-URL-MALFORMED-SYNTAX",
                            title="Malformed / Prohibited URL in Extracted Content",
                            description=f"Extracted destination violates URL standards: {str(e)}",
                            severity=Severity.HIGH,
                            confidence=0.85,
                            source_engine="url_normalizer",
                            source_version="1.0.0",
                            correlation_group="deceptive_syntax",
                        ))
                        return u_evs, u_fns, False

            url_tasks = [_analyze_extracted_target(u) for u in unique_urls]
            url_results = await asyncio.gather(*url_tasks)
            for u_evs, u_fns, u_ok in url_results:
                all_evidence.extend(u_evs)
                all_findings.extend(u_fns)
                if not u_ok:
                    url_checks_succeeded = False

            if url_checks_succeeded:
                completed_checks.append("extracted_urls_analysis")
            else:
                failed_checks.append("extracted_urls_analysis")

        # -------------------------------------------------------------
        # 4. Multi-Detector Evidence Aggregation & Deduplication
        # -------------------------------------------------------------
        deduped_ev, consolidated_fn = EvidenceAggregator.aggregate(all_evidence, all_findings)

        # -------------------------------------------------------------
        # 5. Deterministic Risk Scoring
        # -------------------------------------------------------------
        risk_score, trust_score, risk_level, audit_meta = ScoringEngine.calculate_score(consolidated_fn)

        # -------------------------------------------------------------
        # 6. Coverage Assessment
        # -------------------------------------------------------------
        coverage = CoverageTracker.evaluate(
            planned=planned_checks,
            completed=completed_checks,
            failed=failed_checks,
            skipped=skipped_checks,
        )

        # -------------------------------------------------------------
        # 7. Confidence Calculation
        # -------------------------------------------------------------
        confidence = ConfidenceCalculator.calculate(
            evidence=deduped_ev,
            findings=consolidated_fn,
            coverage_ratio=coverage.coverage_ratio,
        )

        # -------------------------------------------------------------
        # 8. Policy Decision
        # -------------------------------------------------------------
        action, policy_reason, recommendations = PolicyEngine.decide(
            risk_score=risk_score,
            confidence=confidence,
            coverage=coverage,
            findings=consolidated_fn,
        )

        # -------------------------------------------------------------
        # 9. Format Summary, Text Preview, Principal Evidence & Verdict Rationale
        # -------------------------------------------------------------
        text_preview = None
        if extracted_text:
            text_preview = extracted_text[:300] + ("..." if len(extracted_text) > 300 else "")

        if action == ActionVerdict.BLOCK:
            summary = f"Dangerous content blocked: high-risk threat indicators identified (Trust Score: {trust_score}/100)."
        elif action == ActionVerdict.WARN:
            summary = f"Suspicious indicators detected in content (Trust Score: {trust_score}/100). Proceed with caution."
        elif action == ActionVerdict.INCONCLUSIVE:
            summary = f"Analysis inconclusive: {policy_reason}"
        else:
            summary = f"No security threats identified across {len(completed_checks)} completed checks (Trust Score: {trust_score}/100)."

        final_status = MultimodalStatus.COMPLETED if not failed_checks else MultimodalStatus.PARTIAL
        target_summary = f"{input_type.value.upper()} analysis"
        if filename:
            target_summary += f" ({filename})"
        elif extracted_urls:
            target_summary += f" referencing {len(extracted_urls)} link(s)"

        # Build principal evidence breakdown
        principal_evidence = []
        for f in consolidated_fn:
            principal_evidence.append({
                "finding_code": f.finding_code,
                "title": f.title,
                "severity": f.severity.value,
                "confidence": round(f.confidence, 4),
                "source_engine": f.source_engine,
                "evidence_count": len(f.evidence_references),
                "safe_excerpt": getattr(f, "safe_excerpt", None),
                "observed_versus_inferred": getattr(f, "observed_versus_inferred", "directly_observed"),
            })

        # Construct explainable verdict rationale
        rationale_parts = [
            f"Verdict: {action.value.upper()} (Risk Score: {risk_score}/100, Trust Score: {trust_score}/100).",
            f"Inspection Modality: {input_type.value.upper()} (offline static extraction; live network sandbox inspection disabled).",
            f"Execution Pipeline: {len(completed_checks)} check(s) completed ({', '.join(completed_checks)}), {len(failed_checks)} failed.",
        ]
        if consolidated_fn:
            top_f = consolidated_fn[0]
            rationale_parts.append(
                f"Primary Threat Indicator: {top_f.title} (Finding: {top_f.finding_code}, Severity: {top_f.severity.value.upper()}, Confidence: {top_f.confidence})."
            )
        else:
            rationale_parts.append("Primary Threat Indicator: None. Content passed all static lexical, structural, and indicator checks.")

        if limitations:
            rationale_parts.append(f"Recorded Limitations: {'; '.join(limitations[:3])}.")

        verdict_rationale = " ".join(rationale_parts)

        # Map to defined user-facing outcome vocabulary
        if final_status == MultimodalStatus.REJECTED:
            verdict_category = "UNSUPPORTED_INPUT"
            verdict_label = "Unsupported input: format cannot be reliably analyzed"
        elif action == ActionVerdict.INCONCLUSIVE:
            verdict_category = "INCONCLUSIVE"
            verdict_label = "Inconclusive / insufficient coverage: target could not be verified"
        elif action == ActionVerdict.BLOCK:
            is_malware = any(
                "malware" in f.title.lower() or "trojan" in f.title.lower() or
                ("malware" in f.description.lower() and f.source_engine in ("virustotal", "safebrowsing"))
                for f in consolidated_fn
            )
            if is_malware:
                verdict_category = "MALWARE_INDICATORS_DETECTED"
                verdict_label = "Malware indicators detected"
            else:
                verdict_category = "PHISHING_OR_SCAM"
                verdict_label = "Phishing / scam indicators detected"
        elif action == ActionVerdict.WARN:
            verdict_category = "SUSPICIOUS"
            verdict_label = "Suspicious: meaningful risk indicators require caution"
        else:
            verdict_category = "LIKELY_SAFE"
            verdict_label = "Likely safe / no significant threat detected"

        what_we_checked = [{"check": c, "status": "completed"} for c in completed_checks]
        what_we_could_not_check = [
            {"check": c, "status": "failed", "reason": "Check execution failed"}
            for c in failed_checks
        ] + [
            {"check": c, "status": "skipped", "reason": "Check was skipped or prerequisites unmet"}
            for c in skipped_checks
        ]
        if limitations:
            for lim in limitations:
                what_we_could_not_check.append({
                    "check": "capability_limitation",
                    "status": "limited",
                    "reason": lim,
                })

        return MultimodalAnalysisReport(
            analysis_id=analysis_id,
            input_type=input_type,
            status=final_status,
            target_summary=target_summary,
            extracted_text_preview=text_preview,
            extracted_urls=extracted_urls,
            findings=consolidated_fn,
            evidence=deduped_ev,
            risk_score=risk_score,
            trust_score=trust_score,
            risk_level=risk_level,
            confidence=confidence,
            coverage_ratio=coverage.coverage_ratio,
            recommended_action=action,
            summary=summary,
            recommendations=recommendations,
            limitations=limitations,
            detector_versions=detector_versions,
            inspection_type="offline_multimodal_extraction_and_threat_analysis",
            score_interpretation="The risk score (0-100) is an ordinal severity index, not a percentage probability of compromise.",
            principal_evidence=principal_evidence,
            verdict_rationale=verdict_rationale,
            verdict_category=verdict_category,
            verdict_label=verdict_label,
            why_this_result=summary,
            what_we_checked=what_we_checked,
            what_we_could_not_check=what_we_could_not_check,
            next_steps=recommendations,
        )

    def _build_rejected_report(self, analysis_id: str, input_type: InputType, message: str) -> MultimodalAnalysisReport:
        """Builds a fail-safe rejected report when mandatory inputs are missing or invalid."""
        finding = Finding(
            finding_code="FIND-INPUT-REJECTED",
            title="Invalid or Missing Content Input",
            description=message,
            severity=Severity.CRITICAL,
            confidence=1.0,
            source_engine="multimodal_orchestrator",
            source_version=self.ENGINE_VERSION,
        )
        return MultimodalAnalysisReport(
            analysis_id=analysis_id,
            input_type=input_type,
            status=MultimodalStatus.REJECTED,
            target_summary=f"{input_type.value.upper()} (Rejected)",
            extracted_text_preview=None,
            extracted_urls=[],
            findings=[finding],
            evidence=[],
            risk_score=100,
            trust_score=0,
            risk_level=RiskLevel.CRITICAL,
            confidence=1.0,
            coverage_ratio=0.0,
            recommended_action=ActionVerdict.BLOCK,
            summary=f"Input rejected: {message}",
            recommendations=["Provide a valid, non-empty file or text input."],
            limitations=["LIMITATION-INPUT-REJECTED"],
            detector_versions={"multimodal_orchestrator": self.ENGINE_VERSION},
        )
