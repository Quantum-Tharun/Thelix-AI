"""
Thelix AI — Performance Profiling and Benchmark Harness (Phase 21)
Reproducible performance benchmark evaluator measuring end-to-end latency,
p50/p95/p99 percentiles, per-stage breakdowns, database query counts, memory usage,
and throughput across all scan modalities with mocked providers.
"""
import os
import sys
import time
import io
import json
import uuid
import math
import asyncio
import platform
import statistics
import logging
from typing import Dict, List, Any, Optional, Tuple, Callable
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

import psutil
from PIL import Image
import qrcode
import pypdf
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, Session

# Add repository root to path
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from app.models.entities import Base
from app.repositories.scan_repository import ScanRepository
from app.services.orchestrator_service import OrchestratorService
from app.config import settings
from risk_engine.engine import RiskEngine
from risk_engine.reputation_analyzer import ReputationProvider, ReputationResult, ReputationStatus
from risk_engine.url_normalizer import URLNormalizer
from risk_engine.static_analyzer import StaticURLAnalyzer
from risk_engine.evidence_aggregator import EvidenceAggregator
from risk_engine.scoring import ScoringEngine
from risk_engine.coverage import CoverageTracker
from risk_engine.confidence import ConfidenceCalculator
from risk_engine.policy import PolicyEngine
from llm.provider import MockLLMProvider
from ai_engineering.multimodal.contracts import InputType
from ai_engineering.multimodal.multimodal_orchestrator import MultimodalOrchestrator
from ai_engineering.ocr.ocr_pipeline import OCRPipeline
from ai_engineering.qr.qr_analyzer import QRAnalyzer
from ai_engineering.document_analysis.document_extractor import DocumentExtractor
from ai_engineering.text_analysis.scam_detector import ScamTextDetector

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger("thelix.benchmark")


# -----------------------------------------------------------------------------
# Database Profiling Hook (SQLAlchemy Query Counter & Timer)
# -----------------------------------------------------------------------------
class DBQueryTracker:
    """Intercepts SQLAlchemy cursor execution to record exact query counts and execution durations."""
    def __init__(self, engine):
        self.engine = engine
        self.query_count = 0
        self.total_query_duration_ms = 0.0
        self.queries: List[Dict[str, Any]] = []
        self._active = False

        event.listen(self.engine, "before_cursor_execute", self._before_execute)
        event.listen(self.engine, "after_cursor_execute", self._after_execute)

    def start(self):
        self.reset()
        self._active = True

    def stop(self):
        self._active = False

    def reset(self):
        self.query_count = 0
        self.total_query_duration_ms = 0.0
        self.queries.clear()

    def _before_execute(self, conn, cursor, statement, parameters, context, executemany):
        if self._active:
            context._query_start_time = time.perf_counter()

    def _after_execute(self, conn, cursor, statement, parameters, context, executemany):
        if self._active and hasattr(context, "_query_start_time"):
            duration = (time.perf_counter() - context._query_start_time) * 1000.0
            self.query_count += 1
            self.total_query_duration_ms += duration
            self.queries.append({
                "statement": statement[:120].strip().replace("\n", " "),
                "duration_ms": round(duration, 3),
            })


# -----------------------------------------------------------------------------
# Mock Reputation Provider with Configurable Latency
# -----------------------------------------------------------------------------
class BenchmarkMockReputationProvider(ReputationProvider):
    """
    Simulates Google Safe Browsing / VirusTotal with deterministic responses and
    controlled latency (either instant or simulated network RTT) to measure concurrency effects.
    """
    def __init__(self, name: str, version: str = "1.0.0", simulated_latency_ms: float = 0.0):
        super().__init__(cache=None)
        self.name = name
        self.version = version
        self.simulated_latency_ms = simulated_latency_ms
        self.call_count = 0

    async def _execute_lookup(self, sanitized_url: str) -> ReputationResult:
        self.call_count += 1
        if self.simulated_latency_ms > 0:
            await asyncio.sleep(self.simulated_latency_ms / 1000.0)

        # Deterministic detection rule for benchmarking
        is_malicious = any(kw in sanitized_url.lower() for kw in ["phish", "malware", "evil", "steal"])
        is_suspicious = any(kw in sanitized_url.lower() for kw in ["suspicious", "verify-account", "update-bank"])

        if is_malicious:
            return ReputationResult(
                provider_name=self.name,
                provider_version=self.version,
                status=ReputationStatus.CONFIRMED_MALICIOUS,
                threat_types=["SOCIAL_ENGINEERING", "MALWARE"],
                positives_count=12,
                total_engines=70,
                latency_ms=int(self.simulated_latency_ms),
            )
        elif is_suspicious:
            return ReputationResult(
                provider_name=self.name,
                provider_version=self.version,
                status=ReputationStatus.SUSPICIOUS,
                threat_types=["UNWANTED_SOFTWARE"],
                positives_count=3,
                total_engines=70,
                latency_ms=int(self.simulated_latency_ms),
            )
        else:
            return ReputationResult(
                provider_name=self.name,
                provider_version=self.version,
                status=ReputationStatus.NO_MATCH,
                threat_types=[],
                positives_count=0,
                total_engines=70,
                latency_ms=int(self.simulated_latency_ms),
            )


# -----------------------------------------------------------------------------
# Synthetic Workload Generators
# -----------------------------------------------------------------------------
def generate_synthetic_screenshot(text: str = "Please verify your account at https://phish-secure-portal.com/login", width: int = 400, height: int = 200) -> bytes:
    img = Image.new("RGB", (width, height), color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def generate_synthetic_qr(payload: str = "https://phish-secure-portal.com/qr-verify") -> bytes:
    qr = qrcode.QRCode(box_size=8, border=4)
    qr.add_data(payload)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    qr_img.save(buf, format="PNG")
    return buf.getvalue()


def generate_synthetic_pdf(text: str = "Urgent billing invoice: click https://invoice-billing-portal.top/view.pdf") -> bytes:
    writer = pypdf.PdfWriter()
    writer.add_blank_page(width=300, height=300)
    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


SYNTHETIC_MESSAGES = [
    "URGENT: Your bank account has been locked. Verify immediately at https://bank-secure-alert.top/verify to prevent suspension.",
    "IRS Final Notice: Warrant issued for tax evasion. Send $500 in Bitcoin to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa immediately.",
    "Hello team, the weekly engineering architecture sync has been moved to Thursday 2pm on Google Meet.",
    "Quick alert: Click here to claim your $1,000 Amazon gift card voucher code at http://reward-claim-center.xyz",
]

SYNTHETIC_URLS = [
    "https://example.com/clean/path",
    "http://192.168.1.100/admin/login",
    "https://login.microsoft.com.account-update-portal.info/oauth",
    "https://xn--pple-43d.com/signin",
    "https://legitimate-corporate-portal.com/docs/annual-report.pdf",
]


# -----------------------------------------------------------------------------
# Metrics Calculations
# -----------------------------------------------------------------------------
def calculate_distribution(latencies_ms: List[float]) -> Dict[str, float]:
    if not latencies_ms:
        return {"min": 0.0, "max": 0.0, "mean": 0.0, "p50": 0.0, "p95": 0.0, "p99": 0.0, "stdev": 0.0}
    sorted_l = sorted(latencies_ms)
    n = len(sorted_l)

    def p(pct: float) -> float:
        if n == 1:
            return sorted_l[0]
        k = (n - 1) * (pct / 100.0)
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return sorted_l[int(k)]
        return sorted_l[f] * (c - k) + sorted_l[c] * (k - f)

    return {
        "min": round(sorted_l[0], 2),
        "max": round(sorted_l[-1], 2),
        "mean": round(statistics.mean(sorted_l), 2),
        "p50": round(p(50), 2),
        "p95": round(p(95), 2),
        "p99": round(p(99), 2),
        "stdev": round(statistics.stdev(sorted_l) if n > 1 else 0.0, 2),
    }


# -----------------------------------------------------------------------------
# Benchmark Runner Implementation
# -----------------------------------------------------------------------------
class BenchmarkHarness:
    """
    Executes reproducible benchmark suites measuring:
    1. Pure algorithmic / CPU stage latency (normalization, static analysis, regex scam text, aggregation)
    2. Modality extraction latency (OCR image decode, QR decode, PDF parse)
    3. End-to-end URL scan lifecycle latency, DB queries, and stage breakdown
    4. End-to-end Multimodal scan lifecycle latency, DB queries, and stage breakdown
    5. Concurrent throughput and latency scaling (C=1, C=5, C=10)
    """

    def __init__(self, db_engine=None):
        if db_engine is None:
            self.engine = create_engine("sqlite:///:memory:", echo=False)
            Base.metadata.create_all(bind=self.engine)
        else:
            self.engine = db_engine

        self.SessionLocal = sessionmaker(bind=self.engine)
        self.db_tracker = DBQueryTracker(self.engine)

    def _get_system_info(self) -> Dict[str, Any]:
        process = psutil.Process()
        return {
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "cpu_count_logical": psutil.cpu_count(logical=True),
            "cpu_count_physical": psutil.cpu_count(logical=False),
            "ram_total_gb": round(psutil.virtual_memory().total / (1024 ** 3), 2),
            "initial_memory_rss_mb": round(process.memory_info().rss / (1024 ** 2), 2),
            "database_driver": self.engine.dialect.name,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }

    # -------------------------------------------------------------------------
    # 1. Micro-benchmarks for individual pipeline stages
    # -------------------------------------------------------------------------
    def benchmark_static_stages(self, iterations: int = 100) -> Dict[str, Any]:
        """Profiles pure CPU algorithmic stages: normalization, static analyzer, scam detector, aggregator."""
        norm_times = []
        static_times = []
        scam_times = []
        scoring_times = []

        scam_detector = ScamTextDetector()

        for i in range(iterations):
            url = SYNTHETIC_URLS[i % len(SYNTHETIC_URLS)]
            msg = SYNTHETIC_MESSAGES[i % len(SYNTHETIC_MESSAGES)]

            # A. Normalization
            t0 = time.perf_counter()
            norm = URLNormalizer.normalize(url)
            norm_times.append((time.perf_counter() - t0) * 1000.0)

            # B. Static URL Analyzer
            t0 = time.perf_counter()
            ev, fn = StaticURLAnalyzer.analyze(norm)
            static_times.append((time.perf_counter() - t0) * 1000.0)

            # C. Scam Text Detector
            t0 = time.perf_counter()
            s_ev, s_fn = scam_detector.analyze_text(msg)
            scam_times.append((time.perf_counter() - t0) * 1000.0)

            # D. Scoring & Aggregation
            combined_ev = ev + s_ev
            combined_fn = fn + s_fn
            t0 = time.perf_counter()
            dedup_ev, cons_fn = EvidenceAggregator.aggregate(combined_ev, combined_fn)
            r_score, t_score, r_level, _ = ScoringEngine.calculate_score(cons_fn)
            scoring_times.append((time.perf_counter() - t0) * 1000.0)

        return {
            "iterations": iterations,
            "url_normalization": calculate_distribution(norm_times),
            "static_url_analyzer": calculate_distribution(static_times),
            "scam_text_detector": calculate_distribution(scam_times),
            "aggregation_and_scoring": calculate_distribution(scoring_times),
        }

    # -------------------------------------------------------------------------
    # 2. Modality Extraction Benchmarks (OCR, QR, PDF)
    # -------------------------------------------------------------------------
    def benchmark_extraction_stages(self, iterations: int = 30) -> Dict[str, Any]:
        """Profiles modality parsers: Image decode/preprocessing, QR detection, PDF extraction."""
        ocr_pipeline = OCRPipeline()
        qr_analyzer = QRAnalyzer()
        doc_extractor = DocumentExtractor()

        screenshot_bytes = generate_synthetic_screenshot()
        qr_bytes = generate_synthetic_qr()
        pdf_bytes = generate_synthetic_pdf()

        ocr_times = []
        qr_times = []
        pdf_times = []

        for _ in range(iterations):
            # OCR / Screenshot
            t0 = time.perf_counter()
            ocr_res = ocr_pipeline.process_image(screenshot_bytes, filename="screen.png")
            ocr_times.append((time.perf_counter() - t0) * 1000.0)

            # QR Code
            t0 = time.perf_counter()
            qr_res, _, _ = qr_analyzer.analyze_image(qr_bytes, filename="qr.png")
            qr_times.append((time.perf_counter() - t0) * 1000.0)

            # PDF Document
            t0 = time.perf_counter()
            pdf_res = doc_extractor.extract_from_bytes(pdf_bytes, filename="doc.pdf", force_type=InputType.DOCUMENT_PDF)
            pdf_times.append((time.perf_counter() - t0) * 1000.0)

        return {
            "iterations": iterations,
            "screenshot_ocr_extraction": calculate_distribution(ocr_times),
            "qr_code_extraction": calculate_distribution(qr_times),
            "pdf_document_extraction": calculate_distribution(pdf_times),
        }

    # -------------------------------------------------------------------------
    # 3. End-to-End URL Scan Lifecycle Benchmark
    # -------------------------------------------------------------------------
    async def benchmark_url_scan_lifecycle(
        self,
        iterations: int = 50,
        simulated_provider_latency_ms: float = 0.0,
    ) -> Dict[str, Any]:
        """
        Profiles the entire end-to-end URL scan lifecycle through OrchestratorService:
        Database inserts, Normalization, Static Analysis, Reputation Checks,
        Aggregation, Scoring, Confidence, Policy, Explanation, DB persistence, and Audit Logging.
        """
        e2e_latencies = []
        db_query_counts = []
        db_durations_ms = []

        db = self.SessionLocal()
        mock_gsb = BenchmarkMockReputationProvider("google_safe_browsing", "v4", simulated_latency_ms=simulated_provider_latency_ms)
        mock_vt = BenchmarkMockReputationProvider("virustotal", "v3", simulated_latency_ms=simulated_provider_latency_ms)

        orchestrator = OrchestratorService(db=db, llm_provider=MockLLMProvider())
        # Inject benchmark providers into risk engine
        orchestrator.risk_engine.reputation_analyzer.providers = [mock_gsb, mock_vt]

        for i in range(iterations):
            url = SYNTHETIC_URLS[i % len(SYNTHETIC_URLS)]
            scan_id = str(uuid.uuid4())
            user_id = f"bench-user-{i % 5}"

            self.db_tracker.start()
            t0 = time.perf_counter()

            report = await orchestrator.execute_url_scan(
                target_url=url,
                user_id=user_id,
                scan_id=scan_id,
                enable_sandbox=False,
            )

            dur_ms = (time.perf_counter() - t0) * 1000.0
            self.db_tracker.stop()

            e2e_latencies.append(dur_ms)
            db_query_counts.append(self.db_tracker.query_count)
            db_durations_ms.append(self.db_tracker.total_query_duration_ms)

        db.close()

        return {
            "iterations": iterations,
            "simulated_provider_latency_ms": simulated_provider_latency_ms,
            "external_calls_per_scan": 2,
            "e2e_latency_ms": calculate_distribution(e2e_latencies),
            "db_queries_per_scan": {
                "mean": round(statistics.mean(db_query_counts), 1),
                "min": min(db_query_counts),
                "max": max(db_query_counts),
            },
            "db_duration_ms": calculate_distribution(db_durations_ms),
            "sample_query_breakdown": self.db_tracker.queries[:8],
        }

    # -------------------------------------------------------------------------
    # 4. End-to-End Multimodal Scan Lifecycle Benchmark
    # -------------------------------------------------------------------------
    async def benchmark_multimodal_lifecycle(self, iterations_per_type: int = 15) -> Dict[str, Any]:
        """Profiles end-to-end multimodal scan execution across screenshot, QR, PDF, message text."""
        db = self.SessionLocal()
        orchestrator = OrchestratorService(db=db, llm_provider=MockLLMProvider())

        results = {}
        modalities = [
            ("message", None, SYNTHETIC_MESSAGES[0], "message.txt"),
            ("screenshot", generate_synthetic_screenshot(), None, "screenshot.png"),
            ("qr", generate_synthetic_qr(), None, "code.png"),
            ("pdf", generate_synthetic_pdf(), None, "document.pdf"),
        ]

        for input_type, raw_bytes, text_content, filename in modalities:
            latencies = []
            db_queries = []

            for i in range(iterations_per_type):
                scan_id = str(uuid.uuid4())
                user_id = f"bench-user-{i % 5}"

                self.db_tracker.start()
                t0 = time.perf_counter()

                report = await orchestrator.execute_multimodal_scan(
                    input_type=input_type,
                    user_id=user_id,
                    content_bytes=raw_bytes,
                    text_content=text_content,
                    filename=filename,
                    scan_id=scan_id,
                )

                dur_ms = (time.perf_counter() - t0) * 1000.0
                self.db_tracker.stop()

                latencies.append(dur_ms)
                db_queries.append(self.db_tracker.query_count)

            results[input_type] = {
                "iterations": iterations_per_type,
                "latency_ms": calculate_distribution(latencies),
                "db_queries_mean": round(statistics.mean(db_queries), 1),
            }

        db.close()
        return results

    # -------------------------------------------------------------------------
    # 5. Concurrency & Throughput Benchmark
    # -------------------------------------------------------------------------
    async def benchmark_concurrency(
        self,
        total_requests: int = 50,
        concurrency_levels: List[int] = [1, 5, 10],
        simulated_provider_latency_ms: float = 20.0,
    ) -> Dict[str, Any]:
        """
        Evaluates throughput (requests/sec) and latency percentiles under concurrent client load.
        """
        concurrency_results = {}

        for concurrency in concurrency_levels:
            db = self.SessionLocal()
            mock_gsb = BenchmarkMockReputationProvider("google_safe_browsing", "v4", simulated_latency_ms=simulated_provider_latency_ms)
            mock_vt = BenchmarkMockReputationProvider("virustotal", "v3", simulated_latency_ms=simulated_provider_latency_ms)

            orchestrator = OrchestratorService(db=db, llm_provider=MockLLMProvider())
            orchestrator.risk_engine.reputation_analyzer.providers = [mock_gsb, mock_vt]

            semaphore = asyncio.Semaphore(concurrency)
            latencies = []
            failures = 0

            async def worker(idx: int):
                nonlocal failures
                url = SYNTHETIC_URLS[idx % len(SYNTHETIC_URLS)]
                scan_id = str(uuid.uuid4())
                user_id = f"concurrent-user-{idx % concurrency}"

                async with semaphore:
                    t0 = time.perf_counter()
                    try:
                        report = await orchestrator.execute_url_scan(
                            target_url=url,
                            user_id=user_id,
                            scan_id=scan_id,
                            enable_sandbox=False,
                        )
                        latencies.append((time.perf_counter() - t0) * 1000.0)
                    except Exception as e:
                        failures += 1

            wall_t0 = time.perf_counter()
            tasks = [worker(i) for i in range(total_requests)]
            await asyncio.gather(*tasks)
            wall_time_sec = time.perf_counter() - wall_t0

            throughput_rps = round(len(latencies) / wall_time_sec, 2) if wall_time_sec > 0 else 0.0

            concurrency_results[f"concurrency_{concurrency}"] = {
                "concurrency": concurrency,
                "total_requests": total_requests,
                "successful_requests": len(latencies),
                "failures": failures,
                "wall_time_seconds": round(wall_time_sec, 3),
                "throughput_rps": throughput_rps,
                "latencies_ms": calculate_distribution(latencies),
            }
            db.close()

        return concurrency_results

    # -------------------------------------------------------------------------
    # Master Benchmark Suite Runner
    # -------------------------------------------------------------------------
    async def run_full_suite(self, output_path: Optional[str] = None) -> Dict[str, Any]:
        """Runs the complete performance benchmark suite and records all metrics."""
        process = psutil.Process()
        mem_before_mb = round(process.memory_info().rss / (1024 ** 2), 2)

        start_time = time.time()
        sys_info = self._get_system_info()

        logger.info("Running stage 1: Static and Algorithmic benchmarks...")
        static_metrics = self.benchmark_static_stages(iterations=100)

        logger.info("Running stage 2: Modality extraction benchmarks...")
        extraction_metrics = self.benchmark_extraction_stages(iterations=30)

        logger.info("Running stage 3: URL scan lifecycle (instant provider mock)...")
        url_instant_metrics = await self.benchmark_url_scan_lifecycle(
            iterations=50, simulated_provider_latency_ms=0.0
        )

        logger.info("Running stage 4: URL scan lifecycle (with 25ms simulated provider RTT)...")
        url_network_metrics = await self.benchmark_url_scan_lifecycle(
            iterations=50, simulated_provider_latency_ms=25.0
        )

        logger.info("Running stage 5: Multimodal lifecycle benchmarks...")
        multimodal_metrics = await self.benchmark_multimodal_lifecycle(iterations_per_type=15)

        logger.info("Running stage 6: Concurrency and throughput scaling...")
        concurrency_metrics = await self.benchmark_concurrency(
            total_requests=40, concurrency_levels=[1, 5, 10], simulated_provider_latency_ms=20.0
        )

        mem_after_mb = round(process.memory_info().rss / (1024 ** 2), 2)
        total_duration_sec = round(time.time() - start_time, 2)

        report = {
            "metadata": sys_info,
            "benchmark_execution": {
                "total_duration_seconds": total_duration_sec,
                "memory_start_rss_mb": mem_before_mb,
                "memory_end_rss_mb": mem_after_mb,
                "memory_delta_mb": round(mem_after_mb - mem_before_mb, 2),
            },
            "microbenchmarks": {
                "algorithmic_stages": static_metrics,
                "extraction_stages": extraction_metrics,
            },
            "e2e_scans": {
                "url_scan_instant_providers": url_instant_metrics,
                "url_scan_simulated_network_providers": url_network_metrics,
                "multimodal_scans": multimodal_metrics,
            },
            "concurrency_throughput": concurrency_metrics,
        }

        if output_path:
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
            logger.info(f"Benchmark results saved to {output_path}")

        return report


if __name__ == "__main__":
    async def main():
        harness = BenchmarkHarness()
        default_file = os.path.join(REPO_ROOT, "docs", "phase_reports", "benchmark_optimized.json")
        out_file = sys.argv[1] if len(sys.argv) > 1 else default_file
        res = await harness.run_full_suite(output_path=out_file)
        print("\n" + "=" * 70)
        print("THELIX AI — BENCHMARK BASELINE EXECUTION COMPLETE")
        print("=" * 70)
        print(f"Platform: {res['metadata']['platform']} (Python {res['metadata']['python_version']})")
        print(f"CPUs: {res['metadata']['cpu_count_logical']} | RAM: {res['metadata']['ram_total_gb']} GB")
        print(f"Total benchmark run duration: {res['benchmark_execution']['total_duration_seconds']}s")
        print("-" * 70)
        print("URL Scan (Instant Providers):")
        u_inst = res['e2e_scans']['url_scan_instant_providers']['e2e_latency_ms']
        print(f"  p50: {u_inst['p50']}ms | p95: {u_inst['p95']}ms | p99: {u_inst['p99']}ms | mean: {u_inst['mean']}ms")
        print(f"  DB Queries/scan: {res['e2e_scans']['url_scan_instant_providers']['db_queries_per_scan']['mean']}")
        print(f"  DB Total Duration/scan (mean): {res['e2e_scans']['url_scan_instant_providers']['db_duration_ms']['mean']}ms")
        print("-" * 70)
        print("URL Scan (Simulated Network Providers 25ms RTT):")
        u_net = res['e2e_scans']['url_scan_simulated_network_providers']['e2e_latency_ms']
        print(f"  p50: {u_net['p50']}ms | p95: {u_net['p95']}ms | p99: {u_net['p99']}ms | mean: {u_net['mean']}ms")
        print("-" * 70)
        print("Throughput & Concurrency Scaling (Simulated Network 20ms):")
        for c_key, c_val in res['concurrency_throughput'].items():
            print(f"  {c_key.upper()}: Throughput = {c_val['throughput_rps']} req/s | p50 = {c_val['latencies_ms']['p50']}ms | p95 = {c_val['latencies_ms']['p95']}ms")
        print("=" * 70)

    asyncio.run(main())
