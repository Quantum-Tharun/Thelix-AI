import os
import logging
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.config import settings
from app.api.v1 import analyze
from app.api.v1 import ai
from app.api.v1 import scans
from app.api.v1 import maintenance
from app.middleware.observability import ObservabilityMiddleware
from app.middleware.rate_limiter import RateLimitingMiddleware
from app.middleware.request_size_limiter import RequestSizeLimiterMiddleware
from app.database.session import Base, engine, get_db
from risk_engine.engine import RiskEngine
from app.ai.deepfake.service import DeepfakeDetectorService

logger = logging.getLogger("thelix.main")

# Ensure tables exist
Base.metadata.create_all(bind=engine)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Validate environment configuration in production/pilot modes if not in unit test suite
    if settings.ENVIRONMENT in ("production", "pilot") and "PYTEST_CURRENT_TEST" not in os.environ:
        settings.validate_for_environment()
    # Initialize database tables on startup
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="Thelix AI Backend",
    description="Enterprise-grade AI-powered cybersecurity and digital trust assistant.",
    version="1.0.0",
    lifespan=lifespan,
)

# Cross-Origin Resource Sharing (CORS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.parsed_allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate Limiting Protection (Sliding-window per IP/User)
app.add_middleware(RateLimitingMiddleware)

# Streaming Request Body Size Limiter (Missing/Chunked/Misreported Content-Length cap)
app.add_middleware(RequestSizeLimiterMiddleware)

# Observability & Security Headers Middleware
app.add_middleware(ObservabilityMiddleware)

# Mount primary Canonical Digital Trust Analysis operation under /v1/analyze
app.include_router(analyze.router, prefix="/v1/analyze", tags=["Digital Trust Assessment"])

# Mount client-facing Scan lifecycle routes under /v1/scans
app.include_router(scans.router, prefix="/v1/scans", tags=["Scans & Reports (Advanced / Lifecycle)"])

# Mount legacy/subsystem AI routes under /v1/ai for backward compatibility
app.include_router(ai.router, prefix="/v1/ai", tags=["Internal AI Subsystems"])

# Mount Operational Maintenance routes under /v1/maintenance
app.include_router(maintenance.router, prefix="/v1/maintenance", tags=["Operational Maintenance (Internal)"])


@app.get("/health", tags=["Health"])
@app.get("/health/live", tags=["Health"])
async def health_check():
    """Liveness probe: verifies process responsiveness."""
    return {
        "status": "ok",
        "service": "Thelix AI Backend",
        "version": "1.0.0",
        "environment": settings.ENVIRONMENT,
    }


@app.get("/health/ready", tags=["Health"])
@app.get("/readiness", tags=["Health"])
async def readiness_check(db: Session = Depends(get_db)):
    """
    Readiness probe: verifies database connectivity, persistence state,
    and RiskEngine component configuration.
    Does not leak secrets, credentials, or internal exception stack traces.
    """
    try:
        db.execute(text("SELECT 1"))
    except Exception as e:
        logger.error(f"Readiness probe database connection failure: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service unavailable: Database unreachable",
        )

    import shutil
    ocr_available = bool(shutil.which("tesseract"))
    if settings.OCR_REQUIRED and not ocr_available:
        logger.warning("Readiness probe: OCR is required by configuration but tesseract binary is not on host PATH")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service unavailable: OCR binary (tesseract) required but unavailable",
        )

    if settings.RATE_LIMIT_STORE == "redis":
        try:
            import redis
            r = redis.from_url(settings.REDIS_URL, socket_connect_timeout=settings.RATE_LIMIT_TIMEOUT_SECONDS)
            r.ping()
        except Exception as e:
            logger.error(f"Readiness probe Redis rate limiter connection failure: {e}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Service unavailable: Distributed rate limit store (Redis) unreachable",
            )

    # Live-probe Ollama availability (non-blocking, 1.5s timeout)
    ollama_status = "unconfigured"
    if getattr(settings, "OLLAMA_BASE_URL", None):
        try:
            import urllib.request as _ur
            import urllib.error as _ue
            _req = _ur.Request(f"{settings.OLLAMA_BASE_URL}/api/tags", method="GET")
            with _ur.urlopen(_req, timeout=1.5) as _resp:
                ollama_status = "available" if _resp.status == 200 else "unreachable"
        except (_ue.URLError, OSError, Exception):
            ollama_status = "unreachable"

    provider_status = {
        "gemini": bool(settings.GEMINI_API_KEY) if settings.LLM_PROVIDER == "gemini" else "mock",
        "ollama_gemma": ollama_status,
        "virustotal": bool(settings.VIRUSTOTAL_API_KEY),
        "safebrowsing": bool(settings.SAFE_BROWSING_API_KEY),
    }

    return {
        "status": "ready",
        "service": "Thelix AI Backend",
        "version": "1.0.0",
        "environment": settings.ENVIRONMENT,
        "database": "connected",
        "policy_version": RiskEngine.POLICY_VERSION,
        "engine_versions": {
            "policy": RiskEngine.POLICY_VERSION,
            "static_url_analyzer": "1.0.0",
            "url_normalizer": "1.0.0",
            "qr_decoder": "1.0.0",
            "deepfake_detector": "1.0.0-prototype",
        },
        "sandbox_enabled": settings.SAFE_LOCAL_SANDBOX_ENABLED,
        "rate_limiting_enabled": settings.RATE_LIMIT_ENABLED,
        "rate_limit_store": settings.RATE_LIMIT_STORE,
        "ocr_available": ocr_available,
        "qr_available": True,
        "deepfake_status": DeepfakeDetectorService.get_model_status(),
        "pilot_mode_enabled": settings.PILOT_MODE_ENABLED,
        "providers_configured": provider_status,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
