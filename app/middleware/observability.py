import time
import uuid
import logging
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("thelix.observability")


import re
from app.config import settings

# Sensitive query parameter masking pattern
SENSITIVE_PARAM_PATTERN = re.compile(r"(token|secret|key|password|auth|api_key)=([^&]+)", re.I)


class ObservabilityMiddleware(BaseHTTPMiddleware):
    """
    Middleware to log request latency, errors, propagate X-Request-ID
    correlation headers, and enforce standard security response headers.
    """
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        request.state.request_id = request_id

        # Mask sensitive query params in path for audit logs
        # Reject oversized requests before buffering/processing (10MB limit)
        content_length_header = request.headers.get("content-length")
        if content_length_header:
            try:
                if int(content_length_header) > 10 * 1024 * 1024:
                    from starlette.responses import JSONResponse
                    return JSONResponse(
                        status_code=413,
                        content={"detail": "Request payload exceeds maximum limit of 10MB"},
                        headers={
                            "X-Request-ID": request_id,
                            "X-Content-Type-Options": "nosniff",
                        },
                    )
            except ValueError:
                pass

        try:
            response = await call_next(request)
            process_time = time.time() - start_time
            response.headers["X-Request-ID"] = request_id
            response.headers["X-Process-Time"] = f"{process_time:.4f}"

            # Standard security response headers
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["X-XSS-Protection"] = "1; mode=block"
            response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
            if settings.ENVIRONMENT in ("production", "pilot"):
                response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
                response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none';"

            logger.info(
                f"[{request_id}] {request.method} {request.url.path} | "
                f"Status: {response.status_code} | Latency: {process_time:.4f}s"
            )
            return response
        except Exception as e:
            process_time = time.time() - start_time
            logger.error(
                f"[{request_id}] {request.method} {request.url.path} | "
                f"Exception: {type(e).__name__} | Latency: {process_time:.4f}s",
                exc_info=True,
            )
            raise

