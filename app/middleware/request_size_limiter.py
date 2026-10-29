"""
Streaming Request Body Size Limiter ASGI Middleware
Enforces strict streaming bounds on incoming HTTP request bodies before full memory buffering occurs.
Protects against:
- Missing Content-Length headers (e.g. chunked transfer encoding bombs)
- Misreported Content-Length headers (declared < 10MB but streaming > 10MB)
- Memory exhaustion denial-of-service attacks
"""
import asyncio
from typing import Optional
from starlette.responses import JSONResponse
from app.config import settings


class RequestBodyTooLargeException(Exception):
    """Raised when an incoming streaming request body exceeds configured limit."""
    pass


class ClientStallTimeoutException(Exception):
    """Raised when an incoming streaming request client stalls during body reception."""
    pass


class RequestSizeLimiterMiddleware:
    """
    Pure ASGI middleware that tracks cumulative incoming bytes across all chunks.
    Immediately terminates stream and returns HTTP 413 if cumulative bytes exceed max_size_bytes.
    Enforces a strict timeout between chunk receptions to mitigate slowloris upload attacks.
    """
    def __init__(
        self,
        app,
        max_size_bytes: Optional[int] = None,
        chunk_timeout_seconds: float = 30.0,
    ):
        self.app = app
        self.max_size_bytes = max_size_bytes or settings.MAX_UPLOAD_SIZE_BYTES
        self.chunk_timeout_seconds = chunk_timeout_seconds

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        limit = self.max_size_bytes
        limit_mb = limit // (1024 * 1024)

        # 1. Header pre-check (fast-reject if Content-Length declared > max)
        for name, value in scope.get("headers", []):
            if name.lower() == b"content-length":
                try:
                    if int(value) > limit:
                        response = JSONResponse(
                            status_code=413,
                            content={"detail": f"Request payload exceeds maximum limit of {limit_mb}MB"},
                            headers={
                                "X-Content-Type-Options": "nosniff",
                                "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none';",
                            }
                        )
                        await response(scope, receive, send)
                        return
                except ValueError:
                    pass

        # 2. Streaming receiver wrapper: count received bytes incrementally with stall detection
        bytes_received = 0

        async def limited_receive():
            nonlocal bytes_received
            try:
                message = await asyncio.wait_for(receive(), timeout=self.chunk_timeout_seconds)
            except asyncio.TimeoutError:
                raise ClientStallTimeoutException("Client upload timed out during stream reception")

            if message["type"] == "http.request":
                chunk = message.get("body", b"")
                bytes_received += len(chunk)
                if bytes_received > limit:
                    raise RequestBodyTooLargeException(
                        f"Request payload exceeds maximum limit of {limit_mb}MB"
                    )
            return message

        try:
            await self.app(scope, limited_receive, send)
        except RequestBodyTooLargeException as exc:
            response = JSONResponse(
                status_code=413,
                content={"detail": str(exc)},
                headers={
                    "X-Content-Type-Options": "nosniff",
                    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none';",
                }
            )
            await response(scope, receive, send)
        except ClientStallTimeoutException as exc:
            response = JSONResponse(
                status_code=408,
                content={"detail": "Request timed out during upload body transmission"},
                headers={
                    "X-Content-Type-Options": "nosniff",
                    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none';",
                }
            )
            await response(scope, receive, send)
