"""
Sliding-Window Rate Limiting Middleware
Supports in-memory tracking (development/test) and atomic distributed Redis
sliding-window tracking (production/pilot/multi-worker).
Enforces per-client (User ID or IP) request thresholds with automatic sliding-window eviction.
"""
import time
import uuid
import asyncio
import logging
from typing import Dict, List, Optional, Tuple
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.config import settings

logger = logging.getLogger("thelix.rate_limiter")


class BaseRateLimitStore:
    """Abstract rate limiter storage interface."""

    async def check_and_record(
        self, client_id: str, limit: int, window_seconds: float
    ) -> Tuple[bool, Optional[int]]:
        """
        Evaluates current client usage against limit over window_seconds.
        If under limit, records the request and returns (True, None).
        If limit exceeded, returns (False, retry_after_seconds).
        """
        raise NotImplementedError


class InMemoryRateLimitStore(BaseRateLimitStore):
    """
    In-memory sliding-window rate limit store protected by an asyncio lock.
    Designed for local development and unit testing without external Redis dependencies.
    """

    def __init__(self):
        self._requests: Dict[str, List[float]] = {}
        self._lock = asyncio.Lock()
        self._last_cleanup = time.time()

    async def check_and_record(
        self, client_id: str, limit: int, window_seconds: float
    ) -> Tuple[bool, Optional[int]]:
        now = time.time()
        async with self._lock:
            # Clean up stale keys periodically (every 60s)
            if now - self._last_cleanup > 60.0:
                cutoff = now - window_seconds
                stale_keys = [
                    k for k, timestamps in self._requests.items()
                    if not timestamps or timestamps[-1] < cutoff
                ]
                for k in stale_keys:
                    self._requests.pop(k, None)
                self._last_cleanup = now

            timestamps = self._requests.setdefault(client_id, [])
            cutoff = now - window_seconds
            timestamps = [t for t in timestamps if t > cutoff]
            self._requests[client_id] = timestamps

            if len(timestamps) >= limit:
                oldest = timestamps[0]
                retry_after = max(1, int(oldest + window_seconds - now))
                return False, retry_after

            timestamps.append(now)
            return True, None


class RedisRateLimitStore(BaseRateLimitStore):
    """
    Distributed sliding-window rate limit store powered by Redis sorted sets (ZSET).
    Executes atomic eviction, cardinality checks, conditional admission, and bounded expiry
    in a single Redis-side operation via an atomic Lua script (EVALSHA / EVAL).
    """

    LUA_RATE_LIMIT_SCRIPT = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]

local cutoff = now - window
redis.call('ZREMRANGEBYSCORE', key, '-inf', cutoff)
local current_count = redis.call('ZCARD', key)

if current_count >= limit then
    local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
    local oldest_ts = now
    if oldest and #oldest >= 2 then
        oldest_ts = tonumber(oldest[2]) or now
    end
    local retry_after = math.max(1, math.ceil(oldest_ts + window - now))
    return {0, retry_after, current_count}
else
    redis.call('ZADD', key, now, member)
    redis.call('EXPIRE', key, math.ceil(window) + 2)
    return {1, 0, current_count + 1}
end
"""

    def __init__(self, redis_client=None, redis_url: Optional[str] = None):
        import hashlib
        self._redis = redis_client
        self._redis_url = redis_url or settings.REDIS_URL
        self._timeout = settings.RATE_LIMIT_TIMEOUT_SECONDS
        self._script_sha = hashlib.sha1(self.LUA_RATE_LIMIT_SCRIPT.encode("utf-8")).hexdigest()

    def _get_client(self):
        if self._redis is None:
            import redis.asyncio as aioredis
            self._redis = aioredis.from_url(
                self._redis_url,
                socket_connect_timeout=self._timeout,
                socket_timeout=self._timeout,
                decode_responses=True,
            )
        return self._redis

    async def check_and_record(
        self, client_id: str, limit: int, window_seconds: float
    ) -> Tuple[bool, Optional[int]]:
        if limit <= 0:
            return False, int(window_seconds) if window_seconds > 0 else 1
        if window_seconds <= 0:
            return True, None

        r = self._get_client()
        key = f"rate_limit:{client_id}"
        now = time.time()
        member = f"{now}:{uuid.uuid4().hex}"

        try:
            try:
                res = await asyncio.wait_for(
                    r.evalsha(
                        self._script_sha,
                        1,
                        key,
                        str(now),
                        str(window_seconds),
                        str(limit),
                        member,
                    ),
                    timeout=self._timeout,
                )
            except Exception as err:
                err_str = str(err)
                import redis.exceptions
                if isinstance(err, (redis.exceptions.NoScriptError, AttributeError)) or "NOSCRIPT" in err_str:
                    res = await asyncio.wait_for(
                        r.eval(
                            self.LUA_RATE_LIMIT_SCRIPT,
                            1,
                            key,
                            str(now),
                            str(window_seconds),
                            str(limit),
                            member,
                        ),
                        timeout=self._timeout,
                    )
                else:
                    raise

            allowed = bool(res[0] == 1)
            retry_after = int(res[1]) if not allowed else None
            return allowed, retry_after
        except Exception:
            raise


class RateLimitingMiddleware(BaseHTTPMiddleware):
    """
    Sliding-window rate limiter tracking requests per minute.
    Keyed by client IP or Bearer token subject.
    Supports in-memory and shared Redis storage backends.
    """

    EXCLUDED_PREFIXES = (
        "/health",
        "/docs",
        "/redoc",
        "/openapi.json",
    )

    def __init__(
        self,
        app,
        rate_limit_per_minute: Optional[int] = None,
        store: Optional[BaseRateLimitStore] = None,
    ):
        super().__init__(app)
        self._explicit_limit = rate_limit_per_minute
        self.window_seconds = 60.0
        if store is not None:
            self._store = store
        elif settings.RATE_LIMIT_STORE == "redis":
            self._store = RedisRateLimitStore()
        else:
            self._store = InMemoryRateLimitStore()

    def _is_trusted_proxy(self, peer_ip: str, trusted_proxies: set[str]) -> bool:
        """Checks if the direct peer IP is in trusted proxies (exact IP or CIDR network)."""
        if not trusted_proxies or not peer_ip:
            return False
        if "*" in trusted_proxies or peer_ip in trusted_proxies:
            return True
        try:
            import ipaddress
            peer_addr = ipaddress.ip_address(peer_ip)
            for item in trusted_proxies:
                if "/" in item:
                    try:
                        net = ipaddress.ip_network(item, strict=False)
                        if peer_addr in net:
                            return True
                    except ValueError:
                        continue
        except ValueError:
            return False
        return False

    def _extract_client_id(self, request: Request) -> str:
        """Derives stable client identifier from Auth header or remote IP."""
        auth = request.headers.get("Authorization", "")
        if auth.lower().startswith("bearer ") and len(auth) > 15:
            # Use deterministic sha256 of bearer token as client identifier
            import hashlib
            return f"user:{hashlib.sha256(auth.encode('utf-8')).hexdigest()[:16]}"

        # Remote IP derivation with proxy trust enforcement (anti-spoofing)
        direct_ip = request.client.host if request.client else "unknown_client"
        trusted_proxies = settings.parsed_trusted_proxies

        # Only trust X-Forwarded-For if request originates directly from a verified trusted proxy
        if self._is_trusted_proxy(direct_ip, trusted_proxies):
            forwarded = request.headers.get("X-Forwarded-For")
            if forwarded:
                import ipaddress
                hops = [ip.strip() for ip in forwarded.split(",") if ip.strip()]
                for hop in hops:
                    try:
                        ipaddress.ip_address(hop)
                        return f"ip:{hop}"
                    except ValueError:
                        # Malformed IP hop - skip and fail safe
                        continue

        # When request comes directly from untrusted client, ignore forwarded headers to prevent spoofing
        return f"ip:{direct_ip}"

    async def dispatch(self, request: Request, call_next) -> Response:
        # Skip rate limiting if disabled or path is excluded
        if not settings.RATE_LIMIT_ENABLED:
            return await call_next(request)

        path = request.url.path
        if any(path.startswith(prefix) for prefix in self.EXCLUDED_PREFIXES):
            return await call_next(request)

        effective_limit = self._explicit_limit if self._explicit_limit is not None else settings.RATE_LIMIT_PER_MINUTE
        client_id = self._extract_client_id(request)

        try:
            allowed, retry_after = await self._store.check_and_record(
                client_id=client_id,
                limit=effective_limit,
                window_seconds=self.window_seconds,
            )
        except Exception as e:
            if settings.ENVIRONMENT in ("production", "pilot") and settings.RATE_LIMIT_STORE == "redis":
                logger.error(f"Rate limiting shared store error in {settings.ENVIRONMENT}: {e}")
                return JSONResponse(
                    status_code=503,
                    content={
                        "detail": "Service temporarily unavailable: Rate limit verification failure",
                        "error_code": "RATE_LIMIT_STORE_UNAVAILABLE",
                    },
                )
            # In development/test mode with unconfigured redis, fail safe with log
            logger.warning(f"Rate limiting store error in dev mode: {e}")
            allowed, retry_after = True, None

        if not allowed:
            retry_after = retry_after or 1
            return JSONResponse(
                status_code=429,
                content={
                    "detail": f"Rate limit exceeded ({effective_limit} req/min). Please retry in {retry_after}s.",
                    "error_code": "RATE_LIMIT_EXCEEDED",
                    "retry_after_seconds": retry_after,
                },
                headers={"Retry-After": str(retry_after)},
            )

        return await call_next(request)

