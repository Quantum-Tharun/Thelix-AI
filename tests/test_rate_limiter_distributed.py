"""
Phase 3 & 4 Verification Tests: Distributed Rate Limiting & Readiness Probes
Verifies:
- RedisRateLimitStore atomic pipeline sliding-window operations
- Cross-worker rate limit sharing with shared state
- Separate client identity buckets and TTL expiration
- Configuration validation (production rejects in-memory rate limiting; redis requires REDIS_URL)
- Readiness probe reporting rate_limit_store, ocr_available, and handling store outages
"""
import time
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from starlette.requests import Request
from starlette.responses import Response, JSONResponse

from app.config import Settings, ConfigurationError, settings
from app.middleware.rate_limiter import (
    BaseRateLimitStore,
    InMemoryRateLimitStore,
    RedisRateLimitStore,
    RateLimitingMiddleware,
)


class MockAsyncRedisPipeline:
    """Simulates Redis transaction pipeline with atomic sorted set operations."""

    def __init__(self, storage: dict):
        self._storage = storage
        self._commands = []

    def zremrangebyscore(self, key, min_score, max_score):
        self._commands.append(("zremrangebyscore", key, min_score, max_score))
        return self

    def zcard(self, key):
        self._commands.append(("zcard", key))
        return self

    def zrange(self, key, start, stop, withscores=False):
        self._commands.append(("zrange", key, start, stop, withscores))
        return self

    def zadd(self, key, mapping):
        self._commands.append(("zadd", key, mapping))
        return self

    def expire(self, key, seconds):
        self._commands.append(("expire", key, seconds))
        return self

    async def execute(self):
        results = []
        for cmd in self._commands:
            op = cmd[0]
            if op == "zremrangebyscore":
                _, key, min_s, max_s = cmd
                entries = self._storage.get(key, [])
                kept = [e for e in entries if not (min_s <= e[1] <= max_s)]
                removed = len(entries) - len(kept)
                self._storage[key] = kept
                results.append(removed)
            elif op == "zcard":
                _, key = cmd
                results.append(len(self._storage.get(key, [])))
            elif op == "zrange":
                _, key, start, stop, withscores = cmd
                entries = sorted(self._storage.get(key, []), key=lambda x: x[1])
                if stop == 0:
                    slice_entries = entries[start:1]
                else:
                    slice_entries = entries[start:stop + 1] if stop != -1 else entries[start:]
                results.append(slice_entries if withscores else [e[0] for e in slice_entries])
            elif op == "zadd":
                _, key, mapping = cmd
                entries = self._storage.setdefault(key, [])
                for member, score in mapping.items():
                    entries.append((member, score))
                results.append(len(mapping))
            elif op == "expire":
                results.append(True)
        return results

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


class MockAsyncRedisClient:
    """Mock Redis client simulating shared multi-worker state with atomic script execution."""

    def __init__(self):
        self.storage = {}
        self._lock = asyncio.Lock()

    def pipeline(self, transaction=True):
        return MockAsyncRedisPipeline(self.storage)

    async def eval(self, script, numkeys, key, now_str, window_str, limit_str, member):
        async with self._lock:
            now = float(now_str)
            window = float(window_str)
            limit = int(limit_str)
            cutoff = now - window

            entries = self.storage.get(key, [])
            # Evict entries outside window (<= cutoff)
            kept = [e for e in entries if e[1] > cutoff]
            self.storage[key] = kept

            current_count = len(kept)
            if current_count >= limit:
                oldest_ts = min([e[1] for e in kept]) if kept else now
                retry_after = max(1, int(round(oldest_ts + window - now + 0.499)))
                return [0, retry_after, current_count]
            else:
                kept.append((member, now))
                self.storage[key] = kept
                return [1, 0, current_count + 1]

    async def evalsha(self, sha, numkeys, *args):
        return await self.eval(None, numkeys, *args)


@pytest.mark.asyncio
async def test_redis_rate_limit_store_allows_under_limit():
    """Verify that requests under the limit succeed and are recorded atomically."""
    mock_redis = MockAsyncRedisClient()
    store = RedisRateLimitStore(redis_client=mock_redis)

    # Limit = 3 requests per 60 seconds
    for _ in range(3):
        allowed, retry_after = await store.check_and_record(
            client_id="user_123", limit=3, window_seconds=60.0
        )
        assert allowed is True
        assert retry_after is None

    # Verify storage has 3 entries
    assert len(mock_redis.storage.get("rate_limit:user_123", [])) == 3


@pytest.mark.asyncio
async def test_redis_rate_limit_store_blocks_at_limit_with_retry_after():
    """Verify that the 4th request at limit 3 is blocked with a positive retry_after."""
    mock_redis = MockAsyncRedisClient()
    store = RedisRateLimitStore(redis_client=mock_redis)

    for _ in range(3):
        await store.check_and_record("user_123", limit=3, window_seconds=60.0)

    # 4th request must be blocked
    allowed, retry_after = await store.check_and_record("user_123", limit=3, window_seconds=60.0)
    assert allowed is False
    assert retry_after is not None
    assert 1 <= retry_after <= 60


@pytest.mark.asyncio
async def test_redis_rate_limit_store_shares_limits_across_workers():
    """Verify that two independent store instances sharing the same Redis client share limits."""
    mock_redis = MockAsyncRedisClient()
    worker_1_store = RedisRateLimitStore(redis_client=mock_redis)
    worker_2_store = RedisRateLimitStore(redis_client=mock_redis)

    # Worker 1 consumes 2 tokens
    allowed1, _ = await worker_1_store.check_and_record("shared_client", limit=3, window_seconds=60.0)
    allowed2, _ = await worker_1_store.check_and_record("shared_client", limit=3, window_seconds=60.0)
    assert allowed1 is True and allowed2 is True

    # Worker 2 consumes 3rd token
    allowed3, _ = await worker_2_store.check_and_record("shared_client", limit=3, window_seconds=60.0)
    assert allowed3 is True

    # Worker 2 attempts 4th token -> blocked by cross-worker state!
    allowed4, retry_after = await worker_2_store.check_and_record("shared_client", limit=3, window_seconds=60.0)
    assert allowed4 is False
    assert retry_after is not None


@pytest.mark.asyncio
async def test_redis_rate_limit_store_isolates_different_clients():
    """Verify that client A reaching limit does not block client B."""
    mock_redis = MockAsyncRedisClient()
    store = RedisRateLimitStore(redis_client=mock_redis)

    for _ in range(2):
        await store.check_and_record("client_a", limit=2, window_seconds=60.0)

    # Client A is blocked
    allowed_a, _ = await store.check_and_record("client_a", limit=2, window_seconds=60.0)
    assert allowed_a is False

    # Client B is still allowed
    allowed_b, _ = await store.check_and_record("client_b", limit=2, window_seconds=60.0)
    assert allowed_b is True


def test_production_environment_rejects_in_memory_rate_limiting():
    """Verify that production mode fails validation if RATE_LIMIT_STORE is memory."""
    s = Settings(
        ENVIRONMENT="production",
        SECRET_KEY="a" * 32,
        INTERNAL_SERVICE_TOKEN="b" * 32,
        SUPABASE_JWT_SECRET="c" * 32,
        ALLOWED_ORIGINS="https://example.com",
        DATABASE_URL="postgresql://user:pass@localhost:5432/db",
        RATE_LIMIT_STORE="memory",
    )
    with pytest.raises(ConfigurationError) as exc_info:
        s.validate_for_environment()
    assert "In-memory rate limiting is prohibited in production" in str(exc_info.value)


def test_redis_rate_limit_store_requires_redis_url():
    """Verify that RATE_LIMIT_STORE='redis' fails validation when REDIS_URL is empty."""
    s = Settings(
        ENVIRONMENT="production",
        SECRET_KEY="a" * 32,
        INTERNAL_SERVICE_TOKEN="b" * 32,
        SUPABASE_JWT_SECRET="c" * 32,
        ALLOWED_ORIGINS="https://example.com",
        DATABASE_URL="postgresql://user:pass@localhost:5432/db",
        RATE_LIMIT_STORE="redis",
        REDIS_URL="",
    )
    with pytest.raises(ConfigurationError) as exc_info:
        s.validate_for_environment()
    assert "REDIS_URL must be specified" in str(exc_info.value)


def test_redis_url_sanitized_in_logging():
    """Verify that password credentials in REDIS_URL are masked by sanitize_for_logging."""
    s = Settings(REDIS_URL="redis://:secret_password@redis.internal:6379/0")
    sanitized = s.sanitize_for_logging()
    assert "secret_password" not in sanitized["REDIS_URL"]
    assert "[REDACTED]" in sanitized["REDIS_URL"]


@pytest.mark.asyncio
async def test_rate_limiter_middleware_dispatches_429_contract():
    """Verify that RateLimitingMiddleware returns exact 429 JSON and Retry-After header."""
    mock_redis = MockAsyncRedisClient()
    store = RedisRateLimitStore(redis_client=mock_redis)

    app_mock = MagicMock()
    middleware = RateLimitingMiddleware(app=app_mock, rate_limit_per_minute=2, store=store)

    async def call_next(req):
        return Response(content="ok", status_code=200)

    def make_scope(ip="198.51.100.1"):
        return {
            "type": "http",
            "method": "POST",
            "path": "/v1/scans",
            "headers": [(b"host", b"testserver")],
            "client": (ip, 12345),
        }

    # Request 1 & 2 succeed
    res1 = await middleware.dispatch(Request(make_scope()), call_next)
    assert res1.status_code == 200
    res2 = await middleware.dispatch(Request(make_scope()), call_next)
    assert res2.status_code == 200

    # Request 3 returns 429
    res3 = await middleware.dispatch(Request(make_scope()), call_next)
    assert res3.status_code == 429
    assert "Retry-After" in res3.headers
    import json
    body = json.loads(res3.body.decode())
    assert body["error_code"] == "RATE_LIMIT_EXCEEDED"
    assert "retry_after_seconds" in body
    assert body["retry_after_seconds"] >= 1


def test_readiness_probe_reports_capabilities_and_stores():
    """Verify that /health/ready returns ocr_available and rate_limit_store."""
    from fastapi.testclient import TestClient
    from app.main import app

    client = TestClient(app)
    res = client.get("/health/ready")
    assert res.status_code == 200
    data = res.json()
    assert "rate_limit_store" in data
    assert data["rate_limit_store"] == "memory"
    assert "ocr_available" in data
    assert isinstance(data["ocr_available"], bool)


def test_readiness_probe_fails_503_when_ocr_required_and_missing():
    """Verify that /health/ready returns 503 if OCR is required but tesseract is not found."""
    from fastapi.testclient import TestClient
    from app.main import app

    client = TestClient(app)
    with patch("app.main.settings.OCR_REQUIRED", True), \
         patch("shutil.which", return_value=None):
        res = client.get("/health/ready")
        assert res.status_code == 503
        assert "OCR binary (tesseract) required but unavailable" in res.json()["detail"]


def test_readiness_probe_fails_503_when_redis_rate_limit_store_unreachable():
    """Verify that /health/ready returns 503 if RATE_LIMIT_STORE='redis' and Redis ping fails."""
    from fastapi.testclient import TestClient
    from app.main import app

    client = TestClient(app)
    with patch("app.main.settings.RATE_LIMIT_STORE", "redis"), \
         patch("app.main.settings.REDIS_URL", "redis://invalid-host:6379/0"):
        res = client.get("/health/ready")
        assert res.status_code == 503
        assert "Distributed rate limit store (Redis) unreachable" in res.json()["detail"]


@pytest.mark.asyncio
async def test_redis_rate_limit_boundary_minus_one_exact_and_over_limit():
    """Verify rate limit boundary conditions: limit-1, exact limit, and 1 over limit."""
    mock_redis = MockAsyncRedisClient()
    store = RedisRateLimitStore(redis_client=mock_redis)
    limit = 4

    # 1. First 3 requests (limit - 1)
    for _ in range(limit - 1):
        allowed, retry_after = await store.check_and_record("boundary_client", limit=limit, window_seconds=60.0)
        assert allowed is True
        assert retry_after is None

    # 2. 4th request (exactly limit)
    allowed, retry_after = await store.check_and_record("boundary_client", limit=limit, window_seconds=60.0)
    assert allowed is True
    assert retry_after is None

    # 3. 5th request (one over limit)
    allowed, retry_after = await store.check_and_record("boundary_client", limit=limit, window_seconds=60.0)
    assert allowed is False
    assert retry_after is not None
    assert 1 <= retry_after <= 60


@pytest.mark.asyncio
async def test_redis_rate_limit_concurrent_burst_enforces_budget():
    """Verify that a concurrent burst against a shared store admits no more than limit."""
    mock_redis = MockAsyncRedisClient()
    store = RedisRateLimitStore(redis_client=mock_redis)
    limit = 5
    concurrency = 20

    # Launch 20 concurrent admission attempts
    tasks = [
        store.check_and_record("burst_client", limit=limit, window_seconds=60.0)
        for _ in range(concurrency)
    ]
    results = await asyncio.gather(*tasks)

    allowed_count = sum(1 for allowed, _ in results if allowed is True)
    blocked_count = sum(1 for allowed, _ in results if allowed is False)

    assert allowed_count == limit, f"Expected exactly {limit} allowed requests, got {allowed_count}"
    assert blocked_count == concurrency - limit, f"Expected {concurrency - limit} blocked requests, got {blocked_count}"


@pytest.mark.asyncio
async def test_redis_rate_limit_duplicate_timestamps_unique_members():
    """Verify that requests occurring at the exact same float timestamp generate unique members and do not collide."""
    mock_redis = MockAsyncRedisClient()
    store = RedisRateLimitStore(redis_client=mock_redis)

    frozen_now = 1710000000.123456
    with patch("time.time", return_value=frozen_now):
        for _ in range(3):
            allowed, _ = await store.check_and_record("timestamp_client", limit=5, window_seconds=60.0)
            assert allowed is True

    # Confirm 3 distinct entries exist in storage despite identical timestamp
    entries = mock_redis.storage.get("rate_limit:timestamp_client", [])
    assert len(entries) == 3
    member_names = [e[0] for e in entries]
    assert len(set(member_names)) == 3, "Members collided on duplicate timestamp!"


@pytest.mark.asyncio
async def test_redis_rate_limit_production_timeout_fails_closed():
    """Verify that in production/pilot, Redis connection timeouts fail closed with HTTP 503."""
    class TimingOutRedisClient:
        async def evalsha(self, *args, **kwargs):
            raise asyncio.TimeoutError("Redis connection timed out")

        async def eval(self, *args, **kwargs):
            raise asyncio.TimeoutError("Redis connection timed out")

    store = RedisRateLimitStore(redis_client=TimingOutRedisClient())
    app_mock = MagicMock()
    middleware = RateLimitingMiddleware(app=app_mock, rate_limit_per_minute=10, store=store)

    async def call_next(req):
        return Response(content="ok", status_code=200)

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/v1/scans",
        "headers": [(b"host", b"testserver")],
        "client": ("192.0.2.1", 12345),
    }

    with patch("app.middleware.rate_limiter.settings.ENVIRONMENT", "production"), \
         patch("app.middleware.rate_limiter.settings.RATE_LIMIT_STORE", "redis"):
        res = await middleware.dispatch(Request(scope), call_next)
        assert res.status_code == 503
        import json
        body = json.loads(res.body.decode())
        assert body["error_code"] == "RATE_LIMIT_STORE_UNAVAILABLE"


@pytest.mark.asyncio
async def test_real_redis_concurrency_opt_in():
    """
    Opt-in real Redis integration test.
    Requires TEST_REDIS_URL environment variable (e.g. redis://localhost:6379/15).
    Verifies that the Lua script executed on a real Redis server atomically enforces budget under concurrency.
    """
    import os
    redis_url = os.getenv("TEST_REDIS_URL")
    if not redis_url:
        pytest.skip("TEST_REDIS_URL not configured; skipping real Redis integration test.")

    import redis.asyncio as aioredis
    real_redis = aioredis.from_url(redis_url, decode_responses=True)
    try:
        await real_redis.ping()
    except Exception as e:
        pytest.skip(f"Real Redis server at {redis_url} unreachable: {e}")

    test_key = f"real_burst_{time.time()}"
    store = RedisRateLimitStore(redis_client=real_redis)
    limit = 5
    concurrency = 25

    try:
        tasks = [
            store.check_and_record(test_key, limit=limit, window_seconds=30.0)
            for _ in range(concurrency)
        ]
        results = await asyncio.gather(*tasks)

        allowed_count = sum(1 for allowed, _ in results if allowed is True)
        blocked_count = sum(1 for allowed, _ in results if allowed is False)

        assert allowed_count == limit, f"Expected exactly {limit} allowed requests on real Redis, got {allowed_count}"
        assert blocked_count == concurrency - limit, f"Expected {concurrency - limit} blocked requests on real Redis, got {blocked_count}"
    finally:
        await real_redis.delete(f"rate_limit:{test_key}")
        await real_redis.aclose()


