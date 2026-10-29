"""
Reputation Cache & Rate Control
Provides thread-safe, privacy-preserving in-process caching for threat intelligence lookups.
Enforces provider-specific TTLs, differentiated treatment of positive/negative/failure results,
safe SHA-256 cache keys, and rate limit backoff tracking.
"""
from typing import Optional, Dict, Any
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import time
import threading
import logging

logger = logging.getLogger("thelix.reputation_cache")


@dataclass
class CacheEntry:
    """Represents a cached reputation result with expiry metadata."""
    key: str
    result: Any  # ReputationResult
    cached_at: float
    expires_at: float

    @property
    def is_expired(self) -> bool:
        return time.time() >= self.expires_at


class ReputationCache:
    """
    Thread-safe in-process cache for threat reputation results.
    Prevents redundant external API queries and respects quota limits.
    """

    # Default TTL configuration (seconds)
    DEFAULT_TTLS: Dict[str, int] = {
        "malicious": 86400,       # 24 hours for confirmed threats
        "suspicious": 21600,      # 6 hours for suspicious signals
        "no_match": 7200,         # 2 hours for clean / unflagged targets
        "rate_limited": 60,       # 1 minute backoff for 429 rate limits
        "unavailable": 30,        # 30 seconds for transient failures
        "invalid_response": 30,   # 30 seconds for malformed responses
    }

    def __init__(self, custom_ttls: Optional[Dict[str, int]] = None):
        self._lock = threading.Lock()
        self._entries: Dict[str, CacheEntry] = {}
        self._rate_limits: Dict[str, float] = {}  # provider_name -> blocked_until timestamp
        self.ttls = {**self.DEFAULT_TTLS, **(custom_ttls or {})}

    @staticmethod
    def generate_safe_key(provider_name: str, url: str) -> str:
        """
        Derives a privacy-preserving cache key using SHA-256.
        Prevents storing sensitive query tokens or credentials in cleartext cache keys.
        """
        # Canonicalize host and path for hashing
        clean_url = url.strip()
        url_hash = hashlib.sha256(clean_url.encode("utf-8")).hexdigest()
        return f"rep:{provider_name}:{url_hash}"

    def get(self, provider_name: str, url: str) -> Optional[Any]:
        """
        Retrieves a cached reputation result if present and not expired.
        Returns None on cache miss or expiration.
        """
        key = self.generate_safe_key(provider_name, url)
        with self._lock:
            entry = self._entries.get(key)
            if not entry:
                return None

            if entry.is_expired:
                # Evict expired entry
                del self._entries[key]
                logger.debug(f"Cache entry expired for provider '{provider_name}'")
                return None

            logger.debug(f"Cache hit for provider '{provider_name}' (safe key: {key[:16]}...)")
            return entry.result

    def set(
        self,
        provider_name: str,
        url: str,
        result: Any,
        custom_ttl: Optional[int] = None,
    ) -> None:
        """
        Caches a reputation query result using provider status TTL policies.
        Crucial requirement: Failed or rate-limited queries are never cached as clean.
        """
        key = self.generate_safe_key(provider_name, url)
        status_val = getattr(result, "status", None)
        status_str = status_val.value if hasattr(status_val, "value") else str(status_val or "unavailable")

        ttl = custom_ttl or self.ttls.get(status_str.lower(), self.ttls["unavailable"])
        now = time.time()

        entry = CacheEntry(
            key=key,
            result=result,
            cached_at=now,
            expires_at=now + ttl,
        )

        with self._lock:
            self._entries[key] = entry

    def record_rate_limit(self, provider_name: str, backoff_seconds: float = 60.0) -> None:
        """Registers a rate limit block on a provider to avoid subsequent doomed requests."""
        with self._lock:
            self._rate_limits[provider_name] = time.time() + backoff_seconds
            logger.warning(
                f"Rate limit recorded for provider '{provider_name}'. Backing off for {backoff_seconds}s"
            )

    def is_rate_limited(self, provider_name: str) -> bool:
        """Checks if a provider is currently under an active rate limit backoff."""
        with self._lock:
            blocked_until = self._rate_limits.get(provider_name)
            if not blocked_until:
                return False
            if time.time() >= blocked_until:
                del self._rate_limits[provider_name]
                return False
            return True

    def invalidate(self, provider_name: str, url: str) -> bool:
        """Explicitly evicts a cached lookup."""
        key = self.generate_safe_key(provider_name, url)
        with self._lock:
            if key in self._entries:
                del self._entries[key]
                return True
            return False

    def clear(self) -> None:
        """Purges all cache entries and active rate limits."""
        with self._lock:
            self._entries.clear()
            self._rate_limits.clear()

    def size(self) -> int:
        """Returns the current number of active cache entries."""
        with self._lock:
            # Clean expired on inspection
            now = time.time()
            self._entries = {k: v for k, v in self._entries.items() if v.expires_at > now}
            return len(self._entries)
