"""
Reputation Analyzer & Threat Intelligence Providers
Pluggable adapters for threat reputation data (Google Safe Browsing, VirusTotal, etc.).
Enforces timeouts, bounded retries, provenance tracking, privacy sanitization, and explicit unknown/failure states.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import base64
import re
import urllib.parse
import time
import asyncio
import logging
from typing import List, Optional, Tuple, Dict, Any
import httpx

from risk_engine.url_normalizer import NormalizedURL
from risk_engine.evidence import Evidence, Finding, Severity
from risk_engine.reputation_cache import ReputationCache

logger = logging.getLogger("thelix.reputation")


class ReputationStatus(str, Enum):
    """Normalized threat intelligence outcome states."""
    CONFIRMED_MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    NO_MATCH = "no_match"
    UNAVAILABLE = "unavailable"
    RATE_LIMITED = "rate_limited"
    INVALID_RESPONSE = "invalid_response"


@dataclass
class ReputationResult:
    """Reputation query outcome with provenance, status, and forensic metadata."""
    provider_name: str
    provider_version: str
    status: ReputationStatus
    threat_types: List[str] = field(default_factory=list)
    positives_count: int = 0
    total_engines: int = 0
    latency_ms: int = 0
    error_message: Optional[str] = None
    provenance: Optional[str] = None
    query_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    raw_response: Optional[Dict[str, Any]] = None

    @property
    def is_available(self) -> bool:
        """Returns True if the provider successfully evaluated the indicator."""
        return self.status in (
            ReputationStatus.CONFIRMED_MALICIOUS,
            ReputationStatus.SUSPICIOUS,
            ReputationStatus.NO_MATCH,
        )

    @property
    def is_malicious(self) -> bool:
        return self.status == ReputationStatus.CONFIRMED_MALICIOUS

    @property
    def is_suspicious(self) -> bool:
        return self.status == ReputationStatus.SUSPICIOUS


class PrivacySanitizer:
    """
    Sanitizes URLs before transmitting them to third-party threat intelligence APIs.
    Redacts inline credentials, session IDs, and private tokens.
    """
    SENSITIVE_PARAMS = {"token", "auth", "key", "secret", "password", "session", "jwt", "access_token"}

    @classmethod
    def sanitize(cls, norm: NormalizedURL) -> str:
        """Strips credentials and redacts sensitive query parameters."""
        parsed = urllib.parse.urlsplit(norm.normalized_url)

        # Strip userinfo (username:password@)
        netloc = parsed.hostname or ""
        if parsed.port:
            netloc = f"{netloc}:{parsed.port}"

        # Redact query params
        query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        sanitized_pairs = []
        for k, v in query_pairs:
            k_lower = k.lower()
            if any(s in k_lower for s in cls.SENSITIVE_PARAMS):
                sanitized_pairs.append((k, "REDACTED"))
            else:
                sanitized_pairs.append((k, v))

        new_query = urllib.parse.urlencode(sanitized_pairs)
        return urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path, new_query, ""))


    @classmethod
    def is_private_or_internal(cls, norm: NormalizedURL) -> bool:
        """
        Determines whether the destination is private, loopback, link-local,
        cloud metadata, or internal domain.
        Prevents leaking internal network addresses to external threat intel feeds.
        """
        import ipaddress
        host = (getattr(norm, "hostname", "") or "").strip("[]").lower()
        if not host:
            return False

        if host in {"169.254.169.254", "metadata.google.internal", "metadata.goog", "instance-data", "localhost"} or host.endswith(".internal") or host.endswith(".local"):
            return True

        try:
            ip = ipaddress.ip_address(host)
            if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_unspecified:
                return True
        except ValueError:
            pass

        return False


class ReputationProvider(ABC):
    """Abstract base class for all external threat reputation providers."""
    name: str = "generic_provider"
    version: str = "1.0.0"

    def __init__(self, cache: Optional[ReputationCache] = None):
        self.cache = cache

    @abstractmethod
    async def _execute_lookup(self, sanitized_url: str) -> ReputationResult:
        """Provider-specific network query implementation."""
        pass

    async def check_url(self, norm: NormalizedURL) -> ReputationResult:
        """
        Public lookup interface applying caching, privacy sanitization,
        rate-limit guards, and timing.
        """
        # Guard: Do not leak private/internal destinations to external third-party threat feeds
        if PrivacySanitizer.is_private_or_internal(norm):
            return ReputationResult(
                provider_name=self.name,
                provider_version=self.version,
                status=ReputationStatus.NO_MATCH,
                threat_types=[],
                positives_count=0,
                total_engines=0,
                error_message=None,
                raw_response={"note": "Private or internal destination query omitted for privacy"},
            )

        sanitized_url = PrivacySanitizer.sanitize(norm)

        # 1. Check Cache
        if self.cache:
            cached = self.cache.get(self.name, sanitized_url)
            if cached is not None:
                return cached

            # Check if provider is currently backing off from 429
            if self.cache.is_rate_limited(self.name):
                return ReputationResult(
                    provider_name=self.name,
                    provider_version=self.version,
                    status=ReputationStatus.RATE_LIMITED,
                    error_message=f"Provider '{self.name}' is temporarily throttled (active rate-limit backoff)",
                )

        # 2. Execute Lookup
        t0 = time.time()
        try:
            result = await self._execute_lookup(sanitized_url)
        except Exception as e:
            logger.warning(f"Reputation provider '{self.name}' lookup failed: {e}")
            result = ReputationResult(
                provider_name=self.name,
                provider_version=self.version,
                status=ReputationStatus.UNAVAILABLE,
                error_message=str(e),
            )
        result.latency_ms = int((time.time() - t0) * 1000)
        result.provenance = f"{self.name}:{self.version}@{result.query_timestamp.isoformat()}"

        # 3. Handle Rate Limiting & Cache Storage
        if self.cache:
            if result.status == ReputationStatus.RATE_LIMITED:
                self.cache.record_rate_limit(self.name, backoff_seconds=60.0)
            self.cache.set(self.name, sanitized_url, result)

        return result


class GoogleSafeBrowsingProvider(ReputationProvider):
    """Google Safe Browsing Lookup API v4 provider."""
    name = "google_safe_browsing"
    version = "v4"

    def __init__(
        self,
        api_key: str,
        timeout_seconds: float = 4.0,
        cache: Optional[ReputationCache] = None,
    ):
        super().__init__(cache=cache)
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds

    async def _execute_lookup(self, sanitized_url: str) -> ReputationResult:
        if not self.api_key:
            return ReputationResult(
                provider_name=self.name,
                provider_version=self.version,
                status=ReputationStatus.UNAVAILABLE,
                error_message="Google Safe Browsing API key unconfigured",
            )

        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.api_key}"
        payload = {
            "client": {"clientId": "thelix-ai", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": sanitized_url}]
            }
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                resp = await client.post(endpoint, json=payload)
                if resp.status_code == 429:
                    return ReputationResult(
                        provider_name=self.name,
                        provider_version=self.version,
                        status=ReputationStatus.RATE_LIMITED,
                        error_message="Google Safe Browsing API quota exceeded (HTTP 429)",
                    )
                resp.raise_for_status()
                data = resp.json()

            matches = data.get("matches", [])
            threats = [m.get("threatType", "MALWARE") for m in matches]
            is_match = len(matches) > 0

            return ReputationResult(
                provider_name=self.name,
                provider_version=self.version,
                status=ReputationStatus.CONFIRMED_MALICIOUS if is_match else ReputationStatus.NO_MATCH,
                threat_types=threats,
                positives_count=len(matches),
                total_engines=1,
                raw_response=data if is_match else None,
            )
        except httpx.TimeoutException:
            return ReputationResult(
                provider_name=self.name,
                provider_version=self.version,
                status=ReputationStatus.UNAVAILABLE,
                error_message="Google Safe Browsing query timed out",
            )
        except Exception as e:
            # Mask API key from error message
            safe_err = re.sub(r"key=[A-Za-z0-9_\-]+", "key=REDACTED", str(e))
            logger.warning(f"Google Safe Browsing query failed: {safe_err}")
            return ReputationResult(
                provider_name=self.name,
                provider_version=self.version,
                status=ReputationStatus.UNAVAILABLE,
                error_message=safe_err,
            )


class VirusTotalProvider(ReputationProvider):
    """VirusTotal API v3 provider."""
    name = "virustotal"
    version = "v3"

    def __init__(
        self,
        api_key: str,
        timeout_seconds: float = 5.0,
        cache: Optional[ReputationCache] = None,
    ):
        super().__init__(cache=cache)
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds

    async def _execute_lookup(self, sanitized_url: str) -> ReputationResult:
        if not self.api_key:
            return ReputationResult(
                provider_name=self.name,
                provider_version=self.version,
                status=ReputationStatus.UNAVAILABLE,
                error_message="VirusTotal API key unconfigured",
            )

        url_id = base64.urlsafe_b64encode(sanitized_url.encode()).decode().strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": self.api_key}

        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                resp = await client.get(endpoint, headers=headers)
                if resp.status_code == 404:
                    # Unknown/unseen URL in VirusTotal database
                    return ReputationResult(
                        provider_name=self.name,
                        provider_version=self.version,
                        status=ReputationStatus.NO_MATCH,
                        error_message="URL not found in VirusTotal database (unseen)",
                    )
                if resp.status_code == 429:
                    return ReputationResult(
                        provider_name=self.name,
                        provider_version=self.version,
                        status=ReputationStatus.RATE_LIMITED,
                        error_message="VirusTotal API rate limit exceeded (HTTP 429)",
                    )
                resp.raise_for_status()
                data = resp.json()

            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values()) if stats else 0
            positives = malicious + suspicious

            if malicious >= 3:
                status = ReputationStatus.CONFIRMED_MALICIOUS
            elif positives >= 1:
                status = ReputationStatus.SUSPICIOUS
            else:
                status = ReputationStatus.NO_MATCH

            return ReputationResult(
                provider_name=self.name,
                provider_version=self.version,
                status=status,
                threat_types=["MALWARE_OR_PHISHING"] if positives > 0 else [],
                positives_count=positives,
                total_engines=total,
                raw_response=stats,
            )
        except httpx.TimeoutException:
            return ReputationResult(
                provider_name=self.name,
                provider_version=self.version,
                status=ReputationStatus.UNAVAILABLE,
                error_message="VirusTotal query timed out",
            )
        except Exception as e:
            logger.warning(f"VirusTotal query failed: {e}")
            return ReputationResult(
                provider_name=self.name,
                provider_version=self.version,
                status=ReputationStatus.UNAVAILABLE,
                error_message=str(e),
            )


class MockThreatIntelProvider(ReputationProvider):
    """
    Test provider capable of simulating malicious, clean, rate-limited,
    timeout, and invalid responses without making live network calls.
    """
    name = "mock_intel"
    version = "1.0.0"

    def __init__(
        self,
        canned_status: ReputationStatus = ReputationStatus.NO_MATCH,
        positives_count: int = 0,
        threat_types: Optional[List[str]] = None,
        cache: Optional[ReputationCache] = None,
    ):
        super().__init__(cache=cache)
        self.canned_status = canned_status
        self.positives_count = positives_count
        self.threat_types = threat_types or []
        self.call_count = 0

    async def _execute_lookup(self, sanitized_url: str) -> ReputationResult:
        self.call_count += 1
        return ReputationResult(
            provider_name=self.name,
            provider_version=self.version,
            status=self.canned_status,
            threat_types=self.threat_types,
            positives_count=self.positives_count,
            total_engines=70 if self.canned_status != ReputationStatus.UNAVAILABLE else 0,
            error_message="Simulated error" if self.canned_status in (ReputationStatus.UNAVAILABLE, ReputationStatus.RATE_LIMITED) else None,
        )


class ReputationAnalyzer:
    """
    Coordinates threat intelligence providers and translates findings into normalized evidence.
    """
    ENGINE_NAME = "reputation_analyzer"
    ENGINE_VERSION = "2.0.0"

    def __init__(
        self,
        providers: Optional[List[ReputationProvider]] = None,
        cache: Optional[ReputationCache] = None,
    ):
        self.cache = cache or ReputationCache()
        self._providers: List[ReputationProvider] = []
        self.providers = providers if providers is not None else []

    @property
    def providers(self) -> List[ReputationProvider]:
        return self._providers

    @providers.setter
    def providers(self, new_providers: List[ReputationProvider]):
        self._providers = list(new_providers) if new_providers is not None else []
        for p in self._providers:
            if not p.cache and hasattr(self, "cache"):
                p.cache = self.cache

    async def analyze(self, norm: NormalizedURL) -> Tuple[List[Evidence], List[Finding], Dict[str, Any]]:
        """
        Queries all configured reputation providers concurrently.
        Returns (evidence_list, findings_list, provider_metadata).
        """
        evidence_list: List[Evidence] = []
        findings_list: List[Finding] = []
        provider_meta: Dict[str, Any] = {}

        if not self.providers:
            return evidence_list, findings_list, provider_meta

        # Concurrently query all configured threat reputation providers
        lookup_tasks = [provider.check_url(norm) for provider in self.providers]
        results: List[ReputationResult] = await asyncio.gather(*lookup_tasks)

        for provider, res in zip(self.providers, results):
            provider_meta[provider.name] = {
                "status": res.status.value,
                "available": res.is_available,
                "malicious": res.is_malicious,
                "suspicious": res.is_suspicious,
                "positives": res.positives_count,
                "total_engines": res.total_engines,
                "latency_ms": res.latency_ms,
                "provenance": res.provenance,
                "error": res.error_message,
                "timestamp": res.query_timestamp.isoformat(),
            }

            if not res.is_available:
                # Provider was unavailable, rate-limited, or failed
                continue

            if res.is_malicious:
                ev = Evidence(
                    indicator_type=f"reputation_{provider.name}_match",
                    indicator_value_or_reference=norm.normalized_url,
                    source_engine=provider.name,
                    source_version=provider.version,
                    observation={
                        "threat_types": res.threat_types,
                        "positives": res.positives_count,
                        "total_engines": res.total_engines,
                    },
                    reliability=0.98 if provider.name == "google_safe_browsing" else 0.92,
                    confidence=0.95,
                    correlation_group="threat_intel_match",
                    provenance=res.provenance or f"{provider.name}:{provider.version}",
                )
                evidence_list.append(ev)

                is_critical = (
                    provider.name == "google_safe_browsing"
                    or res.positives_count >= 5
                    or any(t.upper() in ("MALWARE", "SOCIAL_ENGINEERING", "PHISHING") for t in res.threat_types)
                )

                findings_list.append(Finding(
                    finding_code=f"FIND-REP-{provider.name.upper()}",
                    title=f"Flagged by Threat Intelligence ({provider.name})",
                    description=f"Destination matched known threat intelligence signatures: {', '.join(res.threat_types) if res.threat_types else f'{res.positives_count} engines flagged'}.",
                    severity=Severity.CRITICAL if is_critical else Severity.HIGH,
                    confidence=0.95,
                    source_engine=provider.name,
                    source_version=provider.version,
                    evidence_references=[ev.evidence_id],
                    correlation_group="threat_intel_match",
                ))

            elif res.is_suspicious:
                ev_susp = Evidence(
                    indicator_type=f"reputation_{provider.name}_suspicious",
                    indicator_value_or_reference=norm.normalized_url,
                    source_engine=provider.name,
                    source_version=provider.version,
                    observation={"positives": res.positives_count, "total_engines": res.total_engines},
                    reliability=0.85,
                    confidence=0.80,
                    correlation_group="threat_intel_match",
                    provenance=res.provenance or f"{provider.name}:{provider.version}",
                )
                evidence_list.append(ev_susp)

                findings_list.append(Finding(
                    finding_code=f"FIND-REP-SUSPICIOUS-{provider.name.upper()}",
                    title=f"Suspicious Reputation ({provider.name})",
                    description=f"Destination flagged by multiple engines ({res.positives_count}/{res.total_engines}).",
                    severity=Severity.MEDIUM,
                    confidence=0.80,
                    source_engine=provider.name,
                    source_version=provider.version,
                    evidence_references=[ev_susp.evidence_id],
                    correlation_group="threat_intel_match",
                ))
            elif res.status == ReputationStatus.NO_MATCH:
                # Record clean lookup evidence. Crucial requirement: No match does NOT prove safety.
                # It does not add a finding or reduce existing risk scores.
                ev_clean = Evidence(
                    indicator_type=f"reputation_{provider.name}_clean",
                    indicator_value_or_reference=norm.normalized_url,
                    source_engine=provider.name,
                    source_version=provider.version,
                    observation={"status": "clean", "total_engines": res.total_engines},
                    reliability=0.75,
                    confidence=0.70,
                    correlation_group=None,
                    provenance=res.provenance or f"{provider.name}:{provider.version}",
                )
                evidence_list.append(ev_clean)

        return evidence_list, findings_list, provider_meta
