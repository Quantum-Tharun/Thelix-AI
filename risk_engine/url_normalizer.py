"""
URL Normalizer
Deterministic canonicalization of URLs without network access.
Tracks all structural transformations applied to preserve auditability.
"""
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlsplit, urlunsplit, quote, unquote
import idna
import re

from risk_engine.input_validator import InputValidator
from risk_engine.exceptions import MalformedURLException


@dataclass
class NormalizedURL:
    """
    Structured outcome of the URL normalization phase.
    """
    raw_url: str
    normalized_url: str
    scheme: str
    hostname: str
    punycode_hostname: str
    port: Optional[int]
    path: str
    query: str
    fragment: str
    is_ip_literal: bool
    is_idn: bool
    has_userinfo: bool
    changes_applied: List[str] = field(default_factory=list)


class URLNormalizer:
    """
    Canonicalizes URLs according to RFC 3986 standards.
    Strictly avoids network requests and records every mutation.
    """

    IP_PATTERN = re.compile(
        r"^(\d{1,3}\.){3}\d{1,3}$|"
        r"^\[[0-9a-fA-F:]+\]$"
    )

    @classmethod
    def normalize(cls, raw_url: str) -> NormalizedURL:
        """
        Normalizes a raw URL string and tracks changes applied.
        """
        validated = InputValidator.validate_url(raw_url)
        changes: List[str] = []

        raw_scheme = validated["scheme"]
        scheme = raw_scheme.lower()
        if scheme != raw_scheme:
            changes.append("lowercased_scheme")

        raw_host = validated["hostname"]
        host = raw_host.lower()
        if host != raw_host:
            changes.append("lowercased_hostname")

        # Punycode / IDN handling
        is_idn = False
        punycode_host = host
        try:
            # Check if domain has non-ASCII characters
            host.encode("ascii")
        except UnicodeEncodeError:
            is_idn = True
            try:
                punycode_host = idna.encode(host).decode("ascii")
                changes.append(f"idn_punycode_converted:{punycode_host}")
            except Exception as e:
                raise MalformedURLException(f"Invalid IDN hostname '{host}': {str(e)}")

        # Check for IP literal
        is_ip_literal = bool(cls.IP_PATTERN.match(punycode_host))

        # Port handling
        port = validated["port"]
        if port is not None:
            if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
                port = None
                changes.append("stripped_default_port")

        # Userinfo handling
        has_userinfo = bool(validated["username"] or validated["password"])
        if has_userinfo:
            changes.append("retained_userinfo_for_analysis")

        # Path normalization
        raw_path = validated["path"]
        path = raw_path
        if not path:
            path = "/"
            changes.append("added_root_slash")
        else:
            # Normalize consecutive slashes in path (e.g. //path -> /path) while leaving leading root
            normalized_path = re.sub(r"/{2,}", "/", path)
            if normalized_path != path:
                path = normalized_path
                changes.append("collapsed_consecutive_slashes")

        # Query and fragment preservation
        query = validated["query"]
        fragment = validated["fragment"]

        # Reconstruct canonical URL
        netloc = punycode_host
        if validated["username"]:
            user_part = validated["username"]
            if validated["password"]:
                user_part += f":{validated['password']}"
            netloc = f"{user_part}@{netloc}"
        if port is not None:
            netloc = f"{netloc}:{port}"

        normalized_url = urlunsplit((scheme, netloc, path, query, fragment))

        return NormalizedURL(
            raw_url=validated["raw_url"],
            normalized_url=normalized_url,
            scheme=scheme,
            hostname=host,
            punycode_hostname=punycode_host,
            port=port,
            path=path,
            query=query,
            fragment=fragment,
            is_ip_literal=is_ip_literal,
            is_idn=is_idn,
            has_userinfo=has_userinfo,
            changes_applied=changes,
        )
