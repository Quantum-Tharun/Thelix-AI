"""
Static URL Analyzer
Inspects structural characteristics, lexical indicators, homographs, encoding, and brand impersonation.
Produces atomic Evidence records and structured Findings without network access.
"""
import math
import re
from typing import List, Tuple, Set, Optional
from urllib.parse import parse_qs, unquote
import ipaddress

from risk_engine.url_normalizer import NormalizedURL
from risk_engine.evidence import Evidence, Finding, Severity

# Targeted high-profile brands frequently targeted in phishing campaigns
TARGET_BRANDS: Set[str] = {
    "paypal", "google", "apple", "microsoft", "amazon", "netflix",
    "facebook", "instagram", "whatsapp", "chase", "bankofamerica",
    "wellsfargo", "citibank", "coinbase", "binance", "metamask",
    "irs", "usps", "fedex", "dhl"
}

# Suspicious TLDs with high historical malicious abuse rates
SUSPICIOUS_TLDS: Set[str] = {
    "top", "xyz", "club", "work", "click", "buzz", "loan",
    "tk", "ml", "ga", "cf", "gq", "gdn", "icu", "rest", "cam"
}

# Suspicious keyword indicators in domain or path
SUSPICIOUS_KEYWORDS: Set[str] = {
    "login", "verify", "verification", "account", "secure", "security",
    "banking", "update", "wallet", "confirm", "confirmation", "recover",
    "recovery", "authenticate", "auth", "signin", "password", "support"
}

# Redirect query parameter keys frequently abused in open redirectors
REDIRECT_PARAM_KEYS: Set[str] = {
    "url", "redirect", "redirect_url", "redirect_uri", "next",
    "dest", "destination", "target", "goto", "link", "r", "u"
}

# Cyrillic and Greek lookalikes for Latin characters
HOMOGLYPH_CHARS = {
    'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y',
    'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w',
    'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I',
    'Κ': 'K', 'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T',
    'Υ': 'Y', 'Χ': 'X'
}


class StaticURLAnalyzer:
    """
    Performs static structural and lexical inspection on normalized URLs.
    """
    ENGINE_NAME = "static_url_analyzer"
    ENGINE_VERSION = "1.0.0"

    @classmethod
    def analyze(cls, norm: NormalizedURL) -> Tuple[List[Evidence], List[Finding]]:
        """
        Executes all static heuristics and returns (evidence_list, findings_list).
        """
        evidence_list: List[Evidence] = []
        findings_list: List[Finding] = []

        cls._check_ip_literal(norm, evidence_list, findings_list)
        cls._check_userinfo_trick(norm, evidence_list, findings_list)
        cls._check_lookalike_and_homographs(norm, evidence_list, findings_list)
        cls._check_subdomains_and_brand_impersonation(norm, evidence_list, findings_list)
        cls._check_suspicious_tld(norm, evidence_list, findings_list)
        cls._check_unusual_ports(norm, evidence_list, findings_list)
        cls._check_encoding_anomalies(norm, evidence_list, findings_list)
        cls._check_redirect_parameters(norm, evidence_list, findings_list)
        cls._check_entropy_and_dga(norm, evidence_list, findings_list)

        return evidence_list, findings_list

    @classmethod
    def _check_ip_literal(cls, norm: NormalizedURL, ev: List[Evidence], fn: List[Finding]):
        """Detects if hostname is an IP address instead of a domain name."""
        host = norm.punycode_hostname.strip("[]")
        is_ip = False
        ip_obj = None

        try:
            ip_obj = ipaddress.ip_address(host)
            is_ip = True
        except ValueError:
            # Check integer or hex representations (e.g., 2130706433 or 0x7f.0.0.1)
            if re.match(r"^\d{7,10}$", host) or "0x" in host.lower():
                is_ip = True

        if is_ip or norm.is_ip_literal:
            e = Evidence(
                indicator_type="ip_literal_host",
                indicator_value_or_reference=host,
                source_engine=cls.ENGINE_NAME,
                source_version=cls.ENGINE_VERSION,
                observation={"hostname": host, "is_private": ip_obj.is_private if ip_obj else False},
                reliability=0.90,
                confidence=0.95,
                correlation_group="host_format",
            )
            ev.append(e)

            fn.append(Finding(
                finding_code="FIND-URL-IP-HOST",
                title="IP Address Used as Hostname",
                description=f"Destination '{host}' is an IP literal rather than a registered domain name. Legitimate services typically use domain names.",
                severity=Severity.HIGH,
                confidence=0.85,
                source_engine=cls.ENGINE_NAME,
                source_version=cls.ENGINE_VERSION,
                evidence_references=[e.evidence_id],
                correlation_group="host_format",
            ))

    @classmethod
    def _check_userinfo_trick(cls, norm: NormalizedURL, ev: List[Evidence], fn: List[Finding]):
        """Detects userinfo embedding e.g. https://google.com@evil.com/"""
        if norm.has_userinfo:
            e = Evidence(
                indicator_type="userinfo_trick",
                indicator_value_or_reference=norm.raw_url,
                source_engine=cls.ENGINE_NAME,
                source_version=cls.ENGINE_VERSION,
                observation={"url": norm.raw_url},
                reliability=0.95,
                confidence=0.95,
                correlation_group="deceptive_syntax",
            )
            ev.append(e)

            fn.append(Finding(
                finding_code="FIND-URL-USERINFO",
                title="Deceptive User-Info in URL Authority",
                description="The URL authority section contains '@' credentials. This is frequently used in phishing to disguise the real destination host.",
                severity=Severity.HIGH,
                confidence=0.95,
                source_engine=cls.ENGINE_NAME,
                source_version=cls.ENGINE_VERSION,
                evidence_references=[e.evidence_id],
                correlation_group="deceptive_syntax",
            ))

    @classmethod
    def _check_lookalike_and_homographs(cls, norm: NormalizedURL, ev: List[Evidence], fn: List[Finding]):
        """Detects Punycode or mixed-script / Cyrillic homoglyph characters."""
        if norm.is_idn or norm.punycode_hostname.startswith("xn--"):
            detected_homoglyphs = []
            for ch in norm.hostname:
                if ch in HOMOGLYPH_CHARS:
                    detected_homoglyphs.append(f"'{ch}' (looks like '{HOMOGLYPH_CHARS[ch]}')")

            e = Evidence(
                indicator_type="idn_punycode",
                indicator_value_or_reference=norm.punycode_hostname,
                source_engine=cls.ENGINE_NAME,
                source_version=cls.ENGINE_VERSION,
                observation={
                    "punycode": norm.punycode_hostname,
                    "unicode": norm.hostname,
                    "homoglyphs_detected": detected_homoglyphs,
                },
                reliability=0.85,
                confidence=0.90,
                correlation_group="homoglyph",
            )
            ev.append(e)

            fn.append(Finding(
                finding_code="FIND-URL-HOMOGRAPH",
                title="Internationalized Domain (IDN) / Punycode Detected",
                description=f"Domain '{norm.hostname}' translates to Punycode '{norm.punycode_hostname}'. Attackers use visually identical characters to impersonate known domains.",
                severity=Severity.MEDIUM if not detected_homoglyphs else Severity.HIGH,
                confidence=0.85,
                source_engine=cls.ENGINE_NAME,
                source_version=cls.ENGINE_VERSION,
                evidence_references=[e.evidence_id],
                correlation_group="homoglyph",
            ))

    @classmethod
    def _check_subdomains_and_brand_impersonation(cls, norm: NormalizedURL, ev: List[Evidence], fn: List[Finding]):
        """Detects misleading subdomains, brand keywords outside apex domain, and hyphen stuffing."""
        host = norm.hostname.lower()
        parts = host.split(".")

        # Count subdomains
        if len(parts) >= 4:
            e = Evidence(
                indicator_type="excessive_subdomains",
                indicator_value_or_reference=host,
                source_engine=cls.ENGINE_NAME,
                source_version=cls.ENGINE_VERSION,
                observation={"subdomain_count": len(parts) - 2},
                reliability=0.70,
                confidence=0.75,
                correlation_group="host_structure",
            )
            ev.append(e)

        # Hyphen stuffing (e.g. secure-paypal-login-update-service.com)
        hyphen_count = host.count("-")
        if hyphen_count >= 3:
            e = Evidence(
                indicator_type="hyphen_stuffing",
                indicator_value_or_reference=host,
                source_engine=cls.ENGINE_NAME,
                source_version=cls.ENGINE_VERSION,
                observation={"hyphen_count": hyphen_count},
                reliability=0.75,
                confidence=0.80,
                correlation_group="host_structure",
            )
            ev.append(e)

        # Brand impersonation check
        # Apex domain is approximately parts[-2] if len >= 2
        apex = parts[-2] if len(parts) >= 2 else ""
        impersonated_brands = []
        for brand in TARGET_BRANDS:
            # Check if brand is in host, but apex is NOT exactly the brand
            if brand in host and apex != brand:
                impersonated_brands.append(brand)

        if impersonated_brands:
            e = Evidence(
                indicator_type="brand_impersonation",
                indicator_value_or_reference=",".join(impersonated_brands),
                source_engine=cls.ENGINE_NAME,
                source_version=cls.ENGINE_VERSION,
                observation={"target_brands": impersonated_brands, "host": host},
                reliability=0.85,
                confidence=0.90,
                correlation_group="brand_impersonation",
            )
            ev.append(e)

            fn.append(Finding(
                finding_code="FIND-URL-BRAND-IMPERSONATION",
                title="Probable Brand Impersonation in Hostname",
                description=f"Hostname references trusted brand name(s) ({', '.join(impersonated_brands)}) without being the authoritative domain.",
                severity=Severity.HIGH,
                confidence=0.85,
                source_engine=cls.ENGINE_NAME,
                source_version=cls.ENGINE_VERSION,
                evidence_references=[e.evidence_id],
                correlation_group="brand_impersonation",
            ))

    @classmethod
    def _check_suspicious_tld(cls, norm: NormalizedURL, ev: List[Evidence], fn: List[Finding]):
        """Detects top-level domains commonly associated with disposable phishing campaigns."""
        parts = norm.hostname.split(".")
        if len(parts) >= 2:
            tld = parts[-1].lower()
            if tld in SUSPICIOUS_TLDS:
                # Check if suspicious TLD is paired with financial, billing, or credential harvesting lures
                lure_terms = [
                    kw for kw in (SUSPICIOUS_KEYWORDS | {"billing", "quickpay", "portal", "payment", "pay", "checkout"})
                    if kw in norm.hostname.lower() or kw in norm.path.lower()
                ]
                has_lure = len(lure_terms) > 0
                e = Evidence(
                    indicator_type="suspicious_tld_lure" if has_lure else "suspicious_tld",
                    indicator_value_or_reference=f"{tld}:{','.join(lure_terms)}" if has_lure else tld,
                    source_engine=cls.ENGINE_NAME,
                    source_version=cls.ENGINE_VERSION,
                    observation={"tld": tld, "lure_terms": lure_terms},
                    reliability=0.85 if has_lure else 0.70,
                    confidence=0.85 if has_lure else 0.75,
                    correlation_group="tld_reputation",
                )
                ev.append(e)

                fn.append(Finding(
                    finding_code="FIND-URL-SUSPICIOUS-TLD",
                    title="High-Risk Top-Level Domain (TLD) with Credential/Financial Lure" if has_lure else "High-Risk Top-Level Domain (TLD)",
                    description=(
                        f"Domain on elevated-risk '.{tld}' TLD contains sensitive credential/financial keyword(s): {', '.join(lure_terms)}"
                        if has_lure else
                        f"The domain uses '.{tld}', a TLD with statistically elevated rates of malicious activity and abuse."
                    ),
                    severity=Severity.MEDIUM if has_lure else Severity.LOW,
                    confidence=0.85 if has_lure else 0.65,
                    source_engine=cls.ENGINE_NAME,
                    source_version=cls.ENGINE_VERSION,
                    evidence_references=[e.evidence_id],
                    correlation_group="tld_reputation",
                ))

    @classmethod
    def _check_unusual_ports(cls, norm: NormalizedURL, ev: List[Evidence], fn: List[Finding]):
        """Detects unusual or high-risk port assignments."""
        if norm.port is not None:
            common_web_ports = {80, 443, 8080, 8443}
            if norm.port not in common_web_ports:
                e = Evidence(
                    indicator_type="unusual_port",
                    indicator_value_or_reference=str(norm.port),
                    source_engine=cls.ENGINE_NAME,
                    source_version=cls.ENGINE_VERSION,
                    observation={"port": norm.port},
                    reliability=0.80,
                    confidence=0.85,
                    correlation_group="network_port",
                )
                ev.append(e)

                fn.append(Finding(
                    finding_code="FIND-URL-UNUSUAL-PORT",
                    title="Non-Standard Port Assignment",
                    description=f"The URL specifies unusual port {norm.port}. Standard web traffic typically operates on port 80 or 443.",
                    severity=Severity.MEDIUM,
                    confidence=0.75,
                    source_engine=cls.ENGINE_NAME,
                    source_version=cls.ENGINE_VERSION,
                    evidence_references=[e.evidence_id],
                    correlation_group="network_port",
                ))

    @classmethod
    def _check_encoding_anomalies(cls, norm: NormalizedURL, ev: List[Evidence], fn: List[Finding]):
        """Detects double percent-encoding or multi-layer evasion tricks."""
        raw = norm.raw_url
        if "%25" in raw.lower():
            e = Evidence(
                indicator_type="double_percent_encoding",
                indicator_value_or_reference="%25",
                source_engine=cls.ENGINE_NAME,
                source_version=cls.ENGINE_VERSION,
                observation={"url": raw[:120]},
                reliability=0.85,
                confidence=0.90,
                correlation_group="evasion_technique",
            )
            ev.append(e)

            fn.append(Finding(
                finding_code="FIND-URL-DOUBLE-ENCODING",
                title="Double Percent-Encoding Detected",
                description="URL contains '%25' sequence, indicating multi-layer URL encoding often used to evade web application firewalls and security filters.",
                severity=Severity.MEDIUM,
                confidence=0.85,
                source_engine=cls.ENGINE_NAME,
                source_version=cls.ENGINE_VERSION,
                evidence_references=[e.evidence_id],
                correlation_group="evasion_technique",
            ))

    @classmethod
    def _check_redirect_parameters(cls, norm: NormalizedURL, ev: List[Evidence], fn: List[Finding]):
        """Detects query parameters pointing to external URLs (open redirect indicators)."""
        if not norm.query:
            return

        try:
            params = parse_qs(norm.query, keep_blank_values=False)
        except Exception:
            return

        redirect_targets = []
        for key, vals in params.items():
            if key.lower() in REDIRECT_PARAM_KEYS:
                for v in vals:
                    if v.startswith("http://") or v.startswith("https://") or v.startswith("//"):
                        redirect_targets.append((key, v))

        if redirect_targets:
            e = Evidence(
                indicator_type="redirect_parameter",
                indicator_value_or_reference=",".join(k for k, _ in redirect_targets),
                source_engine=cls.ENGINE_NAME,
                source_version=cls.ENGINE_VERSION,
                observation={"redirect_params": redirect_targets},
                reliability=0.80,
                confidence=0.85,
                correlation_group="open_redirect",
            )
            ev.append(e)

            fn.append(Finding(
                finding_code="FIND-URL-REDIRECT-PARAM",
                title="Suspicious External Redirect Parameter",
                description="URL query string contains parameters pointing to external addresses. Open redirect patterns are commonly used to disguise malicious destinations.",
                severity=Severity.MEDIUM,
                confidence=0.80,
                source_engine=cls.ENGINE_NAME,
                source_version=cls.ENGINE_VERSION,
                evidence_references=[e.evidence_id],
                correlation_group="open_redirect",
            ))

    @classmethod
    def _check_entropy_and_dga(cls, norm: NormalizedURL, ev: List[Evidence], fn: List[Finding]):
        """Calculates Shannon entropy to detect algorithmically generated domains (DGA)."""
        # Calculate entropy of domain without TLD
        parts = norm.hostname.split(".")
        if len(parts) >= 2:
            domain_label = parts[0]
            if len(domain_label) >= 12:
                entropy = cls._calculate_entropy(domain_label)
                if entropy >= 3.8:  # High randomness threshold for English/alphanumeric domains
                    e = Evidence(
                        indicator_type="high_entropy_domain",
                        indicator_value_or_reference=f"entropy:{entropy:.2f}",
                        source_engine=cls.ENGINE_NAME,
                        source_version=cls.ENGINE_VERSION,
                        observation={"domain_label": domain_label, "entropy": round(entropy, 2)},
                        reliability=0.75,
                        confidence=0.70,
                        correlation_group="dga_domain",
                    )
                    ev.append(e)

                    fn.append(Finding(
                        finding_code="FIND-URL-HIGH-ENTROPY",
                        title="High Entropy / Potential DGA Domain",
                        description=f"Domain label '{domain_label}' exhibits unusually high Shannon entropy ({entropy:.2f}), suggesting automated or algorithmic domain generation.",
                        severity=Severity.LOW,
                        confidence=0.70,
                        source_engine=cls.ENGINE_NAME,
                        source_version=cls.ENGINE_VERSION,
                        evidence_references=[e.evidence_id],
                        correlation_group="dga_domain",
                    ))

    @staticmethod
    def _calculate_entropy(text: str) -> float:
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = -sum(p * math.log2(p) for p in prob)
        return entropy
