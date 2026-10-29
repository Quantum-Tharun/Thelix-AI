"""
DEPRECATED — Legacy Risk Engine Stub
This module is superseded by the authoritative 'risk_engine' package:
- risk_engine.scoring.ScoringEngine (deterministic non-linear aggregation and severity floors)
- risk_engine.policy.PolicyEngine (governance decision rules)
- risk_engine.evidence_aggregator.EvidenceAggregator (evidence deduplication)

Preserved for backward-compatible symbol imports; all score calculations delegate
to the authoritative ScoringEngine.
"""
import warnings
from typing import List, Dict, Any, Tuple
from risk_engine.evidence import Finding, Severity, RiskLevel
from risk_engine.scoring import ScoringEngine


class RiskEngine:
    """
    Deprecated legacy scoring stub.
    Delegates to the authoritative risk_engine.scoring.ScoringEngine.
    """
    POLICY_VERSION = ScoringEngine.POLICY_VERSION

    # Retained for backward-compatibility with any legacy imports
    SAFE_BROWSING_MALWARE = 80
    VIRUSTOTAL_HIGH = 90
    NEW_DOMAIN = 40
    SUSPICIOUS_TLD = 20
    URGENCY_KEYWORD = 30
    FINANCIAL_KEYWORD = 20
    GREETING_MISMATCH = 15
    FAKE_LOGIN_UI = 75
    OBFUSCATED_TEXT = 40

    @classmethod
    def calculate_score(cls, evidence: Dict[str, Any]) -> Tuple[int, int, str, List[str]]:
        """
        Parses evidence dictionary, constructs atomic findings, and calculates
        authoritative scores via ScoringEngine.
        Returns: (trust_score, risk_score, threat_level, reasons)
        """
        warnings.warn(
            "app.ai.risk.engine.RiskEngine is deprecated. Use risk_engine.engine.RiskEngine or ScoringEngine.",
            DeprecationWarning,
            stacklevel=2,
        )

        findings: List[Finding] = []
        reasons: List[str] = []

        url_threats = evidence.get("url_threats", [])
        if "Safe Browsing match" in url_threats:
            findings.append(Finding(
                finding_code="FIND-REP-SAFEBROWSING-MALICIOUS",
                title="Safe Browsing match (Malware/Phishing)",
                description="Target flagged by Google Safe Browsing",
                severity=Severity.CRITICAL,
                confidence=1.0,
                source_engine="safebrowsing",
                source_version="v4",
            ))
            reasons.append("Safe Browsing match (Malware/Phishing)")

        if "Newly registered domain" in url_threats:
            findings.append(Finding(
                finding_code="FIND-STATIC-NEW-DOMAIN",
                title="Newly registered domain (< 30 days)",
                description="Domain registered recently",
                severity=Severity.MEDIUM,
                confidence=0.8,
                source_engine="static_analyzer",
                source_version="1.0.0",
            ))
            reasons.append("Newly registered domain (< 30 days)")

        ui_match = str(evidence.get("ui_match", ""))
        if "fake" in ui_match.lower():
            findings.append(Finding(
                finding_code="FIND-UI-FAKE-LOGIN",
                title="Fake Login UI matched",
                description="Visual patterns match known fake login template",
                severity=Severity.HIGH,
                confidence=0.9,
                source_engine="screenshot_analyzer",
                source_version="1.0.0",
            ))
            reasons.append("Fake Login UI matched")

        ocr_text = str(evidence.get("ocr_text", "")).lower()
        if any(w in ocr_text for w in ("immediately", "suspended", "urgent")):
            findings.append(Finding(
                finding_code="FIND-TXT-URGENT-LURE",
                title="Urgent scam language detected in text",
                description="High-urgency language detected in extracted content",
                severity=Severity.MEDIUM,
                confidence=0.75,
                source_engine="scam_nlp",
                source_version="1.0.0",
            ))
            reasons.append("Urgent scam language detected in text")

        if any(w in ocr_text for w in ("crypto", "bitcoin", "transfer", "wire")):
            findings.append(Finding(
                finding_code="FIND-TXT-FINANCIAL-LURE",
                title="Financial scam language detected in text",
                description="Financial lure keywords detected in extracted content",
                severity=Severity.MEDIUM,
                confidence=0.7,
                source_engine="scam_nlp",
                source_version="1.0.0",
            ))
            reasons.append("Financial scam language detected in text")

        risk_score, trust_score, risk_level, _ = ScoringEngine.calculate_score(findings)
        threat_level = risk_level.value.capitalize()

        return trust_score, risk_score, threat_level, reasons
