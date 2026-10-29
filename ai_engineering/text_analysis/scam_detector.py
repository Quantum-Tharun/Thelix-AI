"""
Deterministic Suspicious Message & Scam Text Detector
Identifies credential harvesting lures, payment/crypto coercion, urgency triggers,
remote access lures, brand mismatches, and adversarial prompt injection patterns.
"""
import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple, Set

from risk_engine.evidence import Evidence, Finding, Severity

logger = logging.getLogger("thelix.scam_detector")


@dataclass
class ScamIndicatorPattern:
    rule_id: str
    finding_code: str
    title: str
    severity: Severity
    base_confidence: float
    regex_patterns: List[str]
    description_template: str
    correlation_group: str


# High-precision contextual regex patterns for social engineering indicators
SCAM_RULES: List[ScamIndicatorPattern] = [
    ScamIndicatorPattern(
        rule_id="RULE-SCAM-CREDENTIAL-LURE",
        finding_code="FIND-SCAM-CREDENTIAL-LURE",
        title="Credential Harvesting / Sensitive Code Request",
        severity=Severity.HIGH,
        base_confidence=0.85,
        regex_patterns=[
            r"(?:enter|provide|confirm|verify|submit|send)\s+(?:your\s+)?(?:[a-z0-9\s,-]{0,35})?(?:password|passcode|security\s+pin|banking\s+pin|direct\s+deposit|ssn|social\s+security)",
            r"(?:enter|provide|send|submit|reply\s+with)\s+(?:your\s+)?(?:one-time\s+password|otp|6-digit\s+code|verification\s+code)",
            r"(?<!never\s)(?<!do\snot\s)\b(?:share|send|provide)\s+(?:this\s+code|your\s+otp|your\s+password)",
            r"(?:login|sign-in)\s+(?:credentials|details|information)\s+(?:required|needed|to\s+restore)",
            r"(?:social\s+security\s+number|ssn\b)",
        ],
        description_template="Message solicits passwords, OTP codes, or secret credentials: '{excerpt}'",
        correlation_group="scam_credential_theft",
    ),
    ScamIndicatorPattern(
        rule_id="RULE-SCAM-PAYMENT-CRYPTO",
        finding_code="FIND-SCAM-PAYMENT-MANIPULATION",
        title="Coerced Payment / Gift Card / Cryptocurrency Demand",
        severity=Severity.HIGH,
        base_confidence=0.85,
        regex_patterns=[
            r"(?:pay|purchase|send|buy)\s+(?:via|with|using)?\s*(?:[a-z0-9\s,-]{0,25})?(?:apple|google\s+play|steam|amazon|vanilla)\s+gift\s*cards?",
            r"(?:send|transfer|pay|deposit)\s+(?:\$[\d,]+\s+in\s+)?(?:bitcoin|btc|eth|ethereum|cryptocurrency|crypto)",
            r"(?:bitcoin|btc|eth|cryptocurrency|crypto)\s+(?:wallet|address|transfer|payment)",
            r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b",
            r"(?:wire\s+transfer|western\s+union|moneygram)\s+(?:immediately|urgently|required)",
            r"(?:refund|reimbursement)\s+overpayment\s+scam",
            r"(?:compromised|recorded|hacked)\s+(?:your\s+)?(?:webcam|camera|video)",
            r"(?:unclaimed\s+tax\s+refund|irs\s+refund)",
            r"(?:pay\s+by\s+(?:credit\s+)?card|click\s+(?:the\s+link\s+below|here)\s+to\s+pay)",
            r"(?:invoice\s*#?[a-z0-9\-]+.*amount\s+due:\s*\$[\d,]+)",
        ],
        description_template="Message demands unconventional or irreversible payment (gift card/crypto/wire/card lure): '{excerpt}'",
        correlation_group="scam_financial_fraud",
    ),
    ScamIndicatorPattern(
        rule_id="RULE-SCAM-URGENCY-COERCION",
        finding_code="FIND-SCAM-URGENCY-COERCION",
        title="Artificial Urgency & Coercive Threat Lure",
        severity=Severity.MEDIUM,
        base_confidence=0.75,
        regex_patterns=[
            r"(?:account|service|access)\s+(?:will\s+be\s+)?(?:suspended|terminated|closed|locked)\s+within\s+(?:\d+\s+hours?|immediately|24h)",
            r"(?:legal\s+action|lawsuit|warrant|arrest|police|irs\s+agent)\s+(?:will\s+be\s+taken|issued|contacted)",
            r"(?:immediate\s+action\s+required|urgent\s+notice|final\s+warning)\b",
            r"(?:act\s+now|respond\s+within\s+\d+\s+minutes?)\s+to\s+avoid",
            r"(?:scratch\s+off\s+the\s+backs?|reply\s+with\s+the\s+pin\s+numbers?)",
            r"(?:release\s+everything\s+to\s+your\s+contacts|personal\s+files\s+will\s+be\s+destroyed)",
            r"(?:call|contact)\s+(?:[0-9\s+()-]{7,20}|support|us|helpdesk)\s+immediately",
        ],
        description_template="Message manufactures extreme urgency or legal coercion: '{excerpt}'",
        correlation_group="scam_urgency_pressure",
    ),
    ScamIndicatorPattern(
        rule_id="RULE-SCAM-REMOTE-ACCESS",
        finding_code="FIND-SCAM-REMOTE-ACCESS",
        title="Remote Access Software Installation Lure",
        severity=Severity.HIGH,
        base_confidence=0.85,
        regex_patterns=[
            r"(?:install|download|run|open)\s+(?:anydesk|teamviewer|quick\s*assist|screenconnect|zoho\s*assist)",
            r"(?:allow|grant)\s+(?:remote\s+access|screen\s+sharing)\s+to\s+(?:support|technician|representative)",
            r"(?:call\s+support\s+to\s+connect|remote\s+support\s+session)",
        ],
        description_template="Message instructs user to install remote management software: '{excerpt}'",
        correlation_group="scam_remote_access",
    ),
    ScamIndicatorPattern(
        rule_id="RULE-SCAM-ACCOUNT-LURE",
        finding_code="FIND-SCAM-ACCOUNT-LURE",
        title="Suspicious Account Security / Unauthorized Activity Alert",
        severity=Severity.MEDIUM,
        base_confidence=0.70,
        regex_patterns=[
            r"(?:unauthorized|suspicious|fraudulent|did\s+not\s+authorize|unrecognized|dispute\s+this)\s+(?:this\s+)?(?:login|activity|transaction|charge|purchase|renewal|debit)",
            r"(?:your\s+account\s+has\s+been\s+restricted|account\s+temporarily\s+locked)",
            r"(?:verify\s+your\s+identity|update\s+billing\s+information)\s+to\s+unlock",
            r"(?:auto-renewal|auto\s+renew|subscription\s+renewed|debited\s+from\s+(?:your\s+)?(?:checking|account|bank))",
        ],
        description_template="Message claims account compromise or unauthorized charge to lure user action: '{excerpt}'",
        correlation_group="scam_account_lure",
    ),
    ScamIndicatorPattern(
        rule_id="RULE-SCAM-PROMPT-INJECTION",
        finding_code="FIND-SCAM-PROMPT-INJECTION-ATTEMPT",
        title="Adversarial Prompt-Injection Sequence Detected",
        severity=Severity.HIGH,
        base_confidence=0.90,
        regex_patterns=[
            r"(?:ignore|disregard|bypass|override)\s+(?:all\s+)?(?:[a-z\s]{0,20})?(?:instructions|rules|policies|filters|prompts?)",
            r"(?:you\s+are\s+now\s+in\s+developer\s+(?:sandbox\s+)?mode|without\s+restrictions|unrestricted\s+ai|jailbreak\s+mode|roleplay\s+mode)",
            r"(?:classify|report|mark|evaluate)\s+(?:this\s+)?(?:content|message|target|url|file)?\s*as\s+(?:[a-z0-9\s]{0,20})?(?:safe|clean|benign)",
            r"(?:\[system\s+prompt\]|system\s+prompt\s*:|output\s+safe|set\s+risk_score\s+to\s+0|verdict\s+to\s+allow|trust\s+score\s+100)",
        ],
        description_template="Content contains adversarial prompt injection attempting to manipulate AI: '{excerpt}'",
        correlation_group="adversarial_evasion",
    ),
]

# Targeted organizations frequently impersonated in lure texts
KNOWN_IMPERSONATION_TARGETS = {
    "paypal": ["paypal.com"],
    "chase": ["chase.com"],
    "bank of america": ["bankofamerica.com"],
    "wells fargo": ["wellsfargo.com"],
    "apple": ["apple.com", "icloud.com"],
    "microsoft": ["microsoft.com", "microsoftonline.com", "live.com"],
    "amazon": ["amazon.com"],
    "netflix": ["netflix.com"],
    "usps": ["usps.com"],
    "fedex": ["fedex.com"],
    "dhl": ["dhl.com"],
    "geek squad": ["bestbuy.com"],
}


class ScamTextDetector:
    """
    Deterministic rule engine evaluating extracted text messages against social engineering indicators.
    """
    ENGINE_NAME = "thelix_scam_text_detector"
    ENGINE_VERSION = "1.0.0"

    @classmethod
    def analyze_text(
        cls,
        text: Optional[str],
        associated_urls: Optional[List[str]] = None
    ) -> Tuple[List[Evidence], List[Finding]]:
        """
        Scans text for scam indicators and validates against associated URLs.
        Returns (evidence_list, findings_list).
        """
        evidence_list: List[Evidence] = []
        findings_list: List[Finding] = []

        if not text or not isinstance(text, str):
            return evidence_list, findings_list

        clean_text = text.strip()
        if not clean_text:
            return evidence_list, findings_list

        # 1. Evaluate Rule Patterns
        for rule in SCAM_RULES:
            matched_excerpts = []
            for pattern_str in rule.regex_patterns:
                matches = re.finditer(pattern_str, clean_text, re.IGNORECASE)
                for m in matches:
                    matched_excerpts.append(m.group(0))

            if matched_excerpts:
                # Deduplicate excerpts
                unique_excerpts = list(dict.fromkeys(matched_excerpts))
                safe_excerpt = "; ".join(unique_excerpts)[:150]

                ev = Evidence(
                    indicator_type=f"text_indicator_{rule.finding_code.lower()}",
                    indicator_value_or_reference=safe_excerpt,
                    source_engine=cls.ENGINE_NAME,
                    source_version=cls.ENGINE_VERSION,
                    observation={
                        "rule_id": rule.rule_id,
                        "matches_count": len(matched_excerpts),
                        "excerpts": unique_excerpts[:5],
                    },
                    reliability=0.88,
                    confidence=rule.base_confidence,
                    correlation_group=rule.correlation_group,
                )
                evidence_list.append(ev)

                findings_list.append(Finding(
                    finding_code=rule.finding_code,
                    title=rule.title,
                    description=rule.description_template.format(excerpt=safe_excerpt),
                    severity=rule.severity,
                    confidence=rule.base_confidence,
                    source_engine=cls.ENGINE_NAME,
                    source_version=cls.ENGINE_VERSION,
                    evidence_references=[ev.evidence_id],
                    correlation_group=rule.correlation_group,
                ))

        # 2. Impersonation & URL Mismatch Check
        if associated_urls:
            cls._check_brand_url_mismatch(clean_text, associated_urls, evidence_list, findings_list)

        return evidence_list, findings_list

    @classmethod
    def _check_brand_url_mismatch(
        cls,
        text: str,
        urls: List[str],
        ev_list: List[Evidence],
        fn_list: List[Finding]
    ):
        """Detects if text claims to represent an organization whose domain does not match extracted URLs."""
        lower_text = text.lower()
        claimed_orgs: List[str] = []

        for org_name in KNOWN_IMPERSONATION_TARGETS:
            if re.search(r"\b" + re.escape(org_name) + r"\b", lower_text):
                claimed_orgs.append(org_name)

        if not claimed_orgs:
            return

        # Check if extracted URLs match claimed org domains
        for org in claimed_orgs:
            valid_domains = KNOWN_IMPERSONATION_TARGETS[org]
            has_matching_url = False
            suspicious_urls = []

            for u in urls:
                is_match = any(domain in u.lower() for domain in valid_domains)
                if is_match:
                    has_matching_url = True
                else:
                    suspicious_urls.append(u)

            # If message claims brand identity but links to completely unrelated external URLs
            if not has_matching_url and suspicious_urls:
                safe_sus = ", ".join(suspicious_urls[:3])
                ev = Evidence(
                    indicator_type="brand_url_mismatch",
                    indicator_value_or_reference=f"{org} -> {safe_sus}",
                    source_engine=cls.ENGINE_NAME,
                    source_version=cls.ENGINE_VERSION,
                    observation={
                        "claimed_org": org,
                        "valid_domains": valid_domains,
                        "unrelated_urls": suspicious_urls,
                    },
                    reliability=0.92,
                    confidence=0.85,
                    correlation_group="brand_impersonation",
                )
                ev_list.append(ev)

                fn_list.append(Finding(
                    finding_code="FIND-SCAM-BRAND-URL-MISMATCH",
                    title="Claimed Brand Identity Mismatches Extracted Destination",
                    description=f"Message claims to be from '{org.title()}', but contains unrelated destination link(s): '{safe_sus}'",
                    severity=Severity.HIGH,
                    confidence=0.85,
                    source_engine=cls.ENGINE_NAME,
                    source_version=cls.ENGINE_VERSION,
                    evidence_references=[ev.evidence_id],
                    correlation_group="brand_impersonation",
                ))
