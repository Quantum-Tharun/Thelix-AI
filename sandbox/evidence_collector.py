"""
Sandbox Evidence Collector
Normalizes runtime observations from isolated browser / HTTP worker execution into Evidence and Findings.
"""
from typing import Dict, Any, List, Tuple
from urllib.parse import urlsplit
import re

from risk_engine.evidence import Evidence, Finding, Severity


class SandboxEvidenceCollector:
    """
    Transforms raw browser inspection DOM & network observations into normalized Evidence & Findings.
    """
    SOURCE_ENGINE = "isolated_sandbox"
    SOURCE_VERSION = "1.0.0"

    @classmethod
    def collect(
        cls,
        initial_url: str,
        inspection_data: Dict[str, Any]
    ) -> Tuple[List[Evidence], List[Finding]]:
        """
        Parses inspection telemetry and returns (evidence_list, findings_list).
        """
        evidence_list: List[Evidence] = []
        findings_list: List[Finding] = []

        final_url = inspection_data.get("final_url", initial_url)
        redirects = inspection_data.get("redirect_chain", [])
        status_code = inspection_data.get("status_code", 0)
        forms = inspection_data.get("forms", [])
        page_title = inspection_data.get("page_title", "")
        headers = inspection_data.get("headers", {})

        # 1. Inspect Redirect Chains
        if len(redirects) > 1:
            initial_host = urlsplit(initial_url).hostname
            final_host = urlsplit(final_url).hostname
            is_cross_domain = initial_host != final_host

            ev_redirect = Evidence(
                indicator_type="redirect_chain",
                indicator_value_or_reference=f"hops:{len(redirects)}",
                source_engine=cls.SOURCE_ENGINE,
                source_version=cls.SOURCE_VERSION,
                observation={
                    "hops": redirects,
                    "initial_url": initial_url,
                    "final_url": final_url,
                    "is_cross_domain": is_cross_domain,
                },
                reliability=0.95,
                confidence=0.90,
                correlation_group="redirect_evasion",
            )
            evidence_list.append(ev_redirect)

            if is_cross_domain:
                findings_list.append(Finding(
                    finding_code="FIND-DOM-CROSS-DOMAIN-REDIRECT",
                    title="Cross-Domain Redirect Observed",
                    description=f"Destination redirected across domains from '{initial_host}' to '{final_host}'. Phishing campaigns often use redirects to evade static filters.",
                    severity=Severity.MEDIUM,
                    confidence=0.85,
                    source_engine=cls.SOURCE_ENGINE,
                    source_version=cls.SOURCE_VERSION,
                    evidence_references=[ev_redirect.evidence_id],
                    correlation_group="redirect_evasion",
                ))

        # 2. Inspect Forms for Credential Harvesting
        has_password_field = False
        external_action_found = False

        for form in forms:
            if form.get("has_password"):
                has_password_field = True
            action = form.get("action", "")
            if action.startswith("http://") or action.startswith("https://"):
                action_host = urlsplit(action).hostname
                final_host = urlsplit(final_url).hostname
                if action_host and action_host != final_host:
                    external_action_found = True

        if has_password_field:
            ev_form = Evidence(
                indicator_type="login_form_detected",
                indicator_value_or_reference="password_input_field",
                source_engine=cls.SOURCE_ENGINE,
                source_version=cls.SOURCE_VERSION,
                observation={"forms_count": len(forms), "external_action": external_action_found},
                reliability=0.95,
                confidence=0.95,
                correlation_group="credential_harvesting",
            )
            evidence_list.append(ev_form)

            if external_action_found:
                findings_list.append(Finding(
                    finding_code="FIND-DOM-SUSPICIOUS-FORM-ACTION",
                    title="Credential Form Submitting to External Domain",
                    description="The inspected page contains a password input form that submits credentials to an external destination. Strong indicator of credential theft.",
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    source_engine=cls.SOURCE_ENGINE,
                    source_version=cls.SOURCE_VERSION,
                    evidence_references=[ev_form.evidence_id],
                    correlation_group="credential_harvesting",
                ))
            else:
                findings_list.append(Finding(
                    finding_code="FIND-DOM-LOGIN-FORM",
                    title="Authentication / Login Form Detected",
                    description="Inspected page renders an interactive credential entry form.",
                    severity=Severity.INFO,
                    confidence=0.90,
                    source_engine=cls.SOURCE_ENGINE,
                    source_version=cls.SOURCE_VERSION,
                    evidence_references=[ev_form.evidence_id],
                    correlation_group="credential_harvesting",
                ))

        # 3. Security Headers Evaluation
        lower_headers = {k.lower(): v for k, v in headers.items()}
        has_hsts = "strict-transport-security" in lower_headers
        has_csp = "content-security-policy" in lower_headers

        if final_url.startswith("https://") and not has_hsts:
            ev_hsts = Evidence(
                indicator_type="missing_hsts",
                indicator_value_or_reference="strict-transport-security",
                source_engine=cls.SOURCE_ENGINE,
                source_version=cls.SOURCE_VERSION,
                observation={"final_url": final_url},
                reliability=0.85,
                confidence=0.80,
                correlation_group="security_headers",
            )
            evidence_list.append(ev_hsts)

        return evidence_list, findings_list
