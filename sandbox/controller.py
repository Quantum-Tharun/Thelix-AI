"""
Sandbox Controller
Coordinates isolated inspection runs, enforces boundary safety, handles worker crashes/timeouts,
and returns normalized Evidence and Findings.
"""
from typing import Tuple, List, Dict, Any, Optional
import logging

import ipaddress
from urllib.parse import urlsplit
from sandbox.browser_worker import BrowserWorker
from sandbox.evidence_collector import SandboxEvidenceCollector
from sandbox.resource_limits import ResourceLimits
from sandbox.target_validator import TargetValidator
from sandbox.network_policy import CLOUD_METADATA_HOSTS, CLOUD_METADATA_IPS
from risk_engine.evidence import Evidence, Finding, Severity
from risk_engine.exceptions import (
    TargetProhibitedException,
    EngineTimeoutException,
    RiskEngineException,
)

from app.config import settings

logger = logging.getLogger("thelix.sandbox_controller")


class SandboxController:
    """
    Supervises sandbox worker lifecycle and translates inspection results into engine evidence.
    """

    def __init__(self, limits: Optional[ResourceLimits] = None):
        self.limits = limits or ResourceLimits()
        self.worker = BrowserWorker(limits=self.limits)

    async def inspect_target(
        self,
        url: str
    ) -> Tuple[List[Evidence], List[Finding], Dict[str, Any]]:
        """
        Runs isolated website inspection safely.
        Guarantees that errors or prohibited destinations fail safely without crashing callers.
        Returns (evidence_list, findings_list, metadata).
        """
        evidence_list: List[Evidence] = []
        findings_list: List[Finding] = []
        meta: Dict[str, Any] = {
            "completed": False,
            "blocked": False,
            "timeout": False,
            "disabled_by_policy": False,
            "error": None,
        }

        # 1. Pre-flight check for immediate prohibited targets (IP literals, cloud metadata endpoints)
        try:
            parsed = urlsplit(url)
            host = parsed.hostname or ""
        except Exception:
            host = ""

        is_metadata_or_ip = False
        if host in CLOUD_METADATA_HOSTS or host in CLOUD_METADATA_IPS:
            is_metadata_or_ip = True
        else:
            try:
                ipaddress.ip_address(host.strip("[]"))
                is_metadata_or_ip = True
            except ValueError:
                pass

        if is_metadata_or_ip:
            is_valid, reason, resolved_ips = TargetValidator.validate_target(url)
            if not is_valid:
                logger.warning(f"Sandbox inspection prohibited for target '{url}': {reason}")
                meta["blocked"] = True
                meta["error"] = reason

                ev_prohibited = Evidence(
                    indicator_type="prohibited_target_attempt",
                    indicator_value_or_reference=url,
                    source_engine="sandbox_controller",
                    source_version="1.0.0",
                    observation={"target_url": url, "resolved_ips": resolved_ips, "reason": reason},
                    reliability=1.0,
                    confidence=1.0,
                    correlation_group="network_policy_violation",
                )
                evidence_list.append(ev_prohibited)

                findings_list.append(Finding(
                    finding_code="FIND-NET-TARGET-PROHIBITED",
                    title="Prohibited Network Target / SSRF Attempt",
                    description=f"Target destination was rejected by network isolation policy: {reason}",
                    severity=Severity.CRITICAL,
                    confidence=1.0,
                    source_engine="sandbox_controller",
                    source_version="1.0.0",
                    evidence_references=[ev_prohibited.evidence_id],
                    correlation_group="network_policy_violation",
                ))
                return evidence_list, findings_list, meta

        # 2. Safe fail-closed check if live network inspection is disabled
        if not settings.SAFE_LOCAL_SANDBOX_ENABLED:
            logger.info(f"Live inspection skipped for '{url}': SAFE_LOCAL_SANDBOX_ENABLED is False")
            meta["disabled_by_policy"] = True
            meta["error"] = "Live website inspection disabled: host environment lacks OS-level network isolation (fail-closed policy). Static analysis performed."
            return evidence_list, findings_list, meta

        try:
            inspection_data = await self.worker.inspect(url)
            ev, fn = SandboxEvidenceCollector.collect(url, inspection_data)
            evidence_list.extend(ev)
            findings_list.extend(fn)

            # Check if subresource SSRF attempts were intercepted
            for sub in inspection_data.get("blocked_subresources", []):
                ev_sub = Evidence(
                    indicator_type="prohibited_subresource_attempt",
                    indicator_value_or_reference=sub.get("url", ""),
                    source_engine="sandbox_subresource_interceptor",
                    source_version="1.0.0",
                    observation=sub,
                    reliability=1.0,
                    confidence=1.0,
                    correlation_group="network_policy_violation",
                )
                evidence_list.append(ev_sub)
                findings_list.append(Finding(
                    finding_code="FIND-NET-SUBRESOURCE-BLOCKED",
                    title="Prohibited Subresource / SSRF Attempt Intercepted",
                    description=f"Inspected page attempted to load prohibited subresource: {sub.get('reason', 'Blocked by policy')}",
                    severity=Severity.HIGH,
                    confidence=1.0,
                    source_engine="sandbox_subresource_interceptor",
                    source_version="1.0.0",
                    evidence_references=[ev_sub.evidence_id],
                    correlation_group="network_policy_violation",
                ))

            meta["completed"] = True
            meta["inspection"] = {
                "final_url": inspection_data.get("final_url"),
                "status_code": inspection_data.get("status_code"),
                "redirect_hops": len(inspection_data.get("redirect_chain", [])),
                "blocked_subresources_count": len(inspection_data.get("blocked_subresources", [])),
                "engine": inspection_data.get("engine", "unknown"),
            }

        except TargetProhibitedException as e:
            logger.warning(f"Sandbox inspection prohibited for target '{url}': {e.message}")
            meta["blocked"] = True
            meta["error"] = e.message

            # Record security finding for attempted SSRF or prohibited destination
            ev_prohibited = Evidence(
                indicator_type="prohibited_target_attempt",
                indicator_value_or_reference=url,
                source_engine="sandbox_controller",
                source_version="1.0.0",
                observation=e.details,
                reliability=1.0,
                confidence=1.0,
                correlation_group="network_policy_violation",
            )
            evidence_list.append(ev_prohibited)

            findings_list.append(Finding(
                finding_code="FIND-NET-TARGET-PROHIBITED",
                title="Prohibited Network Target / SSRF Attempt",
                description=f"Target destination was rejected by network isolation policy: {e.message}",
                severity=Severity.CRITICAL,
                confidence=1.0,
                source_engine="sandbox_controller",
                source_version="1.0.0",
                evidence_references=[ev_prohibited.evidence_id],
                correlation_group="network_policy_violation",
            ))
        except EngineTimeoutException as e:
            logger.warning(f"Sandbox inspection timed out for '{url}': {e.message}")
            meta["timeout"] = True
            meta["error"] = e.message
        except Exception as e:
            logger.error(f"Unexpected error during sandbox inspection of '{url}': {e}")
            meta["error"] = str(e)

        return evidence_list, findings_list, meta
