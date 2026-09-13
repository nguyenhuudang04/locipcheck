"""
analyst_summary.py -- SOC Analyst Summary generator.

Produces structured, analyst-readable summaries without making
conclusive compromised/not-compromised judgments on reputation alone.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from src.models import AlertContext, EnrichmentResult, IOCReport, ProviderStatus, RiskScore, Verdict


@dataclass
class AnalystSummary:
    """Structured summary for the SOC analyst display."""
    ioc_reputation_risk:    int   = 0
    ioc_risk_level:         str   = "LOW"
    incident_severity:      str   = "UNDETERMINED"
    
    executive_assessment:     str = ""
    why_this_ioc_is_risky:    list[str] = field(default_factory=list)
    threat_intelligence:      list[str] = field(default_factory=list)
    infrastructure:           list[str] = field(default_factory=list)
    recommended_containment:  list[str] = field(default_factory=list)
    recommended_telemetry:    list[str] = field(default_factory=list)
    escalation_conditions:    list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "ioc_reputation_risk":     self.ioc_reputation_risk,
            "ioc_risk_level":          self.ioc_risk_level,
            "incident_severity":       self.incident_severity,
            "executive_assessment":    self.executive_assessment,
            "why_this_ioc_is_risky":   self.why_this_ioc_is_risky,
            "threat_intelligence":     self.threat_intelligence,
            "infrastructure":          self.infrastructure,
            "recommended_containment": self.recommended_containment,
            "recommended_telemetry":   self.recommended_telemetry,
            "escalation_conditions":   self.escalation_conditions,
        }


def build_summary(
    report: IOCReport,
    alert_ctx: Optional[AlertContext] = None,
) -> AnalystSummary:
    """Build a structured SOC Analyst Summary from an IOC report."""
    summary = AnalystSummary()
    risk: Optional[RiskScore] = report.risk
    results = report.results

    # ── IOC Reputation Risk ──────────────────────────────────────────
    if risk:
        summary.ioc_reputation_risk = risk.score
        summary.ioc_risk_level      = risk.level

    # ── Incident Severity (requires Alert Context) ────────────────────
    is_malicious = (summary.ioc_reputation_risk >= 50)
    
    if alert_ctx is None or alert_ctx.is_empty():
        summary.incident_severity = "UNDETERMINED"
    else:
        # Evaluate Incident Severity
        action = (alert_ctx.action or "").lower()
        has_execution = bool(alert_ctx.process_name or alert_ctx.command_line)
        has_connection = bool(alert_ctx.source_ip or alert_ctx.destination)
        is_allowed = action in ("allowed", "permit", "accept", "success")
        is_blocked = action in ("blocked", "deny", "drop", "reset", "failed")
        
        if is_malicious and has_execution:
            summary.incident_severity = "CRITICAL"
        elif is_malicious and is_allowed and has_connection:
            summary.incident_severity = "HIGH"
        elif is_malicious and is_blocked:
            summary.incident_severity = "MEDIUM"
        elif not is_malicious and is_blocked:
            summary.incident_severity = "LOW"
        else:
            summary.incident_severity = "LOW"
            
    # ── Executive Assessment ──────────────────────────────────────────
    if summary.incident_severity == "UNDETERMINED":
        summary.executive_assessment = (
            "Without internal alert context, the incident severity cannot be determined. "
            f"The IOC reputation is currently assessed as {summary.ioc_risk_level} based on external threat intelligence."
        )
    elif summary.incident_severity in ("HIGH", "CRITICAL"):
        summary.executive_assessment = (
            f"HIGH LIKELIHOOD OF COMPROMISE. Internal telemetry indicates successful interaction "
            f"with a {summary.ioc_risk_level}-risk indicator. Immediate containment is recommended."
        )
    elif summary.incident_severity == "MEDIUM":
        summary.executive_assessment = (
            f"POTENTIAL THREAT MITIGATED. The {summary.ioc_risk_level}-risk indicator was blocked, "
            "but further investigation is needed to ensure no secondary payload was executed."
        )
    else:
        summary.executive_assessment = (
            "LOW RISK. Indicator interaction was blocked or the IOC has a low threat intelligence reputation. "
            "Monitor for repeated attempts."
        )

    # ── Why this IOC is risky ─────────────────────────────────────────
    if risk and risk.factors:
        for factor in risk.factors:
            if factor.points > 0:
                summary.why_this_ioc_is_risky.append(f"{factor.reason} (+{factor.points})")
    
    if not summary.why_this_ioc_is_risky:
        summary.why_this_ioc_is_risky.append("No significant risk factors identified by intelligence providers.")

    # ── Threat Intelligence Evidence ──────────────────────────────────
    malicious_sources = [r.source for r in results if r.verdict == Verdict.MALICIOUS.value]
    if malicious_sources:
        summary.threat_intelligence.append(f"Flagged as MALICIOUS by: {', '.join(malicious_sources)}.")
    
    suspicious_sources = [r.source for r in results if r.verdict == Verdict.SUSPICIOUS.value]
    if suspicious_sources:
        summary.threat_intelligence.append(f"Flagged as SUSPICIOUS by: {', '.join(suspicious_sources)}.")
        
    no_match_sources = [r.source for r in results if r.provider_status == ProviderStatus.NO_MATCH.value]
    if no_match_sources:
        summary.threat_intelligence.append(f"Not found in databases of: {', '.join(no_match_sources)}.")
        
    skipped_sources = [r.source for r in results if r.provider_status in (ProviderStatus.SKIPPED.value, ProviderStatus.UNAUTHORIZED.value)]
    if skipped_sources:
        summary.threat_intelligence.append(f"Queries skipped or unauthorised for: {', '.join(skipped_sources)}.")

    # ── Infrastructure ────────────────────────────────────────────────
    # We look for DNS/domain related fields in the results.data
    for r in results:
        if r.provider_status == ProviderStatus.MATCHED.value:
            if r.data.get("country"):
                summary.infrastructure.append(f"Country: {r.data['country']} (via {r.source})")
            if r.data.get("asn"):
                summary.infrastructure.append(f"ASN: {r.data['asn']} (via {r.source})")
            if r.data.get("registrar"):
                summary.infrastructure.append(f"Registrar: {r.data['registrar']} (via {r.source})")
            if r.data.get("resolved_ips"):
                summary.infrastructure.append(f"Resolves to IPs: {', '.join(r.data['resolved_ips'][:3])}")

    if not summary.infrastructure:
        summary.infrastructure.append("No notable infrastructure data found.")

    # ── Recommended Containment ───────────────────────────────────────
    if summary.incident_severity in ("HIGH", "CRITICAL"):
        summary.recommended_containment.extend([
            "Isolate the affected endpoint from the network immediately.",
            "Block the IOC at the network perimeter (Firewall/Web Proxy).",
            "Disable the compromised user account if credentials were submitted."
        ])
    else:
        summary.recommended_containment.extend([
            "Ensure the IOC is added to the relevant blocklists.",
            "No immediate endpoint isolation required based on current evidence."
        ])

    # ── Recommended Telemetry Checks ──────────────────────────────────
    if report.ioc_type in ("ipv4", "ipv6", "domain", "url"):
        summary.recommended_telemetry.extend([
            "Check proxy logs for HTTP/HTTPS requests.",
            "Check firewall logs for direct IP connections.",
            "Check DNS logs for resolution requests."
        ])
    elif report.ioc_type in ("md5", "sha1", "sha256"):
        summary.recommended_telemetry.extend([
            "Check EDR logs for file creation and execution.",
            "Check email gateways for attachments matching this hash."
        ])
        
    if alert_ctx and not alert_ctx.is_empty():
        if alert_ctx.action and alert_ctx.action.lower() in ("blocked", "deny"):
            summary.recommended_telemetry.append("Verify no related 'allowed' traffic occurred shortly before or after the blocked event.")

    # ── Escalation Conditions ─────────────────────────────────────────
    summary.escalation_conditions.extend([
        "Escalate to Tier 2 if internal connections to the IOC are established and data exfiltration is suspected.",
        "Escalate to Incident Response if malware execution is confirmed on an endpoint.",
        "Escalate to Management if the affected asset is business-critical."
    ])

    return summary
