"""
abuseipdb.py -- AbuseIPDB v2 enrichment provider.
Docs: https://docs.abuseipdb.com/#check-endpoint

Returns full detail block including ISP, domain, usageType, isTor,
isWhitelisted, numDistinctUsers, totalReports, lastReportedAt.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone

from src.http_client import build_session
from src.models import EnrichmentResult, ProviderStatus, Verdict

logger = logging.getLogger(__name__)

_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
_LINK_BASE = "https://www.abuseipdb.com/check/{ip}"


def enrich(ioc: str) -> EnrichmentResult:
    """Query AbuseIPDB for IP abuse data. Read-only."""
    queried_at = datetime.now(tz=timezone.utc).isoformat()
    result = EnrichmentResult(
        source="AbuseIPDB",
        enrichment_queried_at=queried_at,
        data={"raw_link": _LINK_BASE.format(ip=ioc)}
    )

    api_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    if not api_key:
        result.provider_status = ProviderStatus.SKIPPED.value
        result.error = "ABUSEIPDB_API_KEY not configured"
        return result

    session = build_session(retries=1, backoff_factor=1.0,
                            retry_statuses=(429, 500, 502, 503, 504))
    try:
        resp = session.get(
            _CHECK_URL,
            headers={
                "Key": api_key,
                "Accept": "application/json",
                "User-Agent": "SOC-IOC-Tool/1.0",
            },
            params={"ipAddress": ioc, "maxAgeInDays": "90", "verbose": ""},
            timeout=15,
        )
    except Exception as exc:
        import requests
        result.provider_status = ProviderStatus.ERROR.value
        if isinstance(exc, requests.exceptions.Timeout):
            result.error = "AbuseIPDB request timed out"
        else:
            result.error = f"AbuseIPDB network error: {type(exc).__name__}"
        return result

    if resp.status_code in (401, 403):
        result.provider_status = ProviderStatus.UNAUTHORIZED.value
        result.error = f"AbuseIPDB auth failed (HTTP {resp.status_code})"
        return result
    if resp.status_code == 429:
        result.provider_status = ProviderStatus.RATE_LIMITED.value
        result.error = "AbuseIPDB rate limit hit (HTTP 429)"
        return result
    if not resp.ok:
        if resp.status_code == 422:
            result.provider_status = ProviderStatus.SKIPPED.value
            result.error = "Invalid IP format for AbuseIPDB"
            return result
        result.provider_status = ProviderStatus.ERROR.value
        result.error = f"AbuseIPDB API error (HTTP {resp.status_code})"
        return result

    try:
        body = resp.json()
    except Exception:
        result.provider_status = ProviderStatus.ERROR.value
        result.error = "AbuseIPDB: invalid JSON response"
        return result

    data = body.get("data", {})
    if not data:
        result.provider_status = ProviderStatus.NO_MATCH.value
        return result

    # -- Core fields --
    conf = float(data.get("abuseConfidenceScore") or 0)
    total_reports = int(data.get("totalReports") or 0)

    result.confidence        = conf
    result.malicious_count   = total_reports
    result.data["total_reports"]     = total_reports
    result.data["num_distinct_users"] = int(data.get("numDistinctUsers") or 0)
    result.data["country"]           = data.get("countryCode")
    result.data["isp"]               = data.get("isp")
    result.data["domain"]            = data.get("domain")
    result.data["usage_type"]        = data.get("usageType")
    result.data["is_tor"]            = bool(data.get("isTor"))
    result.data["is_whitelisted"]    = bool(data.get("isWhitelisted"))
    
    result.last_observed         = data.get("lastReportedAt")

    # Tags from usage info
    tags: list[str] = []
    if data.get("usageType"):
        tags.append(str(data["usageType"]).lower().replace(" ", "_"))
    if data.get("isTor"):
        tags.append("tor")
    if data.get("isWhitelisted"):
        tags.append("whitelisted")
    result.data["tags"] = tags[:10]

    # -- Verdict based on confidence score --
    if total_reports == 0:
        result.verdict = Verdict.BENIGN.value
        result.provider_status = ProviderStatus.NO_MATCH.value
        return result

    if conf >= 80 or (conf >= 50 and total_reports >= 10):
        result.verdict = Verdict.MALICIOUS.value
    elif conf >= 25 or total_reports >= 3:
        result.verdict = Verdict.SUSPICIOUS.value
    else:
        result.verdict = Verdict.UNKNOWN.value

    result.provider_status = ProviderStatus.MATCHED.value
    return result
