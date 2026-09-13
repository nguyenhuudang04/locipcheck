"""
threatfox.py -- ThreatFox (abuse.ch) IOC lookup provider.
Docs: https://threatfox.abuse.ch/api/

Supports: IPv4, IPv6, Domain, URL, MD5, SHA1, SHA256
Uses search_ioc endpoint (READ-ONLY -- no submission).
Auth: shared abuse.ch Auth-Key (ABUSECH_AUTH_KEY).
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Optional

from src.http_client import build_session
from src.models import EnrichmentResult, ProviderStatus, Verdict

logger = logging.getLogger(__name__)

_API_URL   = "https://threatfox-api.abuse.ch/api/v1/"
_LINK_BASE = "https://threatfox.abuse.ch/ioc/"


def _get_key() -> str:
    for var in ("ABUSECH_AUTH_KEY", "THREATFOX_AUTH_KEY",
                "URLHAUS_AUTH_KEY", "MALWAREBAZAAR_AUTH_KEY"):
        val = os.getenv(var, "").strip()
        if val:
            return val
    return ""


def enrich(ioc: str, ioc_type: str) -> EnrichmentResult:
    """Search ThreatFox for existing IOC data. Never submits new IOCs."""
    queried_at = datetime.now(tz=timezone.utc).isoformat()
    result = EnrichmentResult(
        source="ThreatFox",
        enrichment_queried_at=queried_at,
        data={"raw_link": f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{ioc}"}
    )

    auth_key = _get_key()
    if not auth_key:
        result.provider_status = ProviderStatus.SKIPPED.value
        result.error = "ABUSECH_AUTH_KEY not configured"
        return result

    session = build_session(retries=1, backoff_factor=1.0,
                            retry_statuses=(429, 502, 503, 504))
    try:
        resp = session.post(
            _API_URL,
            headers={
                "Auth-Key": auth_key,
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "SOC-IOC-Tool/1.0",
            },
            json={"query": "search_ioc", "search_term": ioc},
            timeout=15,
        )
    except Exception as exc:
        import requests
        result.provider_status = ProviderStatus.ERROR.value
        if isinstance(exc, requests.exceptions.Timeout):
            result.error = "ThreatFox request timed out"
        else:
            result.error = f"ThreatFox network error: {type(exc).__name__}"
        return result

    if resp.status_code == 429:
        result.provider_status = ProviderStatus.RATE_LIMITED.value
        result.error = "ThreatFox rate limit hit (HTTP 429)"
        return result
    if resp.status_code in (401, 403):
        result.provider_status = ProviderStatus.UNAUTHORIZED.value
        result.error = f"ThreatFox auth failed (HTTP {resp.status_code})"
        return result
    if not resp.ok:
        result.provider_status = ProviderStatus.ERROR.value
        result.error = f"ThreatFox API error (HTTP {resp.status_code})"
        return result

    try:
        body = resp.json()
    except Exception:
        result.provider_status = ProviderStatus.ERROR.value
        result.error = "ThreatFox: invalid JSON response"
        return result

    query_status: str = body.get("query_status", "")
    data = body.get("data")

    # Auth failure via query_status
    if any(x in query_status.lower() for x in ("unauthorized", "invalid", "illegal")):
        result.provider_status = ProviderStatus.UNAUTHORIZED.value
        result.error = f"ThreatFox auth rejected: {query_status}"
        return result

    # Explicit no-results
    if query_status in ("no_results", "ok") and not data:
        result.provider_status = ProviderStatus.NO_MATCH.value
        result.verdict = Verdict.UNKNOWN.value
        return result

    if not isinstance(data, list) or not data:
        result.provider_status = ProviderStatus.NO_MATCH.value
        result.verdict = Verdict.UNKNOWN.value
        return result

    # Exact-match filter — ThreatFox uses substring matching
    ioc_lower = ioc.lower()
    exact_data = [
        e for e in data
        if str(e.get("ioc") or "").lower() == ioc_lower
        or str(e.get("ioc") or "").lower().startswith(ioc_lower + ":")
    ]
    if not exact_data:
        result.provider_status = ProviderStatus.NO_MATCH.value
        result.verdict = Verdict.UNKNOWN.value
        logger.info("ThreatFox: %d substring hits for '%s' but no exact match", len(data), ioc)
        return result

    data = exact_data

    # Aggregate across matching entries
    max_confidence: int = 0
    tags:          set[str] = set()
    threat_types:  set[str] = set()
    malware_names: set[str] = set()
    first_seen:    Optional[str] = None
    last_seen:     Optional[str] = None
    ioc_id:        Optional[str] = None
    malware_printable: Optional[str] = None
    threat_type:   Optional[str] = None
    ioc_type_det:  Optional[str] = None
    active_status: Optional[str] = None

    for entry in data:
        conf = int(entry.get("confidence_level") or 0)
        if conf > max_confidence:
            max_confidence = conf
            malware_printable = entry.get("malware_printable") or entry.get("malware")
            threat_type       = entry.get("threat_type")
            ioc_type_det      = entry.get("ioc_type")
            active_status     = entry.get("ioc_status") # Can be 'active', 'offline', 'unknown'

        for t in (entry.get("tags") or []):
            tags.add(str(t).lower())

        tt = entry.get("threat_type") or ""
        if tt:
            threat_types.add(tt.lower())

        mal = entry.get("malware") or entry.get("malware_alias") or ""
        if mal:
            malware_names.add(mal.lower())

        fs = entry.get("first_seen") or ""
        ls = entry.get("last_seen") or ""
        if fs and (not first_seen or fs < first_seen):
            first_seen = fs
        if ls and (not last_seen or ls > last_seen):
            last_seen = ls

        if not ioc_id and entry.get("id"):
            ioc_id = str(entry["id"])

    result.confidence        = float(max_confidence)
    result.malicious_count   = len(data)
    
    result.data["ioc_id"]            = ioc_id
    result.data["malware_family"]    = malware_printable
    result.data["threat_type"]       = threat_type
    result.data["ioc_type_detail"]   = ioc_type_det
    result.data["status"]            = active_status
    
    result.first_observed        = first_seen
    result.last_observed         = last_seen
    result.data["tags"]          = list(tags | threat_types | malware_names)[:15]

    if ioc_id:
        result.data["raw_link"] = f"{_LINK_BASE}{ioc_id}/"

    # Verdict from confidence level
    if max_confidence >= 75:
        result.verdict = Verdict.MALICIOUS.value
    elif max_confidence >= 40:
        result.verdict = Verdict.SUSPICIOUS.value
    else:
        result.verdict = Verdict.SUSPICIOUS.value  # Found in feed = at least suspicious

    result.provider_status = ProviderStatus.MATCHED.value
    return result
