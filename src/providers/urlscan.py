"""
urlscan.py -- urlscan.io Search API enrichment for domains and URLs.
Docs: https://urlscan.io/docs/#search

IMPORTANT: Uses the SEARCH endpoint only -- does NOT submit new scans.

Note on free tier: The urlscan.io free plan allows public search without
an API key for most queries. We attempt public search first, then fall back
to authenticated search if the key is present and public fails.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone

from src.http_client import build_session, safe_get
from src.models import EnrichmentResult, ProviderStatus, Verdict

logger = logging.getLogger(__name__)

_SEARCH_URL = "https://urlscan.io/api/v1/search/"


def enrich(ioc: str) -> EnrichmentResult:
    """Search urlscan.io for existing scans matching *ioc*. Read-only."""
    queried_at = datetime.now(tz=timezone.utc).isoformat()
    result = EnrichmentResult(
        source="urlscan.io",
        enrichment_queried_at=queried_at,
        data={"raw_link": f"https://urlscan.io/search/#page.domain:{ioc}"}
    )

    api_key = os.getenv("URLSCAN_API_KEY", "").strip()
    if not api_key:
        result.provider_status = ProviderStatus.SKIPPED.value
        result.error = "URLSCAN_API_KEY not configured -- skipped"
        logger.info("urlscan.io: no API key, skipping")
        return result

    session = build_session()

    # Build query — domain vs URL
    if "." in ioc and "/" not in ioc and not ioc.startswith("http"):
        # Strip surrounding quotes; urlscan search accepts bare domain
        query = f"page.domain:{ioc}"
    else:
        query = f"page.url:{ioc}"

    # Try 1: authenticated request
    headers_auth = {
        "API-Key": api_key,
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "SOC-IOC-Tool/1.0",
    }
    data, err = safe_get(
        session,
        _SEARCH_URL,
        headers=headers_auth,
        params={"q": query, "size": "10", "sort": "date:desc"},
    )

    # If authenticated request returns 403 (plan limitation), try unauthenticated
    if err and "Forbidden" in err:
        logger.info("urlscan.io: authenticated search returned 403, trying public endpoint")
        headers_pub = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "SOC-IOC-Tool/1.0",
        }
        data, err = safe_get(
            session,
            _SEARCH_URL,
            headers=headers_pub,
            params={"q": query, "size": "10", "sort": "date:desc"},
        )
        # If public also fails, mark as plan limitation (not an error)
        if err and "Forbidden" in err:
            result.provider_status = ProviderStatus.SKIPPED.value
            result.error = "Search API requires a paid plan -- skipped"
            return result

    if err:
        if "429" in err:
            result.provider_status = ProviderStatus.RATE_LIMITED.value
        elif "401" in err or "403" in err:
            result.provider_status = ProviderStatus.UNAUTHORIZED.value
        else:
            result.provider_status = ProviderStatus.ERROR.value
        result.error = err
        return result

    if not data or "results" not in data:
        result.provider_status = ProviderStatus.ERROR.value
        result.error = "Unexpected urlscan.io response structure"
        return result

    results_list: list[dict] = data.get("results", [])
    total: int = data.get("total", 0)

    if not results_list:
        result.provider_status = ProviderStatus.NO_MATCH.value
        return result

    result.provider_status = ProviderStatus.MATCHED.value

    # Analyse verdicts from recent scans
    malicious_scans = 0
    suspicious_scans = 0
    tags: set[str] = set()

    for scan in results_list:
        verdict_data = scan.get("verdicts", {}).get("overall", {})
        score = verdict_data.get("score", 0)
        if verdict_data.get("malicious") or score >= 60:
            malicious_scans += 1
        elif score >= 30:
            suspicious_scans += 1
        for tag in verdict_data.get("tags", []):
            tags.add(tag.lower())

    result.malicious_count = malicious_scans
    result.data["tags"] = list(tags)[:10]

    # Most recent scan metadata
    first_scan = results_list[0]
    page = first_scan.get("page", {})
    result.data["country"] = page.get("country")
    result.data["organization"] = page.get("asnname")
    result.data["asn"] = str(page.get("asn")) if page.get("asn") else None
    
    result.last_observed = first_scan.get("task", {}).get("time")

    if total > 0 and len(results_list) > 1:
        result.first_observed = results_list[-1].get("task", {}).get("time")

    # Verdict
    if malicious_scans >= 2:
        result.verdict = Verdict.MALICIOUS.value
    elif malicious_scans == 1 or suspicious_scans >= 2:
        result.verdict = Verdict.SUSPICIOUS.value
    else:
        result.verdict = Verdict.BENIGN.value

    result.confidence = round((malicious_scans / len(results_list)) * 100, 1) if results_list else None
    result.data["raw_link"] = first_scan.get("result", result.data["raw_link"])

    return result
