"""
virustotal.py -- VirusTotal API v3 enrichment.
Supports: IPv4, IPv6, Domain, URL, File hashes (MD5/SHA1/SHA256).
Docs: https://developers.virustotal.com/reference/overview

IMPORTANT: GET requests only -- no file/URL submission.
"""
from __future__ import annotations

import base64
import logging
import os
from datetime import datetime, timezone

from src.http_client import build_session
from src.models import EnrichmentResult, IOCType, ProviderStatus, Verdict

logger = logging.getLogger(__name__)

_BASE = "https://www.virustotal.com/api/v3"


def _url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def _vt_endpoint(ioc: str, ioc_type: str) -> str:
    if ioc_type in (IOCType.IPV4.value, IOCType.IPV6.value):
        return f"{_BASE}/ip_addresses/{ioc}"
    if ioc_type == IOCType.DOMAIN.value:
        return f"{_BASE}/domains/{ioc}"
    if ioc_type == IOCType.URL.value:
        return f"{_BASE}/urls/{_url_id(ioc)}"
    if ioc_type in (IOCType.MD5.value, IOCType.SHA1.value, IOCType.SHA256.value):
        return f"{_BASE}/files/{ioc}"
    raise ValueError(f"Unsupported IOC type for VirusTotal: {ioc_type}")


def enrich(ioc: str, ioc_type: str) -> EnrichmentResult:
    """Query VirusTotal for *ioc*. Returns normalised EnrichmentResult."""
    queried_at = datetime.now(tz=timezone.utc).isoformat()
    result = EnrichmentResult(
        source="VirusTotal",
        enrichment_queried_at=queried_at,
        data={"raw_link": f"https://www.virustotal.com/gui/search/{ioc}"}
    )

    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        result.provider_status = ProviderStatus.SKIPPED.value
        result.error = "VIRUSTOTAL_API_KEY not configured"
        return result

    try:
        endpoint = _vt_endpoint(ioc, ioc_type)
    except ValueError as exc:
        result.provider_status = ProviderStatus.ERROR.value
        result.error = str(exc)
        return result

    session = build_session(retries=1, backoff_factor=1.0,
                            retry_statuses=(429, 500, 502, 503, 504))
    try:
        resp = session.get(
            endpoint,
            headers={
                "x-apikey": api_key,
                "Accept": "application/json",
                "User-Agent": "SOC-IOC-Tool/1.0",
            },
            timeout=20,
        )
    except Exception as exc:
        import requests
        result.provider_status = ProviderStatus.ERROR.value
        if isinstance(exc, requests.exceptions.Timeout):
            result.error = "VirusTotal request timed out"
        else:
            result.error = f"VirusTotal network error: {type(exc).__name__}"
        return result

    if resp.status_code == 404:
        result.provider_status = ProviderStatus.NO_MATCH.value
        result.verdict = Verdict.UNKNOWN.value
        return result
    if resp.status_code in (401, 403):
        result.provider_status = ProviderStatus.UNAUTHORIZED.value
        result.error = f"VirusTotal auth failed (HTTP {resp.status_code})"
        return result
    if resp.status_code == 429:
        result.provider_status = ProviderStatus.RATE_LIMITED.value
        result.error = "VirusTotal rate limit hit (HTTP 429)"
        return result
    if not resp.ok:
        result.provider_status = ProviderStatus.ERROR.value
        result.error = f"VirusTotal API error (HTTP {resp.status_code})"
        return result

    try:
        body = resp.json()
    except Exception:
        result.provider_status = ProviderStatus.ERROR.value
        result.error = "VirusTotal: invalid JSON response"
        return result

    if "data" not in body:
        result.provider_status = ProviderStatus.ERROR.value
        result.error = "VirusTotal: unexpected response structure"
        return result

    attrs: dict = body["data"].get("attributes", {})
    stats: dict = attrs.get("last_analysis_stats", {})

    malicious:  int = int(stats.get("malicious",  0))
    suspicious: int = int(stats.get("suspicious", 0))
    harmless:   int = int(stats.get("harmless",   0))
    undetected: int = int(stats.get("undetected", 0))
    timeout_c:  int = int(stats.get("timeout",    0))
    total_engines = malicious + suspicious + harmless + undetected + timeout_c

    # Full analysis stats for UI display
    result.data["analysis_stats"] = {
        "malicious":  malicious,
        "suspicious": suspicious,
        "harmless":   harmless,
        "undetected": undetected,
        "timeout":    timeout_c,
        "total":      total_engines,
    }

    result.malicious_count   = malicious
    result.reputation        = attrs.get("reputation")
    result.data["reputation"] = attrs.get("reputation")
    
    result.data["country"]           = attrs.get("country")
    result.data["continent"]         = attrs.get("continent")
    result.data["asn"]               = str(attrs.get("asn")) if attrs.get("asn") else None
    result.data["organization"]      = attrs.get("as_owner") or attrs.get("registrar")
    result.data["name"]              = attrs.get("as_owner")
    result.data["network"]           = attrs.get("network")
    result.data["regional_internet_registry"] = attrs.get("regional_internet_registry")
    result.data["jarm"]              = attrs.get("jarm")
    result.data["whois"]             = attrs.get("whois")
    result.data["whois_date"]        = _ts(attrs.get("whois_date"))
    
    # Detailed Vendor Detections
    last_analysis_results = attrs.get("last_analysis_results", {})
    vendor_detections = {
        "malicious": [],
        "suspicious": [],
        "harmless": [],
        "undetected": [],
        "timeout": []
    }
    
    for engine, details in last_analysis_results.items():
        cat = details.get("category", "undetected")
        if cat not in vendor_detections:
            cat = "undetected"
        vendor_detections[cat].append({
            "engine_name": details.get("engine_name", engine),
            "category": details.get("category"),
            "method": details.get("method"),
            "result": details.get("result")
        })
        
    result.data["vendor_detections"] = vendor_detections
    
    result.last_analyzed = _ts(attrs.get("last_analysis_date") or attrs.get("last_modification_date"))

    result.first_observed = _ts(attrs.get("first_submission_date") or attrs.get("creation_date"))
    
    # VirusTotal last_analysis_date không được xem là IOC last_seen. Do not map last_seen to last_analysis_date
    result.last_observed  = _ts(attrs.get("last_submission_date"))

    # Tags
    tags: list[str] = list(attrs.get("tags", []))
    categories = attrs.get("categories", {})
    if isinstance(categories, dict):
        tags.extend(categories.values())
    result.data["tags"] = list({t.lower() for t in tags})[:12]
    
    # Expanding Domain Parser
    result.data["popular_threat_classification"] = attrs.get("popular_threat_classification")
    result.data["categories"] = attrs.get("categories")
    result.data["registrar"] = attrs.get("registrar")
    result.data["creation_date"] = _ts(attrs.get("creation_date"))
    result.data["last_dns_records"] = attrs.get("last_dns_records")
    result.data["last_https_certificate"] = attrs.get("last_https_certificate")
    result.data["total_votes"] = attrs.get("total_votes")
    
    # Note: relationships (resolutions, subdomains, detected URLs, communicating files, referrer files)
    # in API v3 these are usually fetched via sub-endpoints e.g. /domains/{domain}/resolutions
    # However if they are present in the 'relationships' dict of the response body, parse them.
    rels = body["data"].get("relationships", {})
    if "resolutions" in rels:
        result.data["resolutions_count"] = rels["resolutions"].get("meta", {}).get("count")
    if "subdomains" in rels:
        result.data["subdomains_count"] = rels["subdomains"].get("meta", {}).get("count")
    if "detected_urls" in rels:
        result.data["detected_urls_count"] = rels["detected_urls"].get("meta", {}).get("count")
    if "communicating_files" in rels:
        result.data["communicating_files_count"] = rels["communicating_files"].get("meta", {}).get("count")
    if "referrer_files" in rels:
        result.data["referrer_files_count"] = rels["referrer_files"].get("meta", {}).get("count")

    # Verdict
    if malicious >= 5:
        result.verdict = Verdict.MALICIOUS.value
    elif malicious >= 1 or suspicious >= 3:
        result.verdict = Verdict.SUSPICIOUS.value
    elif harmless > 0 and malicious == 0:
        result.verdict = Verdict.BENIGN.value
    else:
        result.verdict = Verdict.UNKNOWN.value

    # Confidence = % of engines flagging malicious
    if total_engines > 0:
        result.confidence = round((malicious / total_engines) * 100, 1)

    result.provider_status = ProviderStatus.MATCHED.value
    return result


def _ts(unix_ts) -> str | None:
    if unix_ts is None:
        return None
    try:
        return datetime.fromtimestamp(int(unix_ts), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return str(unix_ts)


def fetch_vt_relationship(ioc: str, ioc_type: str, relationship: str, limit: int = 10, cursor: str = None) -> dict:
    """Fetch VirusTotal relationship (e.g. comments, resolutions) on-demand."""
    from src.models import ModuleResult, ModulePagination, ProviderStatus
    
    res = ModuleResult(source="VirusTotal", module=relationship)
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        res.status = ProviderStatus.SKIPPED.value
        res.data = {"error": "VIRUSTOTAL_API_KEY not configured"}
        return res.to_dict()

    try:
        base_endpoint = _vt_endpoint(ioc, ioc_type)
        endpoint = f"{base_endpoint}/{relationship}?limit={limit}"
        if cursor:
            endpoint += f"&cursor={cursor}"
    except ValueError as exc:
        res.status = ProviderStatus.ERROR.value
        res.data = {"error": str(exc)}
        return res.to_dict()

    session = build_session(retries=0)  # Basic mode lazy loading, don't retry too much on frontend
    try:
        resp = session.get(
            endpoint,
            headers={
                "x-apikey": api_key,
                "Accept": "application/json",
                "User-Agent": "SOC-IOC-Tool/1.0",
            },
            timeout=15,
        )
    except Exception as exc:
        res.status = ProviderStatus.ERROR.value
        res.data = {"error": f"Network error: {type(exc).__name__}"}
        return res.to_dict()

    if resp.status_code in (401, 403):
        res.status = ProviderStatus.PREMIUM_REQUIRED.value
        res.data = {"error": "Premium privileges required for this endpoint or invalid API key."}
        return res.to_dict()
    if resp.status_code == 404:
        res.status = ProviderStatus.NO_MATCH.value
        return res.to_dict()
    if resp.status_code == 429:
        res.status = ProviderStatus.RATE_LIMITED.value
        res.data = {"error": "VirusTotal API rate limit exceeded."}
        return res.to_dict()
    if not resp.ok:
        res.status = ProviderStatus.ERROR.value
        res.data = {"error": f"HTTP {resp.status_code}"}
        return res.to_dict()

    try:
        body = resp.json()
    except Exception:
        res.status = ProviderStatus.ERROR.value
        res.data = {"error": "Invalid JSON response"}
        return res.to_dict()

    res.status = ProviderStatus.MATCHED.value
    res.data = body.get("data", [])
    
    meta = body.get("meta", {})
    links = body.get("links", {})
    
    # Check for next cursor
    next_cursor = meta.get("cursor")
    if not next_cursor and links.get("next"):
        # Sometimes cursor is in the 'next' URL
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(links["next"])
        qs = parse_qs(parsed.query)
        if "cursor" in qs:
            next_cursor = qs["cursor"][0]
            
    res.pagination = ModulePagination(
        count=meta.get("count", 0),
        cursor=next_cursor,
        next=links.get("next")
    )
    
    return res.to_dict()
