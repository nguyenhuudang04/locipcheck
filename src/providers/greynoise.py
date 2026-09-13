"""
greynoise.py -- GreyNoise enrichment provider.
Docs: https://docs.greynoise.io/reference

Strategy:
  1. If GREYNOISE_API_KEY is present -> use paid /v3/ip/{ip}
  2. If no key -> fall back to FREE Community API /v3/community/{ip}
     (no auth required, returns noise/riot/classification/name/message)
  3. Both paths populate the same EnrichmentResult fields.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone

from src.http_client import build_session
from src.models import EnrichmentResult, ProviderStatus, Verdict

logger = logging.getLogger(__name__)

_PAID_URL      = "https://api.greynoise.io/v3/ip/{ip}"
_COMMUNITY_URL = "https://api.greynoise.io/v3/community/{ip}"
_VIZ_LINK      = "https://viz.greynoise.io/ip/{ip}"


def enrich(ioc: str) -> EnrichmentResult:
    """Query GreyNoise (paid API first, community fallback). Read-only."""
    queried_at = datetime.now(tz=timezone.utc).isoformat()
    result = EnrichmentResult(
        source="GreyNoise",
        enrichment_queried_at=queried_at,
        data={"raw_link": _VIZ_LINK.format(ip=ioc)}
    )

    api_key = os.getenv("GREYNOISE_API_KEY", "").strip()
    session = build_session(retries=1, backoff_factor=1.0,
                            retry_statuses=(429, 500, 502, 503, 504))

    if api_key:
        _query_paid(session, ioc, api_key, result)
    else:
        logger.info("GreyNoise: no API key — trying community endpoint")
        _query_community(session, ioc, result)

    return result


def _query_paid(session, ioc: str, api_key: str, result: EnrichmentResult) -> None:
    try:
        resp = session.get(
            _PAID_URL.format(ip=ioc),
            headers={
                "key": api_key,
                "Accept": "application/json",
                "User-Agent": "SOC-IOC-Tool/1.0",
            },
            timeout=15,
        )
    except Exception as exc:
        _handle_exc(exc, result)
        return

    if resp.status_code == 404:
        result.provider_status = ProviderStatus.NO_MATCH.value
        return
    if resp.status_code in (401, 403):
        result.provider_status = ProviderStatus.UNAUTHORIZED.value
        result.error = f"GreyNoise auth failed (HTTP {resp.status_code})"
        return
    if resp.status_code == 429:
        result.provider_status = ProviderStatus.RATE_LIMITED.value
        result.error = "GreyNoise rate limit hit (HTTP 429)"
        return
    if not resp.ok:
        result.provider_status = ProviderStatus.ERROR.value
        result.error = f"GreyNoise API error (HTTP {resp.status_code})"
        return

    try:
        body = resp.json()
    except Exception:
        result.provider_status = ProviderStatus.ERROR.value
        result.error = "GreyNoise: invalid JSON response"
        return

    _parse_paid(body, result)


def _parse_paid(body: dict, result: EnrichmentResult) -> None:
    result.provider_status = ProviderStatus.MATCHED.value

    cls = (body.get("classification") or "").lower()
    result.data["classification"] = cls
    result.data["noise"] = body.get("noise")
    result.data["riot"]  = body.get("riot")
    result.data["name"]  = body.get("name")

    metadata = body.get("metadata", {})
    result.data["country"]      = metadata.get("country")
    result.data["organization"] = metadata.get("organization")
    result.data["asn"]          = str(metadata.get("asn")) if metadata.get("asn") else None

    result.first_observed = body.get("first_seen")
    result.last_observed  = body.get("last_seen")

    raw_tags = body.get("tags") or []
    result.data["tags"] = [str(t) for t in raw_tags][:15]

    # Verdict
    if cls == "malicious":
        result.verdict = Verdict.MALICIOUS.value
    elif cls == "benign":
        result.verdict = Verdict.BENIGN.value
    elif cls == "unknown" or not cls:
        result.verdict = Verdict.UNKNOWN.value
    else:
        result.verdict = Verdict.SUSPICIOUS.value

    result.data["raw_link"] = body.get("link") or result.data["raw_link"]


def _query_community(session, ioc: str, result: EnrichmentResult) -> None:
    try:
        resp = session.get(
            _COMMUNITY_URL.format(ip=ioc),
            headers={
                "Accept": "application/json",
                "User-Agent": "SOC-IOC-Tool/1.0",
            },
            timeout=15,
        )
    except Exception as exc:
        _handle_exc(exc, result)
        return

    if resp.status_code == 404:
        result.provider_status = ProviderStatus.NO_MATCH.value
        return
    if resp.status_code in (401, 403):
        result.provider_status = ProviderStatus.UNAUTHORIZED.value
        result.error = "GreyNoise community endpoint returned auth error"
        return
    if resp.status_code == 429:
        result.provider_status = ProviderStatus.RATE_LIMITED.value
        result.error = "GreyNoise rate limited (HTTP 429)"
        return
    if not resp.ok:
        result.provider_status = ProviderStatus.ERROR.value
        result.error = f"GreyNoise community API error (HTTP {resp.status_code})"
        return

    try:
        body = resp.json()
    except Exception:
        result.provider_status = ProviderStatus.ERROR.value
        result.error = "GreyNoise: invalid JSON"
        return

    _parse_community(body, result)


def _parse_community(body: dict, result: EnrichmentResult) -> None:
    result.provider_status = ProviderStatus.MATCHED.value

    result.data["noise"]          = body.get("noise")
    result.data["riot"]           = body.get("riot")
    result.data["classification"] = (body.get("classification") or "").lower()
    result.data["name"]           = body.get("name")
    result.data["message"]        = body.get("message")
    result.last_observed          = body.get("last_seen")
    result.data["raw_link"]       = body.get("link") or result.data["raw_link"]

    cls = result.data["classification"]
    if cls == "malicious":
        result.verdict = Verdict.MALICIOUS.value
    elif cls == "benign":
        result.verdict = Verdict.BENIGN.value
    else:
        result.verdict = Verdict.UNKNOWN.value


def _handle_exc(exc: Exception, result: EnrichmentResult) -> None:
    import requests
    result.provider_status = ProviderStatus.ERROR.value
    if isinstance(exc, requests.exceptions.Timeout):
        result.error = "GreyNoise request timed out"
    else:
        result.error = f"GreyNoise network error: {type(exc).__name__}"
