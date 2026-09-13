"""
http_client.py — Centralised HTTP helper with timeout, retry and rate-limit handling.
"""
from __future__ import annotations

import time
import logging
from typing import Any, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# HTTP status codes we handle explicitly
# ---------------------------------------------------------------------------
_HANDLED_CODES = {400, 401, 403, 404, 429, 500}
_STATUS_MESSAGES = {
    400: "Bad Request — check IOC format sent to API",
    401: "Unauthorised — API key missing or invalid",
    403: "Forbidden — API plan does not allow this endpoint",
    404: "Not Found — IOC not present in this source",
    429: "Rate-Limit exceeded — back off and retry",
    500: "Internal Server Error from remote API",
}


def build_session(
    retries: int = 3,
    backoff_factor: float = 1.0,
    retry_statuses: tuple[int, ...] = (429, 500, 502, 503, 504),
) -> requests.Session:
    """Return a requests.Session pre-configured with retry logic."""
    session = requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=list(retry_statuses),
        allowed_methods=["GET", "POST"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def safe_get(
    session: requests.Session,
    url: str,
    *,
    headers: Optional[dict] = None,
    params: Optional[dict] = None,
    timeout: int = 15,
    rate_limit_pause: float = 2.0,
) -> tuple[Optional[dict[str, Any]], Optional[str]]:
    """
    Perform GET; return (json_body, error_message).
    Never raises — all exceptions are caught and returned as error strings.
    """
    try:
        resp = session.get(url, headers=headers, params=params, timeout=timeout)
    except requests.exceptions.Timeout:
        return None, "Request timed out"
    except requests.exceptions.ConnectionError as exc:
        return None, f"Connection error: {exc}"
    except Exception as exc:  # noqa: BLE001
        return None, f"Unexpected request error: {exc}"

    if resp.status_code == 429:
        logger.warning("Rate limit hit for %s — pausing %.1fs before next call", url, rate_limit_pause)
        time.sleep(rate_limit_pause)
        return None, _STATUS_MESSAGES[429]

    if resp.status_code == 404:
        return None, _STATUS_MESSAGES[404]

    if resp.status_code in _HANDLED_CODES:
        msg = _STATUS_MESSAGES.get(resp.status_code, f"HTTP {resp.status_code}")
        logger.warning("HTTP %s from %s: %s", resp.status_code, url, msg)
        return None, msg

    if not resp.ok:
        return None, f"HTTP {resp.status_code} from {url}"

    try:
        return resp.json(), None
    except Exception:  # noqa: BLE001
        return None, "Invalid JSON in response"
