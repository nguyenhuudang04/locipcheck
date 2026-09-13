"""
detector.py — Automatically classify an IOC string using safe regex patterns
and stdlib ipaddress module.  No third-party dependencies.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from src.models import IOCType


# ---------------------------------------------------------------------------
# Compiled regex patterns
# ---------------------------------------------------------------------------
_RE_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
_RE_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
_RE_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")

# Conservative domain pattern — at least one dot, valid TLD ≥ 2 chars
_RE_DOMAIN = re.compile(
    r"^(?:[a-zA-Z0-9]"          # start with alnum
    r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"   # optional middle
    r"\.)+"                      # dot-separated labels
    r"[a-zA-Z]{2,63}$"           # TLD
)

# URL — must start with http:// or https://
_RE_URL = re.compile(r"^https?://", re.IGNORECASE)


def detect(ioc: str) -> IOCType:
    """Return the IOCType for *ioc*.  Order matters — checked most specific first."""
    ioc = ioc.strip()

    if not ioc:
        return IOCType.UNKNOWN

    # --- Hashes (most specific — checked before anything else) ---
    if _RE_SHA256.match(ioc):
        return IOCType.SHA256
    if _RE_SHA1.match(ioc):
        return IOCType.SHA1
    if _RE_MD5.match(ioc):
        return IOCType.MD5

    # --- URL (must come before domain so http://evil.com is URL not domain) ---
    if _RE_URL.match(ioc):
        parsed = urlparse(ioc)
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            return IOCType.URL

    # --- IP addresses ---
    try:
        addr = ipaddress.ip_address(ioc)
        if isinstance(addr, ipaddress.IPv4Address):
            return IOCType.IPV4
        return IOCType.IPV6
    except ValueError:
        pass

    # --- Domain ---
    if _RE_DOMAIN.match(ioc):
        return IOCType.DOMAIN

    return IOCType.UNKNOWN
