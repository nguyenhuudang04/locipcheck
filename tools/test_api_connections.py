#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tools/test_api_connections.py
-----------------------------
Read-only API connectivity checker for SOC IOC Enrichment project.

SECURITY RULES enforced in this script:
- API keys are NEVER printed, logged, or written to any file.
- Request headers are NEVER printed.
- Exceptions are sanitised before display (no URLs with embedded keys).
- HTTP debug logging is OFF.
- os.environ is NEVER printed.
- No data is submitted, uploaded, or scanned.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

# ---------------------------------------------------------------------------
# Silence all HTTP/urllib3 debug output before importing requests
# ---------------------------------------------------------------------------
import logging
logging.getLogger("urllib3").setLevel(logging.CRITICAL)
logging.getLogger("requests").setLevel(logging.CRITICAL)
logging.disable(logging.DEBUG)

import requests
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from rich.console import Console
from rich.table import Table
from rich import box

load_dotenv()

console = Console(highlight=False, emoji=False)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
TIMEOUT = 15
UA = "SOC-IOC-Tool-API-Test/1.0"

# Statuses
PASS             = "PASS"
MISSING_KEY      = "MISSING_KEY"
AUTH_FAILED      = "AUTH_FAILED"
RATE_LIMITED     = "RATE_LIMITED"
NETWORK_ERROR    = "NETWORK_ERROR"
TIMEOUT_STATUS   = "TIMEOUT"
INVALID_RESPONSE = "INVALID_RESPONSE"
FAILED           = "FAILED"

STATUS_COLOURS = {
    PASS:             "bold green",
    MISSING_KEY:      "yellow",
    RATE_LIMITED:     "yellow",
    AUTH_FAILED:      "bold red",
    NETWORK_ERROR:    "bold red",
    TIMEOUT_STATUS:   "bold red",
    INVALID_RESPONSE: "bold red",
    FAILED:           "bold red",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_session(no_retry_on: tuple[int, ...] = (401, 403)) -> requests.Session:
    """Session with 1 retry for 429/5xx, no retry for auth errors."""
    session = requests.Session()
    retry = Retry(
        total=1,
        backoff_factor=1.0,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def _safe_get(session: requests.Session, url: str, *, headers: dict,
              params: dict | None = None) -> tuple[int | None, dict | None, str | None]:
    """
    GET request. Returns (status_code, json_body, error_message).
    URL is never passed to caller — headers (with keys) are not exposed.
    """
    try:
        r = session.get(url, headers=headers, params=params, timeout=TIMEOUT)
        try:
            body = r.json()
        except Exception:
            body = None
        return r.status_code, body, None
    except requests.exceptions.Timeout:
        return None, None, TIMEOUT_STATUS
    except requests.exceptions.ConnectionError:
        return None, None, NETWORK_ERROR
    except Exception:
        return None, None, NETWORK_ERROR


def _safe_post(session: requests.Session, url: str, *, headers: dict,
               json_body: dict | None = None,
               data: dict | None = None) -> tuple[int | None, dict | None, str | None]:
    """
    POST request. Returns (status_code, json_body, error_message).
    """
    try:
        if json_body is not None:
            r = session.post(url, headers=headers, json=json_body, timeout=TIMEOUT)
        else:
            r = session.post(url, headers=headers, data=data, timeout=TIMEOUT)
        try:
            body = r.json()
        except Exception:
            body = None
        return r.status_code, body, None
    except requests.exceptions.Timeout:
        return None, None, TIMEOUT_STATUS
    except requests.exceptions.ConnectionError:
        return None, None, NETWORK_ERROR
    except Exception:
        return None, None, NETWORK_ERROR


def _resolve_abusech_key() -> str:
    """
    Resolve abuse.ch Auth-Key with fallback priority:
      1. ABUSECH_AUTH_KEY
      2. THREATFOX_AUTH_KEY
      3. URLHAUS_AUTH_KEY
      4. MALWAREBAZAAR_AUTH_KEY
    Validates that all present keys share the same value (warns if mismatch).
    Never prints any key value.
    """
    candidates = {
        "ABUSECH_AUTH_KEY":     os.getenv("ABUSECH_AUTH_KEY", "").strip(),
        "THREATFOX_AUTH_KEY":   os.getenv("THREATFOX_AUTH_KEY", "").strip(),
        "URLHAUS_AUTH_KEY":     os.getenv("URLHAUS_AUTH_KEY", "").strip(),
        "MALWAREBAZAAR_AUTH_KEY": os.getenv("MALWAREBAZAAR_AUTH_KEY", "").strip(),
    }
    present = {name: val for name, val in candidates.items() if val}

    if not present:
        return ""

    unique_values = set(present.values())
    if len(unique_values) > 1:
        console.print(
            "[yellow]WARNING:[/] Multiple abuse.ch key variables found with different values. "
            "Using ABUSECH_AUTH_KEY priority order. Please consolidate to ABUSECH_AUTH_KEY."
        )

    # Return by priority
    for name in ("ABUSECH_AUTH_KEY", "THREATFOX_AUTH_KEY", "URLHAUS_AUTH_KEY", "MALWAREBAZAAR_AUTH_KEY"):
        if candidates[name]:
            return candidates[name]
    return ""


# ---------------------------------------------------------------------------
# Step 1 — Key presence check (no values shown)
# ---------------------------------------------------------------------------

def check_env_keys() -> dict[str, bool]:
    """Return presence map for all required keys. Never prints key values."""
    abusech = _resolve_abusech_key()
    found = {
        "VIRUSTOTAL_API_KEY": bool(os.getenv("VIRUSTOTAL_API_KEY", "").strip()),
        "ABUSEIPDB_API_KEY":  bool(os.getenv("ABUSEIPDB_API_KEY", "").strip()),
        "URLSCAN_API_KEY":    bool(os.getenv("URLSCAN_API_KEY", "").strip()),
        "ABUSECH_AUTH_KEY":   bool(abusech),
    }
    console.print("\n[bold cyan]== API Key Presence ==[/]")
    for name, present in found.items():
        status = "[bold green]FOUND[/]" if present else "[bold red]MISSING[/]"
        console.print(f"  {name}: {status}")
    console.print()
    return found


# ---------------------------------------------------------------------------
# Individual provider tests
# ---------------------------------------------------------------------------

def test_virustotal() -> dict:
    result = {"provider": "VirusTotal", "key_status": "FOUND", "http": None,
              "status": None, "detail": {}}
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        result.update({"key_status": "MISSING", "status": MISSING_KEY})
        return result

    session = _build_session()
    code, body, err = _safe_get(
        session,
        "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
        headers={"x-apikey": api_key, "Accept": "application/json",
                 "User-Agent": UA},
    )

    result["http"] = code

    if err:
        result["status"] = err
        return result

    if code == 200:
        data = (body or {}).get("data", {})
        attrs = data.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        d_id = data.get("id")

        if not d_id or "last_analysis_stats" not in attrs:
            result["status"] = INVALID_RESPONSE
            return result

        result["status"] = PASS
        result["detail"] = {
            "ip_returned": d_id,
            "malicious":   stats.get("malicious"),
            "suspicious":  stats.get("suspicious"),
            "harmless":    stats.get("harmless"),
            "undetected":  stats.get("undetected"),
        }
    elif code in (401, 403):
        result["status"] = AUTH_FAILED
    elif code == 429:
        result["status"] = RATE_LIMITED
    else:
        result["status"] = FAILED

    return result


def test_abuseipdb() -> dict:
    result = {"provider": "AbuseIPDB", "key_status": "FOUND", "http": None,
              "status": None, "detail": {}}
    api_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    if not api_key:
        result.update({"key_status": "MISSING", "status": MISSING_KEY})
        return result

    session = _build_session()
    code, body, err = _safe_get(
        session,
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": api_key, "Accept": "application/json",
                 "User-Agent": UA},
        params={"ipAddress": "8.8.8.8", "maxAgeInDays": "90"},
    )

    result["http"] = code

    if err:
        result["status"] = err
        return result

    if code == 200:
        data = (body or {}).get("data", {})
        ip_addr = data.get("ipAddress")
        score   = data.get("abuseConfidenceScore")

        if ip_addr is None or score is None:
            result["status"] = INVALID_RESPONSE
            return result

        result["status"] = PASS
        result["detail"] = {
            "ipAddress":            data.get("ipAddress"),
            "abuseConfidenceScore": data.get("abuseConfidenceScore"),
            "totalReports":         data.get("totalReports"),
            "countryCode":          data.get("countryCode"),
            "isp":                  data.get("isp"),
            "isTor":                data.get("isTor"),
        }
    elif code in (401, 403):
        result["status"] = AUTH_FAILED
    elif code == 429:
        result["status"] = RATE_LIMITED
    else:
        result["status"] = FAILED

    return result


def test_urlscan() -> dict:
    result = {"provider": "urlscan.io", "key_status": "FOUND", "http": None,
              "status": None, "detail": {}}
    api_key = os.getenv("URLSCAN_API_KEY", "").strip()
    if not api_key:
        result.update({"key_status": "MISSING", "status": MISSING_KEY})
        return result

    session = _build_session()
    code, body, err = _safe_get(
        session,
        "https://urlscan.io/api/v1/search/",
        headers={"API-Key": api_key, "Accept": "application/json",
                 "User-Agent": UA},
        params={"q": "page.domain:example.com", "size": "1"},
    )

    result["http"] = code

    if err:
        result["status"] = err
        return result

    if code == 200:
        results_list = (body or {}).get("results", [])
        total = (body or {}).get("total", len(results_list))

        if "results" not in (body or {}):
            result["status"] = INVALID_RESPONSE
            return result

        first_domain = None
        if results_list:
            first_domain = results_list[0].get("page", {}).get("domain")

        result["status"] = PASS
        result["detail"] = {
            "total_results":  total,
            "results_returned": len(results_list),
            "first_domain":   first_domain,
        }
    elif code in (401, 403):
        result["status"] = AUTH_FAILED
    elif code == 429:
        result["status"] = RATE_LIMITED
    else:
        result["status"] = FAILED

    return result


def test_threatfox(auth_key: str) -> dict:
    result = {"provider": "ThreatFox", "key_status": "FOUND", "http": None,
              "status": None, "detail": {}}
    if not auth_key:
        result.update({"key_status": "MISSING", "status": MISSING_KEY})
        return result

    session = _build_session()
    code, body, err = _safe_post(
        session,
        "https://threatfox-api.abuse.ch/api/v1/",
        headers={"Auth-Key": auth_key, "Content-Type": "application/json",
                 "Accept": "application/json", "User-Agent": UA},
        json_body={"query": "get_iocs", "days": 1},
    )

    result["http"] = code

    if err:
        result["status"] = err
        return result

    if code == 200:
        query_status = (body or {}).get("query_status", "")
        data = (body or {}).get("data") or []

        if query_status == "":
            result["status"] = INVALID_RESPONSE
            return result

        # Authentication failure is signalled via query_status, not HTTP code
        if "unauthorized" in query_status.lower() or "invalid" in query_status.lower():
            result["status"] = AUTH_FAILED
            result["detail"] = {"query_status": query_status}
            return result

        ioc_count = len(data) if isinstance(data, list) else 0
        result["status"] = PASS
        result["detail"] = {
            "query_status": query_status,
            "ioc_count":    ioc_count,
        }
    elif code in (401, 403):
        result["status"] = AUTH_FAILED
    elif code == 429:
        result["status"] = RATE_LIMITED
    else:
        result["status"] = FAILED

    return result


def test_malwarebazaar(auth_key: str) -> dict:
    result = {"provider": "MalwareBazaar", "key_status": "FOUND", "http": None,
              "status": None, "detail": {}}
    if not auth_key:
        result.update({"key_status": "MISSING", "status": MISSING_KEY})
        return result

    # Public SHA256 hash from MalwareBazaar docs — metadata lookup only
    _SAMPLE_HASH = "094fd325049b8a9cf6d3e5ef2a6d4cc6a567d7d49c35f8bb8dd9e3c6acf3d78d"

    session = _build_session()
    code, body, err = _safe_post(
        session,
        "https://mb-api.abuse.ch/api/v1/",
        headers={"Auth-Key": auth_key, "Accept": "application/json",
                 "User-Agent": UA},
        data={"query": "get_info", "hash": _SAMPLE_HASH},
    )

    result["http"] = code

    if err:
        result["status"] = err
        return result

    if code == 200:
        query_status = (body or {}).get("query_status", "")
        data = (body or {}).get("data")

        if query_status == "":
            result["status"] = INVALID_RESPONSE
            return result

        if "unauthorized" in query_status.lower() or "invalid" in query_status.lower():
            result["status"] = AUTH_FAILED
            result["detail"] = {"query_status": query_status}
            return result

        detail: dict = {"query_status": query_status}

        # hash_not_found is still PASS — API responded correctly
        if isinstance(data, list) and data:
            entry = data[0]
            detail["sha256_hash"] = entry.get("sha256_hash")
            detail["file_type"]   = entry.get("file_type")
            detail["signature"]   = entry.get("signature")
        elif query_status in ("hash_not_found", "no_results"):
            detail["note"] = "Hash not in database (API is functional)"

        result["status"] = PASS
        result["detail"] = detail
    elif code in (401, 403):
        result["status"] = AUTH_FAILED
    elif code == 429:
        result["status"] = RATE_LIMITED
    else:
        result["status"] = FAILED

    return result


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def _display_detail(label: str, detail: dict) -> None:
    """Print non-sensitive detail fields for a PASS result."""
    if not detail:
        return
    console.print(f"  [dim]{label} details:[/]")
    for k, v in detail.items():
        if v is not None:
            console.print(f"    {k}: [cyan]{v}[/]")


def _build_summary_table(results: list[dict]) -> Table:
    tbl = Table(box=box.ROUNDED, show_header=True, header_style="bold white",
                highlight=False)
    tbl.add_column("Provider",   style="bold", min_width=14)
    tbl.add_column("Key",        min_width=8)
    tbl.add_column("HTTP",       min_width=6)
    tbl.add_column("Result",     min_width=18)

    for r in results:
        key_str  = "[bold green]FOUND[/]"   if r["key_status"] == "FOUND" else "[yellow]MISSING[/]"
        http_str = str(r["http"]) if r["http"] else "--"
        status   = r["status"] or FAILED
        colour   = STATUS_COLOURS.get(status, "white")
        tbl.add_row(r["provider"], key_str, http_str, f"[{colour}]{status}[/]")

    return tbl


def _print_summary(results: list[dict]) -> int:
    """Print totals and return exit code."""
    passed    = sum(1 for r in results if r["status"] == PASS)
    missing   = sum(1 for r in results if r["status"] == MISSING_KEY)
    rate_ltd  = sum(1 for r in results if r["status"] == RATE_LIMITED)
    failed    = sum(1 for r in results if r["status"] in
                    (AUTH_FAILED, NETWORK_ERROR, TIMEOUT_STATUS, INVALID_RESPONSE, FAILED))

    console.print(f"\n[bold green]API passed:[/]       {passed}")
    console.print(f"[bold red]API failed:[/]       {failed}")
    console.print(f"[yellow]API missing:[/]      {missing}")
    console.print(f"[yellow]API rate limited:[/] {rate_ltd}")

    if failed > 0:
        return 1
    if missing > 0 and failed == 0 and rate_ltd == 0:
        return 2
    if rate_ltd > 0 and failed == 0 and missing == 0:
        return 3
    return 0


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="test_api_connections",
        description="Read-only API connectivity checker (no data submitted).",
    )
    parser.add_argument(
        "--provider",
        default="all",
        choices=["all", "virustotal", "abuseipdb", "urlscan", "abusech"],
        help="Provider to test (default: all)",
    )
    args = parser.parse_args()

    # --- Step 1: key presence report ---
    check_env_keys()

    abusech_key = _resolve_abusech_key()

    results: list[dict] = []

    # --- Step 2: run selected tests ---
    run_all = args.provider == "all"

    if run_all or args.provider == "virustotal":
        console.print("[dim]Testing VirusTotal ...[/]")
        r = test_virustotal()
        results.append(r)
        if r["status"] == PASS:
            _display_detail("VirusTotal", r["detail"])
        console.print()

    if run_all or args.provider == "abuseipdb":
        console.print("[dim]Testing AbuseIPDB ...[/]")
        r = test_abuseipdb()
        results.append(r)
        if r["status"] == PASS:
            _display_detail("AbuseIPDB", r["detail"])
        console.print()

    if run_all or args.provider == "urlscan":
        console.print("[dim]Testing urlscan.io ...[/]")
        r = test_urlscan()
        results.append(r)
        if r["status"] == PASS:
            _display_detail("urlscan.io", r["detail"])
        console.print()

    if run_all or args.provider == "abusech":
        console.print("[dim]Testing ThreatFox (abuse.ch) ...[/]")
        r = test_threatfox(abusech_key)
        results.append(r)
        if r["status"] == PASS:
            _display_detail("ThreatFox", r["detail"])
        console.print()

        console.print("[dim]Testing MalwareBazaar (abuse.ch) ...[/]")
        r = test_malwarebazaar(abusech_key)
        results.append(r)
        if r["status"] == PASS:
            _display_detail("MalwareBazaar", r["detail"])
        console.print()

    # --- Step 3: summary table ---
    console.print("\n[bold cyan]== Connection Test Results ==[/]")
    console.print(_build_summary_table(results))

    exit_code = _print_summary(results)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
