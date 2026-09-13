#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
main.py -- SOC IOC Enrichment Tool
Entry point: python main.py <IOC>

Supports: IPv4, IPv6, Domain, URL, MD5, SHA1, SHA256
"""
from __future__ import annotations

import os
import sys

# Force UTF-8 output on Windows to avoid cp1252 UnicodeEncodeError
os.environ.setdefault("PYTHONIOENCODING", "utf-8")

import argparse
import logging
from datetime import datetime, timezone

from dotenv import load_dotenv
from rich.console import Console

from src.detector import detect
from src.models import IOCReport, IOCType
from src.scoring import calculate_risk
from src import report as reporter

# Force safe encoding on Windows legacy terminals
console = Console(highlight=False, emoji=False)

# ---------------------------------------------------------------------------
# Load .env early so providers can read keys via os.getenv
# ---------------------------------------------------------------------------
load_dotenv()

logging.basicConfig(
    level=logging.WARNING,
    format="%(levelname)s [%(name)s] %(message)s",
)


def _enrich_ip(ioc: str, ioc_type: str) -> list:
    """Run all relevant providers for an IP address."""
    results = []
    from src.providers import greynoise, abuseipdb, virustotal, threatfox
    results.append(greynoise.enrich(ioc))
    results.append(abuseipdb.enrich(ioc))
    results.append(virustotal.enrich(ioc, ioc_type))
    results.append(threatfox.enrich(ioc, ioc_type))
    return results


def _enrich_domain(ioc: str) -> list:
    results = []
    from src.providers import virustotal, urlscan, threatfox, dns_provider
    results.append(virustotal.enrich(ioc, IOCType.DOMAIN.value))
    results.append(urlscan.enrich(ioc))
    results.append(threatfox.enrich(ioc, IOCType.DOMAIN.value))
    results.append(dns_provider.enrich(ioc, IOCType.DOMAIN.value))
    return results


def _enrich_url(ioc: str) -> list:
    results = []
    from src.providers import virustotal, urlscan, threatfox, dns_provider
    results.append(virustotal.enrich(ioc, IOCType.URL.value))
    results.append(urlscan.enrich(ioc))
    results.append(threatfox.enrich(ioc, IOCType.URL.value))
    results.append(dns_provider.enrich(ioc, IOCType.URL.value))
    return results


def _enrich_hash(ioc: str, ioc_type: str) -> list:
    results = []
    from src.providers import virustotal, threatfox, malwarebazaar
    results.append(virustotal.enrich(ioc, ioc_type))
    results.append(threatfox.enrich(ioc, ioc_type))
    results.append(malwarebazaar.enrich(ioc))
    return results


def run(ioc: str, output_dir: str = "reports") -> IOCReport | None:
    """
    Main enrichment pipeline.
    1. Detect IOC type
    2. Route to appropriate providers
    3. Score
    4. Report
    """
    ioc_type = detect(ioc)

    if ioc_type == IOCType.UNKNOWN:
        console.print(f"[bold red]ERROR[/] Cannot identify IOC type for: [yellow]{ioc}[/]")
        console.print("  Supported: IPv4, IPv6, Domain, URL, MD5, SHA1, SHA256")
        return None

    console.print(f"\n[bold cyan]>>[/] Enriching [bold white]{ioc}[/] (type: [cyan]{ioc_type.value}[/]) ...\n")

    # Route to providers
    if ioc_type in (IOCType.IPV4, IOCType.IPV6):
        results = _enrich_ip(ioc, ioc_type.value)
    elif ioc_type == IOCType.DOMAIN:
        results = _enrich_domain(ioc)
    elif ioc_type == IOCType.URL:
        results = _enrich_url(ioc)
    else:  # hashes
        results = _enrich_hash(ioc, ioc_type.value)

    # Build report
    ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    risk = calculate_risk(results)
    ioc_report = IOCReport(
        ioc=ioc,
        ioc_type=ioc_type.value,
        results=results,
        risk=risk,
        timestamp=ts,
    )

    # Display
    reporter.display_terminal(ioc_report)

    # Save files
    json_path = reporter.save_json(ioc_report, output_dir)
    md_path = reporter.save_markdown(ioc_report, output_dir)
    console.print(f"\n[dim]JSON report:[/] [link={json_path}]{json_path}[/link]")
    console.print(f"[dim]MD  report:[/] [link={md_path}]{md_path}[/link]\n")

    return ioc_report


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="soc-ioc-enrichment",
        description="SOC IOC Enrichment Tool — look up threat intelligence for an IOC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py 185.220.101.5
  python main.py malware.example.com
  python main.py https://phishing.site/login
  python main.py d41d8cd98f00b204e9800998ecf8427e
  python main.py --output-dir ./my_reports 8.8.8.8
        """,
    )
    parser.add_argument("iocs", nargs="*", help="IOCs to enrich (IP, domain, URL, or hash). You can pass multiple.")
    parser.add_argument(
        "-f", "--file",
        help="File containing list of IOCs (one per line) to enrich",
    )
    parser.add_argument(
        "--output-dir",
        default="reports",
        help="Directory to save JSON/Markdown reports (default: reports/)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    iocs_to_check = []
    if args.iocs:
        iocs_to_check.extend(args.iocs)
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as f:
                for line in f:
                    clean_line = line.strip()
                    if clean_line and not clean_line.startswith("#"):
                        iocs_to_check.append(clean_line)
        except Exception as e:
            console.print(f"[bold red]ERROR[/] Cannot read file {args.file}: {e}")
            sys.exit(1)

    if not iocs_to_check:
        parser.error("You must provide at least one IOC as arguments or via --file.")

    for ioc in iocs_to_check:
        run(ioc, output_dir=args.output_dir)


if __name__ == "__main__":
    main()
