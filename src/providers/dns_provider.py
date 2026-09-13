"""
dns_provider.py -- DNS & WHOIS enrichment for domains.
Provides: A, AAAA, CNAME, MX, NS, TXT lookups, plus domain registration info.
"""
from __future__ import annotations

import logging
import socket
from datetime import datetime, timezone

from src.models import EnrichmentResult, IOCType, ProviderStatus, Verdict

logger = logging.getLogger(__name__)

try:
    import dns.resolver
    import dns.exception
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False


def enrich(ioc: str, ioc_type: str) -> EnrichmentResult:
    queried_at = datetime.now(tz=timezone.utc).isoformat()
    result = EnrichmentResult(
        source="DNS & WHOIS",
        enrichment_queried_at=queried_at,
    )

    if ioc_type not in (IOCType.DOMAIN.value, IOCType.URL.value):
        result.provider_status = ProviderStatus.SKIPPED.value
        result.error = f"DNS enrichment skipped for {ioc_type}"
        return result

    # Extract domain if URL
    domain = ioc
    if ioc_type == IOCType.URL.value:
        try:
            from urllib.parse import urlparse
            parsed = urlparse(ioc if "://" in ioc else f"http://{ioc}")
            domain = parsed.netloc.split(":")[0]
            if not domain:
                raise ValueError
        except Exception:
            result.provider_status = ProviderStatus.SKIPPED.value
            result.error = "Could not extract domain from URL"
            return result

    result.provider_status = ProviderStatus.MATCHED.value
    result.verdict = Verdict.UNKNOWN.value

    if HAS_DNS:
        _do_dns_lookups(domain, result)
    else:
        result.error = "dnspython not installed, skipped advanced DNS."

    if HAS_WHOIS:
        _do_whois_lookup(domain, result)
    else:
        if result.error:
            result.error += " python-whois not installed."
        else:
            result.error = "python-whois not installed, skipped WHOIS."

    return result


def _do_dns_lookups(domain: str, result: EnrichmentResult) -> None:
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    
    records = {}
    resolved_ips = set()
    
    for rtype in ["A", "AAAA", "CNAME", "MX", "NS", "TXT"]:
        try:
            answers = resolver.resolve(domain, rtype)
            records[rtype] = [str(rdata) for rdata in answers]
            
            if rtype in ("A", "AAAA"):
                resolved_ips.update(records[rtype])
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            result.provider_status = ProviderStatus.NO_MATCH.value
            result.error = "NXDOMAIN - Domain does not exist"
            return
        except dns.exception.Timeout:
            pass
        except Exception as e:
            logger.debug("DNS %s lookup failed for %s: %s", rtype, domain, e)

    result.data["dns_records"] = records
    result.data["resolved_ips"] = list(resolved_ips)


def _do_whois_lookup(domain: str, result: EnrichmentResult) -> None:
    try:
        w = whois.whois(domain)
        if not w:
            return
        
        if w.registrar:
            result.data["registrar"] = w.registrar
            
        if w.creation_date:
            dates = w.creation_date if isinstance(w.creation_date, list) else [w.creation_date]
            if dates and dates[0]:
                dt = dates[0]
                result.data["creation_date"] = dt.isoformat() if hasattr(dt, 'isoformat') else str(dt)
                
                # Domain age
                if isinstance(dt, datetime):
                    age_days = (datetime.now() - dt).days
                    result.data["domain_age_days"] = age_days
                    
        if w.expiration_date:
            dates = w.expiration_date if isinstance(w.expiration_date, list) else [w.expiration_date]
            if dates and dates[0]:
                dt = dates[0]
                result.data["expiry_date"] = dt.isoformat() if hasattr(dt, 'isoformat') else str(dt)

        if w.name_servers:
            ns = w.name_servers if isinstance(w.name_servers, list) else [w.name_servers]
            result.data["nameservers"] = [str(n).lower() for n in ns]

        if w.dnssec:
            result.data["dnssec"] = w.dnssec
            
    except Exception as e:
        logger.debug("WHOIS lookup failed for %s: %s", domain, e)
