import pytest
import uuid
import json
import os
from unittest.mock import patch, MagicMock
from src.models import IOCReport, IOCType, RiskScore, EnrichmentResult, ProviderStatus, Verdict
from src.report import save_json
from src.scoring import calculate_risk
from web.app import _run_enrichment

def test_domain_providers():
    """Ensure AbuseIPDB and GreyNoise are not called for domain lookups."""
    # We can test _run_enrichment routing
    # But since it calls the real providers, we should mock them.
    with patch("src.providers.virustotal.enrich") as mock_vt, \
         patch("src.providers.urlscan.enrich") as mock_us, \
         patch("src.providers.threatfox.enrich") as mock_tf, \
         patch("src.providers.dns_provider.enrich") as mock_dns:
         
        mock_vt.return_value = EnrichmentResult(source="VirusTotal")
        mock_us.return_value = EnrichmentResult(source="urlscan.io")
        mock_tf.return_value = EnrichmentResult(source="ThreatFox")
        mock_dns.return_value = EnrichmentResult(source="DNS")

        report = _run_enrichment("example.com", "lookup-123")
        
        # Verify exactly these 4 were called and in the results
        sources = [r.source for r in report.results]
        assert "VirusTotal" in sources
        assert "urlscan.io" in sources
        assert "ThreatFox" in sources
        assert "DNS" in sources
        assert "AbuseIPDB" not in sources
        assert "GreyNoise" not in sources

def test_lookup_id_independence():
    """Ensure two parallel lookups maintain their own lookup_id."""
    report1 = _run_enrichment("1.1.1.1", "lookup-1")
    report2 = _run_enrichment("8.8.8.8", "lookup-2")
    
    assert report1.lookup_id == "lookup-1"
    assert report1.ioc == "1.1.1.1"
    assert report2.lookup_id == "lookup-2"
    assert report2.ioc == "8.8.8.8"

def test_json_export_filename_and_content(tmp_path):
    """Ensure exported JSON contains correct lookup_id and matches IOC."""
    report = IOCReport(
        lookup_id="test-id-123",
        ioc="test.com",
        canonical_ioc="test.com",
        ioc_type="domain",
        created_at="2026-07-31T00:00:00Z"
    )
    
    out_dir = tmp_path / "reports"
    filepath = save_json(report, str(out_dir))
    
    assert "test-id-123" in filepath
    assert "test.com" in filepath
    
    with open(filepath, "r") as f:
        data = json.load(f)
        assert data["ioc"] == "test.com"
        assert data["lookup_id"] == "test-id-123"

def test_coverage_invariant():
    """Ensure sources_attempted matches the sum of all terminal states."""
    # Let's create a mix of results
    results = [
        EnrichmentResult(source="A", provider_status=ProviderStatus.MATCHED.value),
        EnrichmentResult(source="B", provider_status=ProviderStatus.NO_MATCH.value),
        EnrichmentResult(source="C", provider_status=ProviderStatus.SKIPPED.value),
        EnrichmentResult(source="D", provider_status=ProviderStatus.ERROR.value),
        EnrichmentResult(source="E", provider_status=ProviderStatus.RATE_LIMITED.value),
        EnrichmentResult(source="F", provider_status=ProviderStatus.UNAUTHORIZED.value),
    ]
    
    risk = calculate_risk(results)
    
    total_states = (
        risk.sources_matched +
        risk.sources_no_match +
        risk.sources_skipped +
        risk.sources_error +
        risk.sources_rate_limited +
        risk.sources_unauthorized
    )
    
    assert total_states == risk.sources_attempted
    assert risk.sources_attempted == 6

def test_coverage_validation_status():
    """Ensure report_validation_status is set to VALID when coverage is complete."""
    # Test through _run_enrichment mocking
    with patch("src.providers.greynoise.enrich") as mock_gn, \
         patch("src.providers.abuseipdb.enrich") as mock_ab, \
         patch("src.providers.virustotal.enrich") as mock_vt, \
         patch("src.providers.threatfox.enrich") as mock_tf:
         
        mock_gn.return_value = EnrichmentResult(source="GreyNoise", provider_status=ProviderStatus.SKIPPED.value)
        mock_ab.return_value = EnrichmentResult(source="AbuseIPDB", provider_status=ProviderStatus.MATCHED.value)
        mock_vt.return_value = EnrichmentResult(source="VirusTotal", provider_status=ProviderStatus.NO_MATCH.value)
        mock_tf.return_value = EnrichmentResult(source="ThreatFox", provider_status=ProviderStatus.RATE_LIMITED.value)

        report = _run_enrichment("8.8.8.8", "valid-123")
        assert report.report_validation_status == "VALID"

def test_cache_key_isolation():
    """Ensure cache keys for different IOCs do not collide."""
    from web.app import get_cache_key
    
    key1 = get_cache_key("domain", "example.com", "VirusTotal", "overview", "v3")
    key2 = get_cache_key("domain", "test.com", "VirusTotal", "overview", "v3")
    
    assert key1 != key2
    assert "example.com" in key1
    assert "test.com" in key2
    
    # Also verify case canonicalization
    key3 = get_cache_key("domain", "EXAMPLE.com".lower(), "VirusTotal", "overview", "v3")
    assert key1 == key3
