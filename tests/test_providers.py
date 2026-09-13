"""
tests/test_providers.py — Unit tests for API providers.
All HTTP calls are mocked — no real network requests.
Tests cover: timeout, 429, missing API key, 404, valid response.
"""
from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest
import requests

from src.models import Verdict


# ============================================================
# Helper mock factories
# ============================================================

def _mock_response(status_code: int = 200, json_data: dict | None = None) -> MagicMock:
    """Create a mock requests.Response."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.ok = status_code < 400
    if json_data is not None:
        mock_resp.json.return_value = json_data
    else:
        mock_resp.json.side_effect = ValueError("No JSON")
    return mock_resp


# ============================================================
# GreyNoise tests
# ============================================================

class TestGreyNoise:
    def test_missing_api_key(self, monkeypatch):
        monkeypatch.delenv("GREYNOISE_API_KEY", raising=False)
        from src.providers import greynoise
        result = greynoise.enrich("1.2.3.4")
        assert result.error is not None
        assert "not configured" in result.error

    @patch("src.providers.greynoise.build_session")
    def test_timeout(self, mock_build, monkeypatch):
        monkeypatch.setenv("GREYNOISE_API_KEY", "test-key")
        mock_session = MagicMock()
        mock_session.get.side_effect = requests.exceptions.Timeout()
        mock_build.return_value = mock_session
        from src.providers import greynoise
        result = greynoise.enrich("1.2.3.4")
        assert result.error is not None
        assert "timed out" in result.error.lower()

    @patch("src.providers.greynoise.build_session")
    def test_rate_limit_429(self, mock_build, monkeypatch):
        monkeypatch.setenv("GREYNOISE_API_KEY", "test-key")
        mock_session = MagicMock()
        mock_session.get.return_value = _mock_response(429)
        mock_build.return_value = mock_session
        from src.providers import greynoise
        with patch("src.http_client.time.sleep"):  # don't actually sleep
            result = greynoise.enrich("1.2.3.4")
        assert result.error is not None

    @patch("src.providers.greynoise.build_session")
    def test_malicious_verdict(self, mock_build, monkeypatch):
        monkeypatch.setenv("GREYNOISE_API_KEY", "test-key")
        mock_session = MagicMock()
        mock_session.get.return_value = _mock_response(200, {
            "classification": "malicious",
            "noise": True,
            "riot": False,
            "country": "RU",
            "name": "Evil Corp",
            "last_seen": "2024-01-01",
        })
        mock_build.return_value = mock_session
        from src.providers import greynoise
        result = greynoise.enrich("185.220.101.5")
        assert result.verdict == Verdict.MALICIOUS.value
        assert result.country == "RU"
        assert result.source == "GreyNoise"

    @patch("src.providers.greynoise.build_session")
    def test_404_not_found(self, mock_build, monkeypatch):
        monkeypatch.setenv("GREYNOISE_API_KEY", "test-key")
        mock_session = MagicMock()
        mock_session.get.return_value = _mock_response(404)
        mock_build.return_value = mock_session
        from src.providers import greynoise
        result = greynoise.enrich("1.2.3.4")
        assert result.error is not None


# ============================================================
# AbuseIPDB tests
# ============================================================

class TestAbuseIPDB:
    def test_missing_api_key(self, monkeypatch):
        monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
        from src.providers import abuseipdb
        result = abuseipdb.enrich("1.2.3.4")
        assert result.error is not None
        assert "not configured" in result.error

    @patch("src.providers.abuseipdb.build_session")
    def test_timeout(self, mock_build, monkeypatch):
        monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")
        mock_session = MagicMock()
        mock_session.get.side_effect = requests.exceptions.Timeout()
        mock_build.return_value = mock_session
        from src.providers import abuseipdb
        result = abuseipdb.enrich("1.2.3.4")
        assert result.error is not None

    @patch("src.providers.abuseipdb.build_session")
    def test_high_abuse_score_malicious(self, mock_build, monkeypatch):
        monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")
        mock_session = MagicMock()
        mock_session.get.return_value = _mock_response(200, {
            "data": {
                "abuseConfidenceScore": 95,
                "totalReports": 200,
                "countryCode": "CN",
                "isp": "Some ISP",
                "lastReportedAt": "2024-01-15T00:00:00+00:00",
                "usageType": "Data Center/Web Hosting/Transit",
            }
        })
        mock_build.return_value = mock_session
        from src.providers import abuseipdb
        result = abuseipdb.enrich("185.220.101.5")
        assert result.verdict == Verdict.MALICIOUS.value
        assert result.confidence == 95.0
        assert result.malicious_count == 200

    @patch("src.providers.abuseipdb.build_session")
    def test_rate_limit_429(self, mock_build, monkeypatch):
        monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")
        mock_session = MagicMock()
        mock_session.get.return_value = _mock_response(429)
        mock_build.return_value = mock_session
        from src.providers import abuseipdb
        with patch("src.http_client.time.sleep"):
            result = abuseipdb.enrich("1.2.3.4")
        assert result.error is not None

    @patch("src.providers.abuseipdb.build_session")
    def test_clean_ip_benign(self, mock_build, monkeypatch):
        monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")
        mock_session = MagicMock()
        mock_session.get.return_value = _mock_response(200, {
            "data": {
                "abuseConfidenceScore": 0,
                "totalReports": 0,
                "countryCode": "US",
                "isp": "Google LLC",
                "lastReportedAt": None,
                "usageType": "Search Engine Spider",
            }
        })
        mock_build.return_value = mock_session
        from src.providers import abuseipdb
        result = abuseipdb.enrich("8.8.8.8")
        assert result.verdict == Verdict.BENIGN.value


# ============================================================
# VirusTotal tests
# ============================================================

class TestVirusTotal:
    def test_missing_api_key(self, monkeypatch):
        monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
        from src.providers import virustotal
        result = virustotal.enrich("1.2.3.4", "ipv4")
        assert result.error is not None
        assert "not configured" in result.error

    @patch("src.providers.virustotal.build_session")
    def test_timeout(self, mock_build, monkeypatch):
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")
        mock_session = MagicMock()
        mock_session.get.side_effect = requests.exceptions.Timeout()
        mock_build.return_value = mock_session
        from src.providers import virustotal
        result = virustotal.enrich("1.2.3.4", "ipv4")
        assert result.error is not None

    @patch("src.providers.virustotal.build_session")
    def test_malicious_ip(self, mock_build, monkeypatch):
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")
        mock_session = MagicMock()
        mock_session.get.return_value = _mock_response(200, {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 15,
                        "suspicious": 2,
                        "harmless": 50,
                        "undetected": 5,
                    },
                    "reputation": -20,
                    "country": "RU",
                    "asn": 12345,
                    "as_owner": "Evil Hosting",
                    "tags": ["tor", "scanner"],
                }
            }
        })
        mock_build.return_value = mock_session
        from src.providers import virustotal
        result = virustotal.enrich("185.220.101.5", "ipv4")
        assert result.verdict == Verdict.MALICIOUS.value
        assert result.malicious_count == 15
        assert result.country == "RU"

    @patch("src.providers.virustotal.build_session")
    def test_rate_limit_429(self, mock_build, monkeypatch):
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")
        mock_session = MagicMock()
        mock_session.get.return_value = _mock_response(429)
        mock_build.return_value = mock_session
        from src.providers import virustotal
        with patch("src.http_client.time.sleep"):
            result = virustotal.enrich("1.2.3.4", "ipv4")
        assert result.error is not None

    @patch("src.providers.virustotal.build_session")
    def test_sha256_hash_lookup(self, mock_build, monkeypatch):
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")
        mock_session = MagicMock()
        mock_session.get.return_value = _mock_response(200, {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 40,
                        "suspicious": 5,
                        "harmless": 0,
                        "undetected": 10,
                    },
                    "first_submission_date": 1609459200,
                    "last_modification_date": 1672531200,
                    "tags": ["ransomware"],
                }
            }
        })
        mock_build.return_value = mock_session
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        from src.providers import virustotal
        result = virustotal.enrich(sha256, "sha256")
        assert result.verdict == Verdict.MALICIOUS.value
        assert result.malicious_count == 40


# ============================================================
# urlscan tests
# ============================================================

class TestURLScan:
    def test_missing_api_key(self, monkeypatch):
        monkeypatch.delenv("URLSCAN_API_KEY", raising=False)
        from src.providers import urlscan
        result = urlscan.enrich("evil.com")
        assert result.error is not None
        assert "not configured" in result.error

    @patch("src.providers.urlscan.build_session")
    def test_timeout(self, mock_build, monkeypatch):
        monkeypatch.setenv("URLSCAN_API_KEY", "test-key")
        mock_session = MagicMock()
        mock_session.get.side_effect = requests.exceptions.Timeout()
        mock_build.return_value = mock_session
        from src.providers import urlscan
        result = urlscan.enrich("evil.com")
        assert result.error is not None

    @patch("src.providers.urlscan.build_session")
    def test_malicious_domain(self, mock_build, monkeypatch):
        monkeypatch.setenv("URLSCAN_API_KEY", "test-key")
        mock_session = MagicMock()
        mock_session.get.return_value = _mock_response(200, {
            "total": 5,
            "results": [
                {
                    "verdicts": {"overall": {"malicious": True, "score": 80, "tags": ["phishing"]}},
                    "page": {"country": "US", "asnname": "Bad Hosting", "asn": "AS12345"},
                    "task": {"time": "2024-01-15T00:00:00.000Z"},
                    "result": "https://urlscan.io/result/abc123/",
                },
                {
                    "verdicts": {"overall": {"malicious": True, "score": 75, "tags": ["phishing"]}},
                    "page": {"country": "US", "asnname": "Bad Hosting", "asn": "AS12345"},
                    "task": {"time": "2024-01-10T00:00:00.000Z"},
                    "result": "https://urlscan.io/result/def456/",
                },
            ]
        })
        mock_build.return_value = mock_session
        from src.providers import urlscan
        result = urlscan.enrich("phishing.example.com")
        assert result.verdict == Verdict.MALICIOUS.value
        assert result.malicious_count == 2

    @patch("src.providers.urlscan.build_session")
    def test_rate_limit_429(self, mock_build, monkeypatch):
        monkeypatch.setenv("URLSCAN_API_KEY", "test-key")
        mock_session = MagicMock()
        mock_session.get.return_value = _mock_response(429)
        mock_build.return_value = mock_session
        from src.providers import urlscan
        with patch("src.http_client.time.sleep"):
            result = urlscan.enrich("evil.com")
        assert result.error is not None

    @patch("src.providers.urlscan.build_session")
    def test_no_scans_found(self, mock_build, monkeypatch):
        monkeypatch.setenv("URLSCAN_API_KEY", "test-key")
        mock_session = MagicMock()
        mock_session.get.return_value = _mock_response(200, {"total": 0, "results": []})
        mock_build.return_value = mock_session
        from src.providers import urlscan
        result = urlscan.enrich("new-domain.io")
        assert result.error is not None or result.verdict == Verdict.UNKNOWN.value
