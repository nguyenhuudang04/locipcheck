"""
tests/test_providers_abusech.py -- Unit tests for ThreatFox and MalwareBazaar providers.
All HTTP calls are mocked. No real network requests.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch
import requests
import pytest

from src.models import Verdict


def _mock_response(status_code: int = 200, json_data: dict | None = None) -> MagicMock:
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.ok = status_code < 400
    if json_data is not None:
        mock_resp.json.return_value = json_data
    else:
        mock_resp.json.side_effect = ValueError("No JSON")
    return mock_resp


# ============================================================
# ThreatFox tests
# ============================================================

class TestThreatFox:
    def test_missing_key(self, monkeypatch):
        for k in ("ABUSECH_AUTH_KEY", "THREATFOX_AUTH_KEY",
                  "URLHAUS_AUTH_KEY", "MALWAREBAZAAR_AUTH_KEY"):
            monkeypatch.delenv(k, raising=False)
        from src.providers import threatfox
        result = threatfox.enrich("1.2.3.4", "ipv4")
        assert result.error is not None
        assert "not configured" in result.error

    @patch("src.providers.threatfox.build_session")
    def test_timeout(self, mock_build, monkeypatch):
        monkeypatch.setenv("ABUSECH_AUTH_KEY", "test-key")
        session = MagicMock()
        session.post.side_effect = requests.exceptions.Timeout()
        mock_build.return_value = session
        from src.providers import threatfox
        result = threatfox.enrich("1.2.3.4", "ipv4")
        assert result.error is not None

    @patch("src.providers.threatfox.build_session")
    def test_rate_limit_429(self, mock_build, monkeypatch):
        monkeypatch.setenv("ABUSECH_AUTH_KEY", "test-key")
        session = MagicMock()
        session.post.return_value = _mock_response(429)
        mock_build.return_value = session
        from src.providers import threatfox
        result = threatfox.enrich("1.2.3.4", "ipv4")
        assert result.error is not None
        assert "429" in result.error

    @patch("src.providers.threatfox.build_session")
    def test_malicious_high_confidence(self, mock_build, monkeypatch):
        monkeypatch.setenv("ABUSECH_AUTH_KEY", "test-key")
        session = MagicMock()
        session.post.return_value = _mock_response(200, {
            "query_status": "ok",
            "data": [
                {
                    "id": "12345",
                    "ioc": "185.220.101.5",
                    "ioc_type": "ip:port",
                    "threat_type": "botnet_cc",
                    "malware": "Mirai",
                    "confidence_level": 80,
                    "first_seen": "2024-01-01 00:00:00 UTC",
                    "last_seen": "2024-01-15 00:00:00 UTC",
                    "tags": ["tor", "botnet"],
                }
            ]
        })
        mock_build.return_value = session
        from src.providers import threatfox
        result = threatfox.enrich("185.220.101.5", "ipv4")
        assert result.verdict == Verdict.MALICIOUS.value
        assert result.confidence == 80.0
        assert result.malicious_count == 1
        assert "botnet_cc" in result.tags or "mirai" in result.tags

    @patch("src.providers.threatfox.build_session")
    def test_not_found_in_feed(self, mock_build, monkeypatch):
        monkeypatch.setenv("ABUSECH_AUTH_KEY", "test-key")
        session = MagicMock()
        session.post.return_value = _mock_response(200, {
            "query_status": "no_results",
            "data": None
        })
        mock_build.return_value = session
        from src.providers import threatfox
        result = threatfox.enrich("8.8.8.8", "ipv4")
        assert result.verdict == Verdict.UNKNOWN.value
        assert result.error is None

    @patch("src.providers.threatfox.build_session")
    def test_auth_rejected_via_query_status(self, mock_build, monkeypatch):
        monkeypatch.setenv("ABUSECH_AUTH_KEY", "bad-key")
        session = MagicMock()
        session.post.return_value = _mock_response(200, {
            "query_status": "unauthorized",
            "data": None
        })
        mock_build.return_value = session
        from src.providers import threatfox
        result = threatfox.enrich("1.2.3.4", "ipv4")
        assert result.error is not None

    @patch("src.providers.threatfox.build_session")
    def test_fallback_to_legacy_key(self, mock_build, monkeypatch):
        """THREATFOX_AUTH_KEY is used when ABUSECH_AUTH_KEY is missing."""
        monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)
        monkeypatch.setenv("THREATFOX_AUTH_KEY", "legacy-key")
        session = MagicMock()
        session.post.return_value = _mock_response(200, {
            "query_status": "no_results", "data": None
        })
        mock_build.return_value = session
        from src.providers import threatfox
        result = threatfox.enrich("1.2.3.4", "ipv4")
        # Should not be MISSING_KEY error
        assert "not configured" not in (result.error or "")

    @patch("src.providers.threatfox.build_session")
    def test_sha256_hash_lookup(self, mock_build, monkeypatch):
        monkeypatch.setenv("ABUSECH_AUTH_KEY", "test-key")
        session = MagicMock()
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        session.post.return_value = _mock_response(200, {
            "query_status": "ok",
            "data": [{
                "id": "99999",
                "ioc": sha256,
                "ioc_type": "sha256_hash",
                "threat_type": "payload",
                "malware": "Ransomware.Lockbit",
                "confidence_level": 90,
                "first_seen": "2023-06-01 00:00:00 UTC",
                "last_seen": "2023-12-01 00:00:00 UTC",
                "tags": ["ransomware"],
            }]
        })
        mock_build.return_value = session
        from src.providers import threatfox
        result = threatfox.enrich(sha256, "sha256")
        assert result.verdict == Verdict.MALICIOUS.value
        assert result.confidence == 90.0


# ============================================================
# MalwareBazaar tests
# ============================================================

class TestMalwareBazaar:
    def test_missing_key(self, monkeypatch):
        for k in ("ABUSECH_AUTH_KEY", "MALWAREBAZAAR_AUTH_KEY",
                  "THREATFOX_AUTH_KEY", "URLHAUS_AUTH_KEY"):
            monkeypatch.delenv(k, raising=False)
        from src.providers import malwarebazaar
        result = malwarebazaar.enrich("d41d8cd98f00b204e9800998ecf8427e")
        assert result.error is not None
        assert "not configured" in result.error

    @patch("src.providers.malwarebazaar.build_session")
    def test_timeout(self, mock_build, monkeypatch):
        monkeypatch.setenv("ABUSECH_AUTH_KEY", "test-key")
        session = MagicMock()
        session.post.side_effect = requests.exceptions.Timeout()
        mock_build.return_value = session
        from src.providers import malwarebazaar
        result = malwarebazaar.enrich("d41d8cd98f00b204e9800998ecf8427e")
        assert result.error is not None

    @patch("src.providers.malwarebazaar.build_session")
    def test_server_error_500_not_crash(self, mock_build, monkeypatch):
        """HTTP 500 from MalwareBazaar should return error, not crash."""
        monkeypatch.setenv("ABUSECH_AUTH_KEY", "test-key")
        session = MagicMock()
        session.post.return_value = _mock_response(500)
        mock_build.return_value = session
        from src.providers import malwarebazaar
        result = malwarebazaar.enrich("d41d8cd98f00b204e9800998ecf8427e")
        assert result.error is not None
        assert "500" in result.error

    @patch("src.providers.malwarebazaar.build_session")
    def test_hash_found_malicious(self, mock_build, monkeypatch):
        monkeypatch.setenv("ABUSECH_AUTH_KEY", "test-key")
        session = MagicMock()
        sha256 = "094fd325049b8a9cf6d3e5ef2a6d4cc6a567d7d49c35f8bb8dd9e3c6acf3d78d"
        session.post.return_value = _mock_response(200, {
            "query_status": "ok",
            "data": [{
                "sha256_hash": sha256,
                "file_type": "exe",
                "signature": "Ransomware.Ryuk",
                "tags": ["ransomware", "ryuk"],
                "first_seen": "2023-01-01 00:00:00",
                "last_seen": "2023-06-01 00:00:00",
                "reporter": "abuse_ch",
            }]
        })
        mock_build.return_value = session
        from src.providers import malwarebazaar
        result = malwarebazaar.enrich(sha256)
        assert result.verdict == Verdict.MALICIOUS.value
        assert result.confidence == 100.0
        assert "ransomware.ryuk" in result.tags or "ransomware" in result.tags

    @patch("src.providers.malwarebazaar.build_session")
    def test_hash_not_found_is_unknown(self, mock_build, monkeypatch):
        """Hash not in MalwareBazaar = UNKNOWN (not necessarily benign, just not known malware)."""
        monkeypatch.setenv("ABUSECH_AUTH_KEY", "test-key")
        session = MagicMock()
        session.post.return_value = _mock_response(200, {
            "query_status": "hash_not_found",
            "data": None
        })
        mock_build.return_value = session
        from src.providers import malwarebazaar
        result = malwarebazaar.enrich("d41d8cd98f00b204e9800998ecf8427e")
        assert result.verdict == Verdict.UNKNOWN.value

    @patch("src.providers.malwarebazaar.build_session")
    def test_rate_limit_429(self, mock_build, monkeypatch):
        monkeypatch.setenv("ABUSECH_AUTH_KEY", "test-key")
        session = MagicMock()
        session.post.return_value = _mock_response(429)
        mock_build.return_value = session
        from src.providers import malwarebazaar
        result = malwarebazaar.enrich("d41d8cd98f00b204e9800998ecf8427e")
        assert result.error is not None


# ============================================================
# Scoring integration: new sources contribute correctly
# ============================================================

class TestScoringWithNewProviders:
    def test_threatfox_high_confidence_adds_points(self):
        from src.models import EnrichmentResult
        from src.scoring import calculate_risk
        results = [
            EnrichmentResult(source="ThreatFox", verdict=Verdict.MALICIOUS.value, confidence=80.0)
        ]
        risk = calculate_risk(results)
        factor_names = [f.factor for f in risk.factors]
        assert "threatfox_confidence" in factor_names

    def test_malwarebazaar_confirmed_adds_points(self):
        from src.models import EnrichmentResult
        from src.scoring import calculate_risk
        results = [
            EnrichmentResult(source="MalwareBazaar", verdict=Verdict.MALICIOUS.value, confidence=100.0)
        ]
        risk = calculate_risk(results)
        factor_names = [f.factor for f in risk.factors]
        assert "malwarebazaar_confirmed" in factor_names

    def test_combined_vt_threatfox_malwarebazaar_high_score(self):
        from src.models import EnrichmentResult
        from src.scoring import calculate_risk
        results = [
            EnrichmentResult(source="VirusTotal", verdict=Verdict.MALICIOUS.value, malicious_count=20),
            EnrichmentResult(source="ThreatFox", verdict=Verdict.MALICIOUS.value, confidence=85.0),
            EnrichmentResult(source="MalwareBazaar", verdict=Verdict.MALICIOUS.value, confidence=100.0),
        ]
        risk = calculate_risk(results)
        assert risk.score >= 75
        assert risk.level == "CRITICAL"
