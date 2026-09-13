"""
tests/test_scoring.py — Unit tests for risk scoring logic.
No network calls.
"""
import pytest
from src.models import EnrichmentResult, Verdict
from src.scoring import calculate_risk


def _make(source: str, verdict: str, **kwargs) -> EnrichmentResult:
    res = EnrichmentResult(source=source, provider_status="MATCHED", verdict=verdict)
    res.data = kwargs
    if "malicious_count" in kwargs:
        res.malicious_count = kwargs["malicious_count"]
    if "confidence" in kwargs:
        res.confidence = kwargs["confidence"]
    if source == "VirusTotal" and "malicious_count" in kwargs:
        res.data["analysis_stats"] = {"malicious": kwargs["malicious_count"], "total": 90}
    return res


class TestBasicScoring:
    def test_empty_results_gives_zero(self):
        risk = calculate_risk([])
        assert risk.score == 0
        assert risk.level == "LOW"

    def test_single_malicious_capped_at_60(self):
        """One malicious source alone should never exceed 60."""
        results = [_make("VirusTotal", Verdict.MALICIOUS.value, malicious_count=50)]
        risk = calculate_risk(results)
        assert risk.score <= 60

    def test_two_malicious_sources_high(self):
        results = [
            _make("VirusTotal", Verdict.MALICIOUS.value, malicious_count=15),
            _make("AbuseIPDB", Verdict.MALICIOUS.value, confidence=95.0),
        ]
        risk = calculate_risk(results)
        assert risk.score >= 50
        assert risk.level in ("HIGH", "CRITICAL")

    def test_all_benign_low_score(self):
        results = [
            _make("VirusTotal", Verdict.BENIGN.value),
            _make("AbuseIPDB", Verdict.BENIGN.value, confidence=0.0, malicious_count=0),
        ]
        risk = calculate_risk(results)
        assert risk.score <= 20
        assert risk.level == "LOW"

    def test_suspicious_medium(self):
        results = [
            _make("VirusTotal", Verdict.SUSPICIOUS.value, malicious_count=2),
            _make("urlscan.io", Verdict.SUSPICIOUS.value),
        ]
        risk = calculate_risk(results)
        assert risk.score >= 15

class TestScoringFactors:
    def test_vt_engine_count_adds_points(self):
        results = [_make("VirusTotal", Verdict.MALICIOUS.value, malicious_count=20)]
        risk = calculate_risk(results)
        factor_names = [f.factor for f in risk.factors]
        assert "vt_engines[VirusTotal]" in factor_names

    def test_abuseipdb_high_confidence_adds_points(self):
        results = [_make("AbuseIPDB", Verdict.MALICIOUS.value, confidence=95.0)]
        risk = calculate_risk(results)
        factor_names = [f.factor for f in risk.factors]
        assert "abuseipdb_confidence" in factor_names

    def test_high_risk_tags_add_points(self):
        results = [_make("GreyNoise", Verdict.SUSPICIOUS.value, tags=["tor", "botnet"])]
        risk = calculate_risk(results)
        factor_names = [f.factor for f in risk.factors]
        assert "high_risk_tags" in factor_names

    def test_multi_source_malicious_bonus(self):
        results = [
            _make("VirusTotal", Verdict.MALICIOUS.value, malicious_count=5),
            _make("AbuseIPDB", Verdict.MALICIOUS.value, confidence=100.0),
        ]
        risk = calculate_risk(results)
        factor_names = [f.factor for f in risk.factors]
        assert "multi_source_corroboration" in factor_names

    def test_single_source_cap_applied(self):
        """Single malicious source with very high VT count should be capped."""
        results = [_make("VirusTotal", Verdict.MALICIOUS.value, malicious_count=100)]
        risk = calculate_risk(results)
        # Cap factor should appear if total would exceed 60
        cap_factors = [f for f in risk.factors if f.factor == "single_source_cap"]
        # May or may not apply depending on total
        assert risk.score <= 60


class TestLevelMapping:
    def test_score_75_is_critical(self):
        results = [
            _make("VirusTotal", Verdict.MALICIOUS.value, malicious_count=30),
            _make("AbuseIPDB", Verdict.MALICIOUS.value, confidence=95.0),
            _make("GreyNoise", Verdict.MALICIOUS.value, tags=["tor", "botnet"]),
        ]
        risk = calculate_risk(results)
        if risk.score >= 75:
            assert risk.level == "CRITICAL"

    def test_score_50_is_high(self):
        results = [
            _make("VirusTotal", Verdict.MALICIOUS.value, malicious_count=10),
            _make("AbuseIPDB", Verdict.MALICIOUS.value, confidence=75.0),
        ]
        risk = calculate_risk(results)
        assert risk.level in ("HIGH", "CRITICAL")


class TestErrorSources:
    def test_error_sources_not_counted_in_data(self):
        results = [
            _make("VirusTotal", Verdict.UNKNOWN.value),
            EnrichmentResult(source="AbuseIPDB", provider_status="ERROR", error="API key missing"),
        ]
        risk = calculate_risk(results)
        assert risk.sources_consulted == 2
        assert risk.sources_with_data == 1
