"""
scoring.py -- Multi-source IOC risk scoring engine.
"""
from __future__ import annotations

import logging
from typing import List

from src.models import EnrichmentResult, ProviderStatus, RiskScore, ScoreBreakdown, Verdict

logger = logging.getLogger(__name__)

# Tags that represent elevated risk
_HIGH_RISK_TAGS = frozenset({
    "tor", "vpn", "proxy", "botnet", "scanner", "c2", "ransomware",
    "phishing", "dropper", "loader", "stealer", "rat", "backdoor",
    "miner", "exploit", "trojan", "cobalt_strike", "brute_force",
    "ddos", "spam", "malvertising",
})


def calculate_risk(results: List[EnrichmentResult]) -> RiskScore:
    """
    Calculate IOC Reputation Risk from enrichment results.
    Returns a RiskScore with transparent breakdown.
    """
    factors:          list[ScoreBreakdown] = []
    raw_score:        float               = 0.0
    malicious_sources: list[str]          = []

    sources_attempted = len(results)
    sources_consulted = sources_attempted
    
    sources_matched = sum(1 for r in results if r.provider_status == ProviderStatus.MATCHED.value)
    sources_no_match = sum(1 for r in results if r.provider_status == ProviderStatus.NO_MATCH.value)
    sources_skipped = sum(1 for r in results if r.provider_status == ProviderStatus.SKIPPED.value)
    sources_error = sum(1 for r in results if r.provider_status == ProviderStatus.ERROR.value)
    sources_rate_limited = sum(1 for r in results if r.provider_status == ProviderStatus.RATE_LIMITED.value)
    sources_unauthorized = sum(1 for r in results if r.provider_status == ProviderStatus.UNAUTHORIZED.value)
    
    sources_successful = sources_matched + sources_no_match
    sources_with_data = sources_matched

    # ── Per-source contributions ─────────────────────────────────────────

    for r in results:
        if r.provider_status != ProviderStatus.MATCHED.value:
            continue

        src = r.source
        pts = 0.0
        reason = ""

        # ── VirusTotal ──────────────────────
        if src == "VirusTotal":
            stats = r.data.get("analysis_stats", {})
            mal = stats.get("malicious", 0)
            tot = stats.get("total", 0)
            if mal >= 30:
                pts = 30; reason = f"VT: {mal}/{tot} engines flagged malicious"
            elif mal >= 15:
                pts = 25; reason = f"VT: {mal}/{tot} engines flagged malicious"
            elif mal >= 8:
                pts = 20; reason = f"VT: {mal}/{tot} engines flagged malicious"
            elif mal >= 4:
                pts = 15; reason = f"VT: {mal}/{tot} engines flagged malicious"
            elif mal >= 1:
                pts = 10; reason = f"VT: {mal}/{tot} engines flagged malicious"
            elif r.verdict == Verdict.BENIGN.value:
                pts = -5; reason = "VirusTotal: benign verdict (all clean engines)"
            else:
                pts = 0; reason = "VirusTotal: no malicious detections"

            if pts != 0:
                if r.verdict == Verdict.MALICIOUS.value and pts > 0:
                    malicious_sources.append(src)
                factors.append(ScoreBreakdown(factor=f"vt_engines[{src}]", points=pts, reason=reason, provider=src))
                raw_score += pts

            # Reputation
            rep = r.data.get("reputation")
            if rep is not None:
                if rep < -10:
                    factors.append(ScoreBreakdown(factor="vt_reputation", points=10, reason=f"VT: negative reputation ({rep})", provider=src))
                    raw_score += 10
                    malicious_sources.append(src)
                elif rep > 10:
                    factors.append(ScoreBreakdown(factor="vt_reputation", points=-5, reason=f"VT: positive reputation ({rep})", provider=src))
                    raw_score -= 5

            # Total Votes
            votes = r.data.get("total_votes", {})
            mal_votes = votes.get("malicious", 0)
            if mal_votes >= 10:
                factors.append(ScoreBreakdown(factor="vt_votes", points=5, reason=f"VT: {mal_votes} community malicious votes", provider=src))
                raw_score += 5

        # ── AbuseIPDB ───────────────────
        elif src == "AbuseIPDB" and r.confidence is not None:
            conf = r.confidence
            if conf >= 90:
                pts = 25; reason = f"AbuseIPDB: {conf:.0f}% abuse confidence"
            elif conf >= 70:
                pts = 18; reason = f"AbuseIPDB: {conf:.0f}% abuse confidence"
            elif conf >= 50:
                pts = 12; reason = f"AbuseIPDB: {conf:.0f}% abuse confidence"
            elif conf >= 20:
                pts = 6;  reason = f"AbuseIPDB: {conf:.0f}% abuse confidence"
            else:
                pts = 0;  reason = f"AbuseIPDB: low confidence {conf:.0f}%"

            if pts > 0:
                malicious_sources.append(src)
                factors.append(ScoreBreakdown(factor=f"abuseipdb_confidence", points=pts, reason=reason, provider=src))
                raw_score += pts

        # ── GreyNoise ──────────────────────
        elif src == "GreyNoise":
            cls = (r.data.get("classification") or "").lower()
            if cls == "malicious":
                pts = 20; reason = "GreyNoise: classified as malicious"
                malicious_sources.append(src)
            elif cls == "unknown":
                pts = 5; reason = "GreyNoise: unknown classification (seen scanning)"
            elif cls == "benign":
                pts = -5; reason = "GreyNoise: classified as benign/legitimate scanner"
            else:
                pts = 0; reason = "GreyNoise: no classification"

            if pts != 0:
                factors.append(ScoreBreakdown(factor=f"greynoise_class", points=pts, reason=reason, provider=src))
                raw_score += pts

        # ── ThreatFox ────────────────────
        elif src == "ThreatFox" and r.confidence is not None:
            conf = float(r.confidence)
            if conf >= 90:
                pts = 22; reason = f"ThreatFox: IOC matched, confidence {conf:.0f}"
            elif conf >= 75:
                pts = 18; reason = f"ThreatFox: IOC matched, confidence {conf:.0f}"
            elif conf >= 50:
                pts = 12; reason = f"ThreatFox: IOC in feed, confidence {conf:.0f}"
            elif conf >= 1:
                pts = 7;  reason = f"ThreatFox: IOC in feed, confidence {conf:.0f}"
            else:
                pts = 0;  reason = "ThreatFox: zero confidence"

            if pts > 0:
                malicious_sources.append(src)
                factors.append(ScoreBreakdown(factor=f"threatfox_confidence", points=pts, reason=reason, provider=src))
                raw_score += pts

        # ── MalwareBazaar ───────────────────────────
        elif src == "MalwareBazaar":
            if r.verdict == Verdict.MALICIOUS.value:
                pts = 25
                reason = "MalwareBazaar: sample confirmed malicious"
                malicious_sources.append(src)
                factors.append(ScoreBreakdown(factor=f"malwarebazaar_confirmed", points=pts, reason=reason, provider=src))
                raw_score += pts

        # ── urlscan.io ─────────────────────────────
        elif src == "urlscan.io" and r.verdict != Verdict.UNKNOWN.value:
            if r.verdict == Verdict.MALICIOUS.value:
                pts = 15; reason = f"urlscan: {r.malicious_count or 1} malicious scan(s)"
                malicious_sources.append(src)
            elif r.verdict == Verdict.SUSPICIOUS.value:
                pts = 8;  reason = "urlscan: suspicious scan result"
            else:
                pts = -2; reason = "urlscan: scans return benign result"

            if pts != 0:
                factors.append(ScoreBreakdown(factor=f"urlscan_verdict", points=pts, reason=reason, provider=src))
                raw_score += pts

    # ── Multi-source corroboration bonus ────────────────────────
    unique_mal_sources = list(dict.fromkeys(malicious_sources))
    if len(unique_mal_sources) >= 2:
        bonus = min(15 * (len(unique_mal_sources) - 1), 30)
        src_list = ", ".join(unique_mal_sources[:3])
        factors.append(ScoreBreakdown(
            factor="multi_source_corroboration",
            points=bonus,
            reason=f"{len(unique_mal_sources)} independent sources flagged malicious: {src_list}",
            provider="composite",
        ))
        raw_score += bonus

    # ── High-risk tag bonus ─────────────────────────────────────
    all_tags: set[str] = set()
    for r in results:
        if r.provider_status == ProviderStatus.MATCHED.value:
            tags = r.data.get("tags", [])
            all_tags.update(t.lower() for t in tags)

    matched_risk_tags = _HIGH_RISK_TAGS & all_tags
    if matched_risk_tags:
        tag_pts = min(len(matched_risk_tags) * 2, 10)
        tag_list = ", ".join(sorted(matched_risk_tags)[:5])
        factors.append(ScoreBreakdown(
            factor="high_risk_tags",
            points=tag_pts,
            reason=f"High-risk tags detected: {tag_list}",
            provider="composite",
        ))
        raw_score += tag_pts

    # ── No-match penalty ──────────────
    if sources_no_match >= 3 and len(unique_mal_sources) == 0:
        factors.append(ScoreBreakdown(
            factor="multi_source_clean",
            points=-10,
            reason=f"{sources_no_match} sources returned NO_MATCH — likely clean",
            provider="composite",
        ))
        raw_score -= 10

    # ── Clamp and level ───────────────────────────────────────────────────
    final_score = max(0, min(100, int(round(raw_score))))

    if final_score >= 75:
        level = "CRITICAL"
    elif final_score >= 50:
        level = "HIGH"
    elif final_score >= 25:
        level = "MEDIUM"
    else:
        level = "LOW"

    return RiskScore(
        score=final_score,
        level=level,
        factors=factors,
        sources_consulted=sources_consulted,
        sources_attempted=sources_attempted,
        sources_successful=sources_successful,
        sources_matched=sources_matched,
        sources_no_match=sources_no_match,
        sources_skipped=sources_skipped,
        sources_error=sources_error,
        sources_rate_limited=sources_rate_limited,
        sources_unauthorized=sources_unauthorized,
        sources_with_data=sources_with_data
    )
