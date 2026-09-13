from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class IOCType(str, Enum):
    IPV4    = "ipv4"
    IPV6    = "ipv6"
    DOMAIN  = "domain"
    URL     = "url"
    MD5     = "md5"
    SHA1    = "sha1"
    SHA256  = "sha256"
    UNKNOWN = "unknown"


class Verdict(str, Enum):
    MALICIOUS  = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN     = "benign"
    UNKNOWN    = "unknown"


class ProviderStatus(str, Enum):
    MATCHED          = "MATCHED"           # IOC found, data returned
    NO_MATCH         = "NO_MATCH"          # API OK but IOC not in database
    SKIPPED          = "SKIPPED"           # Missing API key, rate limit package limits, unsupported IOC type
    ERROR            = "ERROR"             # API error, timeout, malformed JSON
    RATE_LIMITED     = "RATE_LIMITED"      # HTTP 429
    UNAUTHORIZED     = "UNAUTHORIZED"      # HTTP 401 / 403
    PREMIUM_REQUIRED = "PREMIUM_REQUIRED"  # Forbidden for this module or tier


@dataclass
class EnrichmentResult:
    source:           str            = ""
    provider_status:  str            = ProviderStatus.NO_MATCH.value
    verdict:          str            = Verdict.UNKNOWN.value
    error:            Optional[str]  = None
    
    # Core extracted fields
    confidence:       Optional[float] = None
    malicious_count:  Optional[int]   = None
    reputation:       Optional[int]   = None
    
    # Timestamps
    first_observed:   Optional[str]   = None
    last_observed:    Optional[str]   = None
    last_analyzed:    Optional[str]   = None
    enrichment_queried_at: Optional[str] = None
    
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        out_data = {}
        if self.verdict != Verdict.UNKNOWN.value: out_data["verdict"] = self.verdict
        if self.confidence is not None: out_data["confidence"] = self.confidence
        if self.malicious_count is not None: out_data["malicious_count"] = self.malicious_count
        if self.reputation is not None: out_data["reputation"] = self.reputation
        if self.first_observed: out_data["first_observed"] = self.first_observed
        if self.last_observed: out_data["last_observed"] = self.last_observed
        if self.last_analyzed: out_data["last_analyzed"] = self.last_analyzed
        if self.enrichment_queried_at: out_data["enrichment_queried_at"] = self.enrichment_queried_at
        if self.error: out_data["error"] = self.error
        
        for k, v in self.data.items():
            if v is not None:
                out_data[k] = v
                
        return {
            "source": self.source,
            "status": self.provider_status,
            "data": out_data
        }


@dataclass
class ScoreBreakdown:
    factor:   str
    points:   float
    reason:   str
    provider: str = ""


@dataclass
class RiskScore:
    score:                int = 0
    level:                str = "LOW"
    factors:              list[ScoreBreakdown] = field(default_factory=list)
    sources_consulted:    int = 0
    sources_attempted:    int = 0
    sources_successful:   int = 0
    sources_matched:      int = 0
    sources_no_match:     int = 0
    sources_skipped:      int = 0
    sources_error:        int = 0
    sources_rate_limited: int = 0
    sources_unauthorized: int = 0
    sources_with_data:    int = 0

    def to_dict(self) -> dict:
        return {
            "score":                self.score,
            "level":                self.level,
            "sources_consulted":    self.sources_consulted,
            "sources_attempted":    self.sources_attempted,
            "sources_successful":   self.sources_successful,
            "sources_matched":      self.sources_matched,
            "sources_no_match":     self.sources_no_match,
            "sources_skipped":      self.sources_skipped,
            "sources_error":        self.sources_error,
            "sources_rate_limited": self.sources_rate_limited,
            "sources_unauthorized": self.sources_unauthorized,
            "sources_with_data":    self.sources_with_data,
            "factors": [
                {
                    "factor":   f.factor,
                    "points":   f.points,
                    "reason":   f.reason,
                    "provider": f.provider,
                }
                for f in self.factors
            ],
        }


@dataclass
class AlertContext:
    event_time:       Optional[str] = None
    hostname:         Optional[str] = None
    username:         Optional[str] = None
    source_ip:        Optional[str] = None
    destination:      Optional[str] = None
    action:           Optional[str] = None
    event_count:      Optional[int] = None
    log_source:       Optional[str] = None
    process_name:     Optional[str] = None
    command_line:     Optional[str] = None
    file_hash:        Optional[str] = None
    email_sender:     Optional[str] = None
    email_recipient:  Optional[str] = None
    
    def is_empty(self) -> bool:
        return all(v is None for v in [
            self.event_time, self.hostname, self.username, self.source_ip,
            self.destination, self.action, self.event_count, self.log_source,
            self.process_name, self.command_line, self.file_hash, 
            self.email_sender, self.email_recipient
        ])

    def to_dict(self) -> dict:
        return {k: v for k, v in {
            "event_time":       self.event_time,
            "hostname":         self.hostname,
            "username":         self.username,
            "source_ip":        self.source_ip,
            "destination":      self.destination,
            "action":           self.action,
            "event_count":      self.event_count,
            "log_source":       self.log_source,
            "process_name":     self.process_name,
            "command_line":     self.command_line,
            "file_hash":        self.file_hash,
            "email_sender":     self.email_sender,
            "email_recipient":  self.email_recipient,
        }.items() if v is not None and v != ""}


@dataclass
class ModulePagination:
    count:  int = 0
    cursor: Optional[str] = None
    next:   Optional[str] = None
    
    def to_dict(self) -> dict:
        return {
            "count":  self.count,
            "cursor": self.cursor,
            "next":   self.next,
        }

@dataclass
class ModuleResult:
    source:     str
    module:     str
    status:     str = ProviderStatus.NO_MATCH.value
    data:       Any = field(default_factory=dict)
    pagination: Optional[ModulePagination] = None
    
    def to_dict(self) -> dict:
        return {
            "source":     self.source,
            "module":     self.module,
            "status":     self.status,
            "data":       self.data,
            "pagination": self.pagination.to_dict() if self.pagination else None
        }


@dataclass
class IOCReport:
    lookup_id:     str = ""
    ioc:           str = ""
    canonical_ioc: str = ""
    ioc_type:      str = ""
    created_at:    str = ""
    results:   list[EnrichmentResult] = field(default_factory=list)
    risk:      Optional[RiskScore]    = None
    timestamp: str                    = ""
    report_validation_status: str     = "VALID"

    def to_dict(self) -> dict:
        return {
            "lookup_id":     self.lookup_id,
            "ioc":           self.ioc,
            "canonical_ioc": self.canonical_ioc,
            "ioc_type":      self.ioc_type,
            "created_at":    self.created_at,
            "timestamp":     self.timestamp,
            "report_validation_status": self.report_validation_status,
            "risk":          self.risk.to_dict() if self.risk else None,
            "results":       [r.to_dict() for r in self.results],
        }
