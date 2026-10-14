"""Models for detections, alerts, IOCs, and an analysis session."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from app.models.event import LogEvent
from app.models.rule import DetectionMethod, Severity


@dataclass
class DetectionResult:
    """One rule match against one event (or a correlated group, for behavioral)."""

    event: LogEvent
    rule_id: str
    rule_name: str
    category: str
    severity: Severity
    confidence: int
    method: DetectionMethod
    matched_snippet: str  # the substring that triggered the match
    recommendation: str = ""
    contributing_events: list[LogEvent] = field(default_factory=list)
    context_notes: str = ""


class AlertStatus(str, Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


@dataclass
class Alert:
    """A detection promoted to something an analyst tracks and dispositions."""

    alert_id: str
    detection: DetectionResult
    created_at: datetime
    status: AlertStatus = AlertStatus.NEW
    notes: str = ""


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    USER_AGENT = "user_agent"
    URI = "uri"
    EMAIL = "email"
    CUSTOM = "custom"


@dataclass
class IOC:
    """A locally-managed threat-intelligence indicator."""

    ioc_id: str
    indicator: str
    ioc_type: IOCType
    severity: Severity
    confidence: int
    source: str
    first_seen: datetime
    last_seen: datetime
    notes: str = ""
    tags: tuple[str, ...] = field(default_factory=tuple)


@dataclass
class BlocklistEntry:
    """A locally-tracked suspicious/malicious source IP."""

    ip: str
    reason: str
    confidence: int
    added_at: datetime
    suggested_by_detection: str | None = None  # rule_id that suggested this


@dataclass
class AnalysisSession:
    """One load-and-analyze run: which files, how many events, summary counts."""

    session_id: str
    created_at: datetime
    source_files: tuple[str, ...]
    total_events: int = 0
    total_detections: int = 0
    severity_counts: dict[str, int] = field(default_factory=dict)
