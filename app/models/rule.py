"""Detection rule definitions.

Rules are data, not code paths — this is what lets the rules_view UI list,
enable/disable, edit, and persist them without touching detector.py.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from re import Pattern


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[self.value]


class DetectionMethod(str, Enum):
    """Distinguishes single-line signature matches from multi-event correlation."""

    SIGNATURE = "signature"
    BEHAVIORAL = "behavioral"


class RuleCategory(str, Enum):
    AUTH = "Authentication"
    INJECTION = "Injection"
    XSS = "Cross-Site Scripting"
    TRAVERSAL = "Path Traversal / File Access"
    SSRF = "SSRF / Network Abuse"
    RECON = "Reconnaissance"
    EXFIL = "Data Exfiltration"
    REDIRECT = "Open Redirect"
    ANOMALY = "Anomaly / Protocol"
    UPLOAD = "File Upload Abuse"


@dataclass
class DetectionRule:
    """A single detection rule: built-in or custom, signature-based.

    `pattern` is compiled lazily via `compiled()` so rules can be constructed
    (e.g. loaded from SQLite) before their regex is validated, and so a bad
    custom-rule regex fails loudly and locally rather than crashing detection
    of every other rule.
    """

    rule_id: str
    name: str
    category: RuleCategory
    description: str
    pattern: str
    severity: Severity
    confidence: int = 80  # 0-100, analyst-facing confidence score
    enabled: bool = True
    tags: tuple[str, ...] = field(default_factory=tuple)
    recommendation: str = ""
    is_builtin: bool = True
    method: DetectionMethod = DetectionMethod.SIGNATURE

    _compiled: Pattern[str] | None = field(default=None, repr=False, compare=False)

    def compiled(self) -> Pattern[str]:
        if self._compiled is None:
            self._compiled = re.compile(self.pattern, re.IGNORECASE)
        return self._compiled

    def validate(self) -> str | None:
        """Returns an error message if the regex is invalid, else None."""
        try:
            re.compile(self.pattern)
        except re.error as exc:
            return f"Invalid regex: {exc}"
        return None
