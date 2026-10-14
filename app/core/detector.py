"""Signature-based detection engine.

Matches all enabled rules against each event. Runs against BOTH the raw
request and the normalized request: raw catches encoding-specific rules
(e.g. "Encoded Path Traversal") while normalized catches payloads that only
become recognizable after decoding. A rule fires at most once per event
even if it matches in both views, to avoid double-counting.
"""

from __future__ import annotations

from collections.abc import Iterable

from app.models.detection import DetectionResult
from app.models.event import LogEvent
from app.models.rule import DetectionMethod, DetectionRule


class RuleEngine:
    def __init__(self, rules: Iterable[DetectionRule]):
        self.rules: list[DetectionRule] = [r for r in rules]

    def enabled_rules(self) -> list[DetectionRule]:
        return [r for r in self.rules if r.enabled]

    def _candidate_text(self, event: LogEvent) -> str:
        parts = [
            event.request or "",
            event.path or "",
            event.username or "",
            event.user_agent or "",
            event.raw_line,
        ]
        return " ".join(p for p in parts if p)

    def detect_event(self, event: LogEvent) -> list[DetectionResult]:
        results: list[DetectionResult] = []
        raw_text = self._candidate_text(event)
        normalized_text = event.normalized_request or raw_text

        for rule in self.enabled_rules():
            pattern = rule.compiled()
            match = pattern.search(normalized_text) or pattern.search(raw_text)
            if not match:
                continue
            snippet = match.group(0)
            if len(snippet) > 120:
                snippet = snippet[:120] + "..."
            results.append(
                DetectionResult(
                    event=event,
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    category=rule.category.value,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    method=DetectionMethod.SIGNATURE,
                    matched_snippet=snippet,
                    recommendation=rule.recommendation,
                )
            )
        return results

    def detect(self, events: Iterable[LogEvent]) -> list[DetectionResult]:
        results: list[DetectionResult] = []
        for event in events:
            results.extend(self.detect_event(event))
        return results
