"""Manual verification script for Phase 1: parser + normalizer + detector.

Not a pytest suite yet (that comes with the full test suite in a later
phase) — this is a quick sanity run against the two real sample logs to
confirm the auth-log parsing gap is fixed and detection fires as expected.
Run with: python -m tests.test_phase1
"""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.detector import RuleEngine
from app.core.normalizer import normalize_events
from app.core.parser import ParserRegistry
from app.models.event import ParseQuality
from app.rules.default_rules import get_default_rules

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "sample_data"


def run_on_file(path: Path) -> None:
    print(f"\n{'=' * 70}\n{path.name}\n{'=' * 70}")

    registry = ParserRegistry()
    events = registry.parse_file(str(path))
    normalize_events(events)

    quality_counts = Counter(e.parse_quality.value for e in events)
    parser_counts = Counter(e.parser_used for e in events)
    print(f"Total lines: {len(events)}")
    print(f"Parse quality: {dict(quality_counts)}")
    print(f"Parser used:   {dict(parser_counts)}")

    unparsed = [e for e in events if e.parse_quality == ParseQuality.UNPARSED]
    if unparsed:
        print(f"UNPARSED lines ({len(unparsed)}):")
        for e in unparsed[:5]:
            print(f"  line {e.line_number}: {e.raw_line.strip()[:100]}")

    print("\nFirst 3 parsed events:")
    for e in events[:3]:
        print(
            f"  [{e.parser_used}] ip={e.source_ip} time={e.timestamp} "
            f"status={e.status_code} user={e.username} request={e.display_request()[:70]}"
        )

    engine = RuleEngine(get_default_rules())
    detections = engine.detect(events)
    print(f"\nDetections: {len(detections)}")

    by_rule = Counter(d.rule_name for d in detections)
    for rule_name, count in by_rule.most_common():
        print(f"  {rule_name}: {count}")

    by_severity = Counter(d.severity.value for d in detections)
    print(f"\nBy severity: {dict(by_severity)}")

    print("\nSample detections:")
    for d in detections[:6]:
        print(
            f"  [{d.severity.value.upper():8}] {d.rule_name:30} ip={d.event.source_ip:16} "
            f"snippet={d.matched_snippet[:50]!r}"
        )


if __name__ == "__main__":
    run_on_file(SAMPLE_DIR / "attacks.log")
    run_on_file(SAMPLE_DIR / "login-logs.txt")
