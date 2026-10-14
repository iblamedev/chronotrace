"""Verification script for Phase 2: Correlator + Severity Resolver + SQLite Storage.

Executes the complete pipeline:
  parse -> normalize -> detect -> correlate -> severity-resolve -> persist -> reload round trip.
Verifies against both sample logs: attacks.log and login-logs.txt.
"""

from __future__ import annotations

import sys
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.correlator import CorrelationEngine
from app.core.detector import RuleEngine
from app.core.normalizer import normalize_events
from app.core.parser import ParserRegistry
from app.core.severity import resolve_severity
from app.models.detection import Alert, AlertStatus, AnalysisSession
from app.models.rule import DetectionMethod
from app.storage.database import Database
from app.storage.repositories import (
    AlertRepo,
    EventRepo,
    RuleRepo,
    SessionRepo,
)

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "sample_data"
TEST_DB_PATH = Path(__file__).resolve().parent.parent / "tests" / "test_threatdesk.db"


def run_pipeline(path: Path, db: Database) -> None:
    print(f"\n{'=' * 75}\nANALYSIS & CORRELATION: {path.name}\n{'=' * 75}")

    # 1. Parse & Normalize
    parser = ParserRegistry()
    events = parser.parse_file(str(path))
    normalize_events(events)
    print(f"Parsed & normalized: {len(events)} events")

    # 2. Signature Detection
    rule_repo = RuleRepo(db)
    rules = rule_repo.get_enabled_rules()
    engine = RuleEngine(rules)
    sig_detections = engine.detect(events)
    print(f"Signature detections: {len(sig_detections)}")

    # 3. Behavioral Correlation
    correlator = CorrelationEngine()
    behavioral_detections = correlator.correlate(events, sig_detections)
    print(f"Behavioral (correlated) detections: {len(behavioral_detections)}")
    for b in behavioral_detections:
        print(
            f"  [BEHAVIORAL] {b.rule_name} (Sev: {b.severity.value.upper()}) IP={b.event.source_ip}"
        )
        print(f"               Snippet: {b.matched_snippet}")

    all_detections = sig_detections + behavioral_detections

    # 4. Severity Resolution & Alert Generation
    alerts: list[Alert] = []
    session_id = f"sess_{uuid.uuid4().hex[:8]}"
    now = datetime.now(timezone.utc)

    for d in all_detections:
        final_sev = resolve_severity(d, behavioral_detections)
        d.severity = final_sev
        alert_id = f"alt_{uuid.uuid4().hex[:8]}"
        alerts.append(
            Alert(
                alert_id=alert_id,
                detection=d,
                created_at=now,
                status=AlertStatus.NEW,
                notes=d.context_notes,
            )
        )

    # 5. Persist Session, Events, and Alerts
    session_repo = SessionRepo(db)
    event_repo = EventRepo(db)
    alert_repo = AlertRepo(db)

    sev_counts = dict(Counter(a.detection.severity.value for a in alerts))
    session = AnalysisSession(
        session_id=session_id,
        created_at=now,
        source_files=(str(path),),
        total_events=len(events),
        total_detections=len(alerts),
        severity_counts=sev_counts,
    )
    session_repo.save_session(session)
    event_repo.save_events(session_id, events)
    alert_repo.save_alerts(alerts, session_id)
    print(f"Persisted session {session_id} to SQLite DB")

    # 6. Reload from Database and Verify Round-Trip
    reloaded_session = session_repo.get_latest_session()
    assert reloaded_session is not None
    assert reloaded_session.session_id == session_id
    assert reloaded_session.total_events == len(events)
    assert reloaded_session.total_detections == len(alerts)

    reloaded_events = event_repo.get_events(session_id=session_id, limit=200)
    assert len(reloaded_events) == len(events)

    reloaded_alerts = alert_repo.get_alerts(session_id=session_id)
    assert len(reloaded_alerts) == len(alerts)

    # Verify signature vs behavioral counts in reloaded alerts
    sig_count = sum(
        1 for a in reloaded_alerts if a["method"] == DetectionMethod.SIGNATURE.value
    )
    beh_count = sum(
        1 for a in reloaded_alerts if a["method"] == DetectionMethod.BEHAVIORAL.value
    )
    print("Reload verification SUCCESS:")
    print(f"  Reloaded Events: {len(reloaded_events)} == Original {len(events)}")
    print(
        f"  Reloaded Alerts: {len(reloaded_alerts)} (Signature: {sig_count}, Behavioral: {beh_count})"
    )
    print(f"  Reloaded Severity distribution: {reloaded_session.severity_counts}")


def main() -> None:
    if TEST_DB_PATH.exists():
        TEST_DB_PATH.unlink()

    db = Database(TEST_DB_PATH)
    print("Database initialized and default rules seeded.")

    rule_repo = RuleRepo(db)
    all_rules = rule_repo.get_all_rules()
    print(f"Total rules seeded in DB: {len(all_rules)}")

    run_pipeline(SAMPLE_DIR / "attacks.log", db)
    run_pipeline(SAMPLE_DIR / "login-logs.txt", db)

    db.close()
    if TEST_DB_PATH.exists():
        TEST_DB_PATH.unlink()
    print("\nPhase 2 verification completed successfully!")


if __name__ == "__main__":
    main()
