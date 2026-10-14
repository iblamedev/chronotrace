"""Verification script for PDF Report generation in ChronoTrace.

Runs both sample logs (attacks.log and login-logs.txt), creates an analysis session,
persists it, and generates a real PDF report using ReportLab.
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
from app.core.report_generator import SOCReportGenerator
from app.core.severity import resolve_severity
from app.models.detection import Alert, AlertStatus, AnalysisSession
from app.storage.database import Database
from app.storage.repositories import AlertRepo, EventRepo, RuleRepo, SessionRepo

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "sample_data"
PDF_OUT = Path(__file__).resolve().parent.parent / "chronotrace_test_report.pdf"


def main() -> None:
    print("Initializing database and ingesting sample logs for PDF report...")
    db = Database(":memory:")
    rule_repo = RuleRepo(db)
    session_repo = SessionRepo(db)
    event_repo = EventRepo(db)
    alert_repo = AlertRepo(db)

    # Ingest both sample logs
    parser = ParserRegistry()
    events = []
    events.extend(parser.parse_file(str(SAMPLE_DIR / "attacks.log")))
    events.extend(parser.parse_file(str(SAMPLE_DIR / "login-logs.txt")))
    normalize_events(events)

    detector = RuleEngine(rule_repo.get_enabled_rules())
    sig_dets = detector.detect(events)

    correlator = CorrelationEngine()
    beh_dets = correlator.correlate(events, sig_dets)
    all_dets = sig_dets + beh_dets

    session_id = f"sess_full_{uuid.uuid4().hex[:6]}"
    now = datetime.now(timezone.utc)
    alerts = []
    for d in all_dets:
        d.severity = resolve_severity(d, beh_dets)
        alerts.append(
            Alert(
                alert_id=f"alt_{uuid.uuid4().hex[:8]}",
                detection=d,
                created_at=now,
                status=AlertStatus.NEW,
                notes=d.context_notes,
            )
        )

    sev_counts = dict(Counter(a.detection.severity.value for a in alerts))
    session = AnalysisSession(
        session_id=session_id,
        created_at=now,
        source_files=("attacks.log", "login-logs.txt"),
        total_events=len(events),
        total_detections=len(alerts),
        severity_counts=sev_counts,
    )

    session_repo.save_session(session)
    event_repo.save_events(session_id, events)
    alert_repo.save_alerts(alerts, session_id)

    print(
        f"Session created: {session_id} with {len(events)} events and {len(alerts)} alerts."
    )

    # Generate ReportLab PDF
    print("Generating ReportLab PDF report...")
    generator = SOCReportGenerator(PDF_OUT)
    alert_dicts = alert_repo.get_alerts(session_id=session_id)
    out_path = generator.generate(session, alert_dicts)

    assert Path(out_path).exists()
    size_kb = Path(out_path).stat().st_size / 1024
    print(f"PDF Successfully generated at: {out_path} ({size_kb:.2f} KB)")
    print("PDF verification passed!")


if __name__ == "__main__":
    main()
