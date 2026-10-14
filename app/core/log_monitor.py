"""QThread-based non-blocking live log file monitor.

Monitors appended lines from a targeted log file, passing each new line
through parse -> normalize -> detect -> correlate -> alert without freezing the GUI.
Supports states: LIVE, PAUSED, STOPPED.
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from PySide6.QtCore import QObject, QThread, Signal

from app.core.correlator import CorrelationEngine
from app.core.detector import RuleEngine
from app.core.normalizer import normalize_events
from app.core.parser import ParserRegistry
from app.core.severity import resolve_severity
from app.models.detection import Alert, AlertStatus, DetectionResult
from app.models.event import LogEvent
from app.models.rule import DetectionRule


class FileTailWorker(QObject):
    event_parsed = Signal(LogEvent)
    detection_found = Signal(DetectionResult)
    alert_created = Signal(Alert)
    status_changed = Signal(str)

    def __init__(
        self, file_path: str, rules: list[DetectionRule], poll_interval_sec: float = 0.5
    ):
        super().__init__()
        self.file_path = file_path
        self.rules = rules
        self.poll_interval = poll_interval_sec

        self._running = False
        self._paused = False

        self.parser = ParserRegistry()
        self.detector = RuleEngine(rules)
        self.correlator = CorrelationEngine()

        self._session_events: list[LogEvent] = []
        self._session_detections: list[DetectionResult] = []

    def start_tail(self) -> None:
        self._running = True
        self._paused = False
        self.status_changed.emit("LIVE")

        p = Path(self.file_path)
        if not p.exists():
            # Touch or create empty
            p.touch()

        with open(p, "r", encoding="utf-8", errors="replace") as f:
            # Replay the existing file once, then continue watching appended lines.
            f.seek(0)
            line_no = 0

            while self._running:
                if self._paused:
                    time.sleep(self.poll_interval)
                    continue

                line = f.readline()
                if not line:
                    time.sleep(self.poll_interval)
                    continue

                line_no += 1
                clean_line = line.rstrip("\r\n")
                if not clean_line:
                    continue

                ev = self.parser.parse_line(clean_line, line_no, p.name)
                normalize_events([ev])
                self._session_events.append(ev)
                self.event_parsed.emit(ev)

                # Signature detection
                sig_dets = self.detector.detect_event(ev)
                for d in sig_dets:
                    self._session_detections.append(d)
                    self.detection_found.emit(d)

                    final_sev = resolve_severity(d)
                    d.severity = final_sev
                    alt = Alert(
                        alert_id=f"live_{uuid.uuid4().hex[:8]}",
                        detection=d,
                        created_at=datetime.now(timezone.utc),
                        status=AlertStatus.NEW,
                    )
                    self.alert_created.emit(alt)

                # Periodic behavioral correlation (check recent window)
                if len(self._session_events) % 5 == 0:
                    recent_evs = self._session_events[-50:]
                    recent_dets = self._session_detections[-100:]
                    beh_dets = self.correlator.correlate(recent_evs, recent_dets)
                    for bd in beh_dets:
                        # Avoid duplicates
                        if not any(
                            x.rule_id == bd.rule_id
                            and x.event.line_number == bd.event.line_number
                            for x in self._session_detections
                        ):
                            self._session_detections.append(bd)
                            self.detection_found.emit(bd)
                            alt = Alert(
                                alert_id=f"live_beh_{uuid.uuid4().hex[:8]}",
                                detection=bd,
                                created_at=datetime.now(timezone.utc),
                                status=AlertStatus.NEW,
                                notes=bd.context_notes,
                            )
                            self.alert_created.emit(alt)

        self.status_changed.emit("STOPPED")

    def pause_tail(self) -> None:
        self._paused = True
        self.status_changed.emit("PAUSED")

    def resume_tail(self) -> None:
        self._paused = False
        self.status_changed.emit("LIVE")

    def stop_tail(self) -> None:
        self._running = False
        self._paused = False


class LogMonitor(QObject):
    """Controller wrapping FileTailWorker inside a QThread."""

    event_parsed = Signal(LogEvent)
    alert_created = Signal(Alert)
    status_changed = Signal(str)

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        self.thread: QThread | None = None
        self.worker: FileTailWorker | None = None

    def start_monitoring(self, file_path: str, rules: list[DetectionRule]) -> None:
        self.stop_monitoring()

        self.thread = QThread()
        self.worker = FileTailWorker(file_path, rules)
        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.start_tail)
        self.worker.event_parsed.connect(self.event_parsed.emit)
        self.worker.alert_created.connect(self.alert_created.emit)
        self.worker.status_changed.connect(self.status_changed.emit)

        self.thread.start()

    def pause_monitoring(self) -> None:
        if self.worker:
            self.worker.pause_tail()

    def resume_monitoring(self) -> None:
        if self.worker:
            self.worker.resume_tail()

    def stop_monitoring(self) -> None:
        if self.worker:
            self.worker.stop_tail()
        if self.thread and self.thread.isRunning():
            self.thread.quit()
            self.thread.wait(1000)
        self.thread = None
        self.worker = None
        self.status_changed.emit("STOPPED")
