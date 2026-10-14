"""Live log file monitoring view for ThreatDesk.

Features:
- Select a file to tail live in the background
- Non-blocking QThread tailing with zero GUI lag
- Live streaming log events table and live alert counter
- Monitoring controls: Start, Pause, Resume, Stop
- PulseIndicator breathing status dot + styled badge pill
- MetricRow with MetricCards for Streamed Events, Active Threats, Critical Threats
- TableCard hosting AnalysisTable with SeverityBadge, MethodChip, and inspector integration
"""

from __future__ import annotations

import time

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.core.log_monitor import LogMonitor
from app.models.detection import Alert
from app.models.event import LogEvent
from app.storage.repositories import RuleRepo
from app.ui.animations import PulseIndicator
from app.ui.theme import GUTTER, SPACE
from app.ui.widgets.animated_button import TactileButton
from app.ui.widgets.event_inspector import EventInspectorDialog
from app.ui.widgets.interactive_table import (
    AnalysisTable,
    TableCard,
    mono_item,
    text_item,
)
from app.ui.widgets.metric_card import MetricCard, MetricRow
from app.ui.widgets.severity_badge import MethodChip, SeverityBadge
from app.ui.widgets.surfaces import Card, SectionHeader
from app.ui.widgets.toast_notification import ToastHost


class LiveMonitorView(QWidget):
    def __init__(self, rule_repo: RuleRepo, parent: QWidget | None = None):
        super().__init__(parent)
        self.rule_repo = rule_repo
        self.monitor = LogMonitor(self)

        self.live_events: list[LogEvent] = []
        self.live_alerts: list[Alert] = []
        self.streamed_count = 0
        self.alert_count = 0
        self.critical_count = 0
        self._last_live_toast = 0.0

        layout = QVBoxLayout(self)
        layout.setContentsMargins(
            GUTTER["view"], GUTTER["view_top"], GUTTER["view"], GUTTER["view_bottom"]
        )
        layout.setSpacing(SPACE["md"])

        # 1. Header with live pulsing status indicator
        status_box = QWidget()
        status_box.setProperty("card", "plain")
        s_row = QHBoxLayout(status_box)
        s_row.setContentsMargins(0, 0, 0, 0)
        s_row.setSpacing(SPACE["xs"])

        self.pulse = PulseIndicator(parent=status_box, tone="text_muted", diameter=8)
        s_row.addWidget(self.pulse, 0, Qt.AlignmentFlag.AlignVCenter)

        self.status_pill = QLabel("STOPPED", status_box)
        self.status_pill.setProperty("role", "label")
        self.status_pill.setStyleSheet("font-weight: 700; letter-spacing: 0.08px;")
        s_row.addWidget(self.status_pill, 0, Qt.AlignmentFlag.AlignVCenter)

        self.header = SectionHeader(
            title="Real-Time File Tail & Threat Stream",
            caption="Continuously monitors appended log records via dedicated background worker threads",
            trailing=status_box,
        )
        layout.addWidget(self.header)

        # 2. Controls Row inside Inset Card
        ctrl_card = Card(variant="inset", padding=SPACE["sm"])
        c_lay = QHBoxLayout()
        c_lay.setContentsMargins(0, 0, 0, 0)
        c_lay.setSpacing(SPACE["sm"])

        self.file_input = QLineEdit()
        self.file_input.setPlaceholderText("Target log file path to monitor...")
        c_lay.addWidget(self.file_input, 1)

        self.btn_browse = TactileButton("Browse...", appearance="default")
        self.btn_browse.clicked.connect(self._browse_file)
        c_lay.addWidget(self.btn_browse)

        self.btn_start = TactileButton("Start Live Tail", appearance="primary")
        self.btn_start.clicked.connect(self._start_monitoring)
        c_lay.addWidget(self.btn_start)

        self.btn_pause = TactileButton("Pause", appearance="default")
        self.btn_pause.setEnabled(False)
        self.btn_pause.clicked.connect(self._toggle_pause)
        c_lay.addWidget(self.btn_pause)

        self.btn_stop = TactileButton("Stop", appearance="danger")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self._stop_monitoring)
        c_lay.addWidget(self.btn_stop)

        ctrl_card.body().addLayout(c_lay)
        layout.addWidget(ctrl_card)

        # 3. Metric KPI Row
        self.kpi_streamed = MetricCard(
            title="Streamed Events",
            initial_value=0,
            subtitle="Real-time ingested lines",
            accent_token="accent",
        )
        self.kpi_threats = MetricCard(
            title="Active Threats",
            initial_value=0,
            subtitle="Fired real-time rules",
            accent_token="severity_high",
        )
        self.kpi_critical = MetricCard(
            title="Critical Threats",
            initial_value=0,
            subtitle="Immediate triage alerts",
            accent_token="severity_critical",
        )

        self.metrics_row = MetricRow(
            [self.kpi_streamed, self.kpi_threats, self.kpi_critical],
            parent=self,
            spacing=SPACE["md"],
        )
        layout.addWidget(self.metrics_row)

        # 4. Real-time Threat Stream TableCard & AnalysisTable
        self.table_card = TableCard(
            title="Live Alert Feed",
            caption="Live detection stream updated synchronously as log entries arrive",
            parent=self,
        )

        self.table = AnalysisTable(
            0,
            6,
            parent=self.table_card,
            severity_column=0,
            stretch_column=4,
        )
        self.table.setHorizontalHeaderLabels(
            [
                "Severity",
                "Method",
                "Threat Rule",
                "Source IP",
                "Payload Preview",
                "Timestamp",
            ]
        )
        self.table.setColumnWidth(0, 110)
        self.table.setColumnWidth(1, 110)
        self.table.setColumnWidth(2, 240)
        self.table.setColumnWidth(3, 140)
        self.table.horizontalHeader().setSectionResizeMode(
            4, QHeaderView.ResizeMode.Stretch
        )
        self.table.setColumnWidth(5, 110)
        self.table.itemDoubleClicked.connect(self._inspect_alert)
        self.table.row_activated.connect(self._on_row_activated)

        self.table_card.attach_table(self.table)
        self.table_card.set_empty_state(
            title="Real-Time Detection Feed Inactive",
            body="Select a target log file and click 'Start Live Tail' to monitor appended records in real time.",
        )
        layout.addWidget(self.table_card, 1)

        # Connect log monitor signals
        self.monitor.event_parsed.connect(self._on_event_parsed)
        self.monitor.alert_created.connect(self._on_alert_created)
        self.monitor.status_changed.connect(self._on_status_changed)

    def _browse_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Log File to Tail",
            "",
            "Log Files (*.log *.txt);;All Files (*)",
        )
        if path:
            self.file_input.setText(path)

    def _start_monitoring(self) -> None:
        path = self.file_input.text().strip()
        if not path:
            ToastHost.instance().show_toast(
                "Please select a target log file to tail.",
                title="File Required",
                severity="warning",
            )
            return
        rules = self.rule_repo.get_enabled_rules()
        self.monitor.start_monitoring(path, rules)
        self.btn_start.setEnabled(False)
        self.btn_pause.setEnabled(True)
        self.btn_stop.setEnabled(True)
        ToastHost.instance().show_toast(
            f"Tailing file: {path}",
            title="Monitoring Active",
            severity="success",
        )

    def _toggle_pause(self) -> None:
        if self.btn_pause.text() == "Pause":
            self.monitor.pause_monitoring()
            self.btn_pause.setText("Resume")
        else:
            self.monitor.resume_monitoring()
            self.btn_pause.setText("Pause")

    def _stop_monitoring(self) -> None:
        self.monitor.stop_monitoring()
        self.btn_start.setEnabled(True)
        self.btn_pause.setEnabled(False)
        self.btn_stop.setEnabled(False)
        self.btn_pause.setText("Pause")
        ToastHost.instance().show_toast(
            "Live monitoring stopped.",
            title="Monitor Stopped",
            severity="info",
        )

    def _on_status_changed(self, status: str) -> None:
        if status == "LIVE":
            self.status_pill.setText("LIVE STREAMING")
            self.status_pill.setStyleSheet("color: var(--success); font-weight: 700;")
            self.pulse.set_tone("success")
            self.pulse.start()
        elif status == "PAUSED":
            self.status_pill.setText("PAUSED")
            self.status_pill.setStyleSheet("color: var(--warning); font-weight: 700;")
            self.pulse.set_tone("warning")
            self.pulse.stop()
        else:
            self.status_pill.setText("STOPPED")
            self.status_pill.setStyleSheet("color: var(--text-muted); font-weight: 700;")
            self.pulse.set_tone("text_muted")
            self.pulse.stop()

    def _on_event_parsed(self, ev: LogEvent) -> None:
        self.streamed_count += 1
        self.live_events.append(ev)
        if len(self.live_events) > 5000:
            self.live_events.pop(0)
        self.kpi_streamed.set_value(self.streamed_count, animate=False)

    def _on_alert_created(self, alt: Alert) -> None:
        self.alert_count += 1
        if alt.detection.severity.value == "critical":
            self.critical_count += 1
        self.live_alerts.insert(0, alt)
        if len(self.live_alerts) > 5000:
            self.live_alerts.pop()
        self.kpi_threats.set_value(self.alert_count, animate=False)
        self.kpi_critical.set_value(self.critical_count, animate=False)

        # Dispatch toast for high or critical detection
        now = time.monotonic()
        if (
            alt.detection.severity.value in ("critical", "high")
            and now - self._last_live_toast >= 1.0
        ):
            self._last_live_toast = now
            snippet_str = alt.detection.matched_snippet[:60]
            ToastHost.instance().show_toast(
                f"{alt.detection.rule_name} triggered by {alt.detection.event.source_ip}: {snippet_str}",
                title=f"LIVE ALERT: {alt.detection.severity.value.upper()}",
                severity=alt.detection.severity.value,
            )

        # Insert row at top of table
        self.table.insertRow(0)

        # Col 0: Badge
        badge = SeverityBadge(alt.detection.severity, alt.detection.method)
        self.table.setCellWidget(0, 0, badge)

        # Col 1: Method
        chip = MethodChip(alt.detection.method)
        self.table.setCellWidget(0, 1, chip)

        # Col 2: Rule Name
        r_item = text_item(alt.detection.rule_name, color_token="text_primary")
        self.table.setItem(0, 2, r_item)

        # Col 3: Source IP
        ip_item = mono_item(alt.detection.event.source_ip or "-", color_token="text_primary")
        self.table.setItem(0, 3, ip_item)

        # Col 4: Snippet
        p_item = mono_item(alt.detection.matched_snippet[:120], color_token="text_muted")
        self.table.setItem(0, 4, p_item)

        # Col 5: Time
        t_item = mono_item(alt.created_at.strftime("%H:%M:%S"), color_token="text_secondary")
        self.table.setItem(0, 5, t_item)

        # Limit to 200 items for memory stability
        if self.table.rowCount() > 200:
            self.table.removeRow(200)

        self.table_card.refresh_empty_state()

    def _inspect_alert(self, item: QTableWidgetItem) -> None:
        self._inspect_row(item.row())

    def _on_row_activated(self, row: int) -> None:
        self._inspect_row(row)

    def _inspect_row(self, row: int) -> None:
        if 0 <= row < len(self.live_alerts):
            alt = self.live_alerts[row]
            dlg = EventInspectorDialog(
                event=alt.detection.event, alert=alt, parent=self
            )
            dlg.exec()

    def refresh_theme(self) -> None:
        """Update KPI cards, table styling, and status indicators when theme changes."""
        self.kpi_streamed.refresh_theme()
        self.kpi_threats.refresh_theme()
        self.kpi_critical.refresh_theme()
        self.table.refresh_theme()
