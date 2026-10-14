"""Reports view for ThreatDesk.

Features:
- Select analysis session
- Executive preview of incident statistics
- One-click ReportLab PDF generation
- Automatically launch or reveal generated PDF
- Built with SectionHeader, Card(variant="inset"), TactileButton, and ToastHost
"""

from __future__ import annotations

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QVBoxLayout,
    QWidget,
)

from app.core.report_generator import SOCReportGenerator
from app.models.detection import AnalysisSession
from app.storage.repositories import AlertRepo, SessionRepo
from app.ui.theme import GUTTER, SPACE, TOKENS
from app.ui.widgets.animated_button import TactileButton
from app.ui.widgets.surfaces import Card, SectionHeader
from app.ui.widgets.toast_notification import ToastHost


class ReportsView(QWidget):
    def __init__(
        self,
        session_repo: SessionRepo,
        alert_repo: AlertRepo,
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        self.session_repo = session_repo
        self.alert_repo = alert_repo

        self.sessions: list[AnalysisSession] = []
        self.current_session: AnalysisSession | None = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(
            GUTTER["view"], GUTTER["view_top"], GUTTER["view"], GUTTER["view_bottom"]
        )
        layout.setSpacing(SPACE["md"])

        # 1. Header
        self.header = SectionHeader(
            title="Executive & Technical Incident Reports",
            caption="Export publication-ready PDF reports with incident summaries, attack breakdowns, and remediation steps",
        )
        layout.addWidget(self.header)

        # 2. Session Selector Card
        sel_card = Card(
            title="Target Analysis Session",
            subtitle="Choose an ingestion session to compile into an executive audit report",
            variant="inset",
            parent=self,
        )
        s_lay = QHBoxLayout()
        s_lay.setContentsMargins(0, 0, 0, 0)
        s_lay.setSpacing(SPACE["sm"])

        self.session_combo = QComboBox()
        self.session_combo.currentIndexChanged.connect(self._on_session_changed)
        s_lay.addWidget(self.session_combo, 1)

        self.btn_refresh = TactileButton("Refresh Sessions", appearance="default")
        self.btn_refresh.clicked.connect(self.refresh_sessions)
        s_lay.addWidget(self.btn_refresh)

        sel_card.body().addLayout(s_lay)
        layout.addWidget(sel_card)

        # 3. Report Preview Card
        self.preview_card = Card(
            title="Report Generation Preview",
            subtitle="Calculated metrics and telemetry summary to be compiled into the PDF document",
            variant="primary",
            parent=self,
        )

        self.lbl_meta = QLabel("No active session selected.")
        self.lbl_meta.setProperty("role", "body")
        self.lbl_meta.setStyleSheet(
            f"color: {TOKENS['text_primary']}; line-height: 1.5; padding: 6px 0;"
        )
        self.lbl_meta.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.preview_card.body().addWidget(self.lbl_meta)

        self.preview_card.body().addStretch(1)

        action_row = QHBoxLayout()
        action_row.setContentsMargins(0, 0, 0, 0)
        action_row.setSpacing(SPACE["sm"])

        self.btn_generate = TactileButton("Generate & Export PDF Report", appearance="primary")
        self.btn_generate.clicked.connect(self._generate_pdf)
        action_row.addWidget(self.btn_generate)
        action_row.addStretch(1)

        self.preview_card.body().addLayout(action_row)
        layout.addWidget(self.preview_card, 1)

        self.refresh_sessions()

    def refresh_sessions(self) -> None:
        self.sessions = self.session_repo.list_sessions()
        self.session_combo.clear()
        for s in self.sessions:
            self.session_combo.addItem(
                f"{s.session_id} — {s.created_at.strftime('%Y-%m-%d %H:%M')} ({s.total_events} events, {s.total_detections} threats)",
                s.session_id,
            )

    def _on_session_changed(self) -> None:
        idx = self.session_combo.currentIndex()
        if 0 <= idx < len(self.sessions):
            self.current_session = self.sessions[idx]
            s = self.current_session
            crit = s.severity_counts.get("critical", 0)
            high = s.severity_counts.get("high", 0)
            med = s.severity_counts.get("medium", 0)
            low_info = s.severity_counts.get("low", 0) + s.severity_counts.get("info", 0)
            sources_text = ", ".join(s.source_files) if s.source_files else "Direct Ingestion"

            self.lbl_meta.setText(
                f"<b>Session Identifier:</b> {s.session_id}<br>"
                f"<b>Creation Timestamp:</b> {s.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}<br>"
                f"<b>Ingested Sources:</b> {sources_text}<br>"
                f"<b>Total Evaluated Events:</b> {s.total_events:,}<br>"
                f"<b>Correlated Threats:</b> {s.total_detections:,}<br>"
                f"<b>Severity Distribution:</b> Critical: {crit} · High: {high} · Medium: {med} · Low/Info: {low_info}"
            )
        else:
            self.current_session = None
            self.lbl_meta.setText("No active session selected.")

    def _generate_pdf(self) -> None:
        if not self.current_session:
            ToastHost.instance().show_toast(
                "Please select or ingest an analysis session first.",
                title="Export Warning",
                severity="warning",
            )
            return

        default_filename = f"threatdesk_report_{self.current_session.session_id}.pdf"
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save SOC Incident PDF Report",
            default_filename,
            "PDF Documents (*.pdf)",
        )
        if not path:
            return

        alerts = self.alert_repo.get_alerts(session_id=self.current_session.session_id)
        generator = SOCReportGenerator(path)
        try:
            out_file = generator.generate(self.current_session, alerts)
            ToastHost.instance().show_toast(
                f"Report saved to: {out_file}",
                title="PDF Generated",
                severity="success",
            )
            res = QMessageBox.information(
                self,
                "Report Generated",
                f"Incident Report successfully generated!\nLocation: {out_file}\n\nWould you like to open it now?",
                QMessageBox.StandardButton.Open | QMessageBox.StandardButton.Ok,
            )
            if res == QMessageBox.StandardButton.Open:
                QDesktopServices.openUrl(QUrl.fromLocalFile(out_file))
        except Exception as exc:  # noqa: BLE001
            ToastHost.instance().show_toast(
                f"Failed to compile PDF: {exc}",
                title="PDF Error",
                severity="error",
            )

    def refresh_theme(self) -> None:
        """Update dynamic label stylesheet on theme change."""
        self.lbl_meta.setStyleSheet(
            f"color: {TOKENS['text_primary']}; line-height: 1.5; padding: 6px 0;"
        )
