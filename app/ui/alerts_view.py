"""Alerts view for ThreatDesk.

Security alert triage workstation:
- SectionHeader with session overview
- Control bar with search and filters (Severity, Method, Status)
- TableCard hosting AnalysisTable with SeverityBadge, MethodChip, mono_item, text_item
- Action footer with TactileButtons (Acknowledge, Resolve, Add to Watchlist, Inspect Details)
- Toast notifications for alert actions
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.models.detection import AlertStatus, BlocklistEntry
from app.storage.repositories import AlertRepo, BlocklistRepo, EventRepo
from app.ui.theme import GUTTER, SPACE, status_color
from app.ui.widgets.animated_button import TactileButton
from app.ui.widgets.event_inspector import EventInspectorDialog
from app.ui.widgets.interactive_table import (
    AnalysisTable,
    TableCard,
    mono_item,
    text_item,
)
from app.ui.widgets.severity_badge import MethodChip, SeverityBadge
from app.ui.widgets.surfaces import Card, SectionHeader
from app.ui.widgets.toast_notification import ToastHost


class AlertsView(QWidget):
    watchlist_updated = Signal()

    def __init__(
        self,
        alert_repo: AlertRepo,
        blocklist_repo: BlocklistRepo,
        event_repo: EventRepo | None = None,
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        self.alert_repo = alert_repo
        self.blocklist_repo = blocklist_repo
        self.event_repo = event_repo
        self.current_session_id: str | None = None
        self.current_alerts: list[dict[str, Any]] = []
        self._selected_alert_row = -1

        layout = QVBoxLayout(self)
        layout.setContentsMargins(
            GUTTER["view"], GUTTER["view_top"], GUTTER["view"], GUTTER["view_bottom"]
        )
        layout.setSpacing(SPACE["md"])

        # 1. Header
        self.header = SectionHeader(
            title="Security Alerts & Incident Triage",
            caption="Disposition detected threats, escalate malicious indicators, and review audit notes",
        )
        layout.addWidget(self.header)

        # 2. Filter Bar in an inset Card
        filter_card = Card(variant="inset", padding=SPACE["sm"])
        ctrl_bar = QHBoxLayout()
        ctrl_bar.setContentsMargins(0, 0, 0, 0)
        ctrl_bar.setSpacing(SPACE["sm"])

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search alerts, rule names, IPs, snippets...")
        self.search_input.textChanged.connect(self.refresh)
        ctrl_bar.addWidget(self.search_input, 2)

        self.sev_filter = QComboBox()
        self.sev_filter.addItems(["All Severities", "Critical", "High", "Medium", "Low", "Info"])
        self.sev_filter.currentTextChanged.connect(self.refresh)
        ctrl_bar.addWidget(self.sev_filter)

        self.method_filter = QComboBox()
        self.method_filter.addItems(["All Methods", "Signature", "Behavioral"])
        self.method_filter.currentTextChanged.connect(self.refresh)
        ctrl_bar.addWidget(self.method_filter)

        self.status_filter = QComboBox()
        self.status_filter.addItems(["All Statuses", "New", "Acknowledged", "Resolved"])
        self.status_filter.currentTextChanged.connect(self.refresh)
        ctrl_bar.addWidget(self.status_filter)

        filter_card.body().addLayout(ctrl_bar)
        layout.addWidget(filter_card)

        # 3. TableCard with AnalysisTable
        self.table_card = TableCard(
            title="Alerts Ledger",
            caption="Structured forensic triage log across all ingestion channels",
            parent=self,
        )

        self.table = AnalysisTable(
            0,
            7,
            parent=self.table_card,
            severity_column=0,
            stretch_column=5,
        )
        self.table.setHorizontalHeaderLabels(
            [
                "Severity",
                "Method",
                "Threat Rule",
                "Category",
                "Source IP",
                "Matched Trigger Snippet",
                "Status",
            ]
        )
        self.table.setColumnWidth(0, 110)
        self.table.setColumnWidth(1, 110)
        self.table.setColumnWidth(2, 230)
        self.table.setColumnWidth(3, 140)
        self.table.setColumnWidth(4, 140)
        self.table.horizontalHeader().setSectionResizeMode(
            5, QHeaderView.ResizeMode.Stretch
        )
        self.table.setColumnWidth(6, 120)
        self.table.itemDoubleClicked.connect(self._on_row_double_clicked)
        self.table.row_activated.connect(self._on_row_activated)
        self.table.cellClicked.connect(self._remember_selected_row)

        self.table_card.attach_table(self.table)
        self.table_card.set_empty_state(
            title="No Security Alerts Found",
            body="No events match current filter conditions, or no log ingestion session is active.",
        )
        layout.addWidget(self.table_card, 1)

        # 4. Action Buttons Footer
        footer = QHBoxLayout()
        footer.setContentsMargins(0, 0, 0, 0)
        footer.setSpacing(SPACE["sm"])

        self.btn_ack = TactileButton("Mark Acknowledged", appearance="default")
        self.btn_ack.clicked.connect(self._mark_acknowledged)
        footer.addWidget(self.btn_ack)

        self.btn_res = TactileButton("Mark Resolved", appearance="default")
        self.btn_res.clicked.connect(self._mark_resolved)
        footer.addWidget(self.btn_res)

        self.btn_block = TactileButton("Add IP to Watchlist", appearance="default")
        self.btn_block.clicked.connect(self._add_to_blocklist)
        footer.addWidget(self.btn_block)

        self.btn_inspect = TactileButton("Inspect Details", appearance="primary")
        self.btn_inspect.clicked.connect(self._inspect_selected)
        footer.addWidget(self.btn_inspect)

        footer.addStretch(1)

        self.count_label = QLabel("0 Alerts")
        self.count_label.setProperty("role", "secondary")
        self.count_label.setStyleSheet("font-weight: 600;")
        footer.addWidget(self.count_label)

        layout.addLayout(footer)

    def set_session(self, session_id: str | None) -> None:
        self.current_session_id = session_id
        if session_id:
            self.header.set_caption(f"Active Session: {session_id} · Forensic Triage Stream")
        else:
            self.header.set_caption("Review, triage, acknowledge, and resolve detected threat alerts")
        self.refresh()

    def refresh(self) -> None:
        sev = self.sev_filter.currentText().lower()
        sev_param = sev if sev != "all severities" else None

        meth = self.method_filter.currentText().lower()
        meth_param = meth if meth != "all methods" else None

        stat = self.status_filter.currentText().lower()
        stat_param = stat if stat != "all statuses" else None

        search = self.search_input.text().strip() or None

        self.current_alerts = self.alert_repo.get_alerts(
            session_id=self.current_session_id,
            severity=sev_param,
            status=stat_param,
            method=meth_param,
            search=search,
        )
        self._selected_alert_row = -1

        self.count_label.setText(f"{len(self.current_alerts)} Alerts")
        self.table.setRowCount(len(self.current_alerts))

        for row, a in enumerate(self.current_alerts):
            sev = a.get("severity", "info")
            meth = a.get("method", "signature")

            # Col 0: Badge
            badge = SeverityBadge(sev, meth)
            self.table.setCellWidget(row, 0, badge)

            # Col 1: MethodChip
            chip = MethodChip(meth)
            self.table.setCellWidget(row, 1, chip)

            # Col 2: Rule Name
            r_item = text_item(a.get("rule_name", ""), color_token="text_primary")
            self.table.setItem(row, 2, r_item)

            # Col 3: Category
            c_item = text_item(a.get("category", "-"), color_token="text_secondary")
            self.table.setItem(row, 3, c_item)

            # Col 4: Source IP
            ip_item = mono_item(a.get("source_ip") or "-", color_token="text_primary")
            self.table.setItem(row, 4, ip_item)

            # Col 5: Snippet
            s_item = mono_item(a.get("matched_snippet", "")[:140], color_token="text_muted")
            self.table.setItem(row, 5, s_item)

            # Col 6: Status
            stat_val = a.get("status", "new").upper()
            stat_color_val = status_color(stat_val)
            stat_item = text_item(stat_val)
            from PySide6.QtGui import QColor
            stat_item.setForeground(QColor(stat_color_val))
            stat_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(row, 6, stat_item)

        self.table_card.refresh_empty_state()

    def _get_selected_alert(self) -> dict[str, Any] | None:
        row = self.table.selected_row()
        if row < 0:
            row = self._selected_alert_row
        if 0 <= row < len(self.current_alerts):
            return self.current_alerts[row]
        return None

    def _remember_selected_row(self, row: int, _column: int) -> None:
        self._selected_alert_row = row

    def _mark_acknowledged(self) -> None:
        alert = self._get_selected_alert()
        if not alert:
            ToastHost.instance().show_toast(
                "Please select an alert row from the table first.",
                title="No Alert Selected",
                severity="warning",
            )
            return
        self.alert_repo.update_status(alert["alert_id"], AlertStatus.ACKNOWLEDGED)
        ToastHost.instance().show_toast(
            f"Alert {alert['rule_name']} acknowledged.",
            title="Alert Updated",
            severity="info",
        )
        self.refresh()

    def _mark_resolved(self) -> None:
        alert = self._get_selected_alert()
        if not alert:
            ToastHost.instance().show_toast(
                "Please select an alert row from the table first.",
                title="No Alert Selected",
                severity="warning",
            )
            return
        self.alert_repo.update_status(alert["alert_id"], AlertStatus.RESOLVED)
        ToastHost.instance().show_toast(
            f"Alert {alert['rule_name']} marked as resolved.",
            title="Alert Resolved",
            severity="success",
        )
        self.refresh()

    def _add_to_blocklist(self) -> None:
        alert = self._get_selected_alert()
        if not alert or not alert.get("source_ip") or alert.get("source_ip") == "-":
            ToastHost.instance().show_toast(
                "No valid source IP associated with this alert.",
                title="Watchlist",
                severity="warning",
            )
            return

        ip = alert["source_ip"]
        entry = BlocklistEntry(
            ip=ip,
            reason=f"Detected via {alert['rule_name']} ({alert['severity'].upper()})",
            confidence=alert["confidence"],
            added_at=datetime.now(timezone.utc),
            suggested_by_detection=alert["rule_id"],
        )
        self.blocklist_repo.add_entry(entry)
        self.watchlist_updated.emit()
        ToastHost.instance().show_toast(
            f"Host IP {ip} enrolled in threat watchlist.",
            title="Watchlist Enrolled",
            severity="success",
        )

    def _inspect_selected(self) -> None:
        alert = self._get_selected_alert()
        if not alert:
            ToastHost.instance().show_toast(
                "Please select an alert row from the table first.",
                title="No Alert Selected",
                severity="warning",
            )
            return
        ev = None
        if self.event_repo and alert.get("session_id") and alert.get("event_id"):
            ev = self.event_repo.get_event_by_line(
                alert["session_id"], alert["event_id"]
            )
        dlg = EventInspectorDialog(event=ev, alert=alert, parent=self)
        dlg.exec()

    def _on_row_double_clicked(self, item: QTableWidgetItem) -> None:
        self._selected_alert_row = item.row()
        self._inspect_selected()

    def _on_row_activated(self, row: int) -> None:
        self._selected_alert_row = row
        self._inspect_selected()

    def refresh_theme(self) -> None:
        """Re-render table rows and badges when theme changes."""
        self.table.refresh_theme()
        self.refresh()
