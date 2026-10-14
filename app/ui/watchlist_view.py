"""Analyst Watchlist / Blocklist view for ThreatDesk.

Features:
- Track suspicious and malicious source IPs
- Assign analyst confidence, reason, and source rule
- Remove or export blocklist
- Pure defensive air-gapped analyst tracking (never touches OS firewall)
- Built on TableCard, AnalysisTable, TactileButton, and AppDialog modal
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QVBoxLayout,
    QWidget,
)

from app.models.detection import BlocklistEntry
from app.storage.repositories import BlocklistRepo
from app.ui.theme import GUTTER, SPACE
from app.ui.widgets.animated_button import TactileButton
from app.ui.widgets.app_dialog import AppDialog, Section
from app.ui.widgets.interactive_table import (
    AnalysisTable,
    TableCard,
    mono_item,
    text_item,
)
from app.ui.widgets.surfaces import SectionHeader
from app.ui.widgets.toast_notification import ToastHost


class AddIPDialog(AppDialog):
    """Refined modal for enrolling a malicious or suspicious host IP."""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(
            title="Enroll Hostile IP",
            eyebrow="ANALYST DEFENSE WATCHLIST",
            meta="Track suspicious host in local database for automatic alert escalation",
            severity="high",
            width=520,
            height=380,
            parent=parent,
        )
        self.entry: BlocklistEntry | None = None

        body = self.body_layout()

        sec = Section(
            title="Host Details",
            caption="Provide IPv4/IPv6 host address and rationale for tracking",
            tone="danger",
        )

        sec.add(QLabel("Target IP Address:"))
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("e.g. 203.0.113.45")
        sec.add(self.ip_input)

        sec.add(QLabel("Forensic Reason / Incident Context:"))
        self.reason_input = QLineEdit()
        self.reason_input.setPlaceholderText("e.g. Repeated SQL injection attempts against /api/v1/auth")
        sec.add(self.reason_input)

        body.addWidget(sec)

        # Footer
        self.btn_cancel = TactileButton("Cancel", appearance="default")
        self.btn_cancel.clicked.connect(self.reject)

        self.btn_add = TactileButton("Add to Watchlist", appearance="primary")
        self.btn_add.clicked.connect(self._save)

        self.add_footer_action(self.btn_cancel)
        self.add_footer_action(self.btn_add)

    def _save(self) -> None:
        ip_val = self.ip_input.text().strip()
        if not ip_val:
            ToastHost.instance().show_toast(
                "IP Address cannot be empty.",
                title="Validation Error",
                severity="warning",
            )
            return

        self.entry = BlocklistEntry(
            ip=ip_val,
            reason=self.reason_input.text().strip() or "Manual Analyst Addition",
            confidence=90,
            added_at=datetime.now(timezone.utc),
            suggested_by_detection=False,
        )
        self.accept()


class WatchlistView(QWidget):
    def __init__(self, blocklist_repo: BlocklistRepo, parent: QWidget | None = None):
        super().__init__(parent)
        self.blocklist_repo = blocklist_repo
        self.entries: list[BlocklistEntry] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(
            GUTTER["view"], GUTTER["view_top"], GUTTER["view"], GUTTER["view_bottom"]
        )
        layout.setSpacing(SPACE["md"])

        # 1. Header with action buttons
        self.header = SectionHeader(
            title="Hostile IP Watchlist & Defended Blocklist",
            caption="Locally tracked malicious IPs with confidence ratings and forensic reasoning",
        )

        self.btn_export = TactileButton("Export Watchlist", appearance="default")
        self.btn_export.clicked.connect(self._export_blocklist)

        self.btn_add = TactileButton("+ Add Hostile IP", appearance="primary")
        self.btn_add.clicked.connect(self._add_ip_dialog)

        self.header.layout().addWidget(self.btn_export)
        self.header.layout().addWidget(self.btn_add)
        layout.addWidget(self.header)

        # 2. TableCard with AnalysisTable
        self.table_card = TableCard(
            title="Enrolled Host Registry",
            caption="Air-gapped defensive watchlist evaluated during threat log correlation",
            parent=self,
        )

        self.table = AnalysisTable(
            0,
            4,
            parent=self.table_card,
            severity_column=None,
            stretch_column=3,
        )
        self.table.setHorizontalHeaderLabels(
            [
                "Target IP Address",
                "Confidence",
                "Enrolled Timestamp",
                "Detection Reason / Forensic Context",
            ]
        )
        self.table.setColumnWidth(0, 200)
        self.table.setColumnWidth(1, 120)
        self.table.setColumnWidth(2, 200)
        self.table.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.ResizeMode.Stretch
        )

        self.table_card.attach_table(self.table)
        self.table_card.set_empty_state(
            title="No Hostile IPs Enrolled",
            body="Watchlist is empty. Click '+ Add Hostile IP' above or escalate suspicious hosts from the Security Alerts ledger.",
        )
        layout.addWidget(self.table_card, 1)

        # 3. Action Buttons Footer
        footer = QHBoxLayout()
        footer.setContentsMargins(0, 0, 0, 0)
        footer.setSpacing(SPACE["sm"])

        self.btn_remove = TactileButton("Remove from Watchlist", appearance="danger")
        self.btn_remove.clicked.connect(self._remove_selected)
        footer.addWidget(self.btn_remove)

        footer.addStretch(1)

        self.count_label = QLabel("0 Tracked IPs")
        self.count_label.setProperty("role", "secondary")
        self.count_label.setStyleSheet("font-weight: 600;")
        footer.addWidget(self.count_label)

        layout.addLayout(footer)
        self.refresh()

    def refresh(self) -> None:
        self.entries = self.blocklist_repo.list_entries()
        self.count_label.setText(f"{len(self.entries)} Tracked IPs")
        self.table.setRowCount(len(self.entries))

        for row, entry in enumerate(self.entries):
            # Col 0: IP
            ip_item = mono_item(entry.ip, color_token="severity_critical")
            self.table.setItem(row, 0, ip_item)

            # Col 1: Confidence
            c_item = mono_item(f"{entry.confidence}%", color_token="accent")
            self.table.setItem(row, 1, c_item)

            # Col 2: Date
            t_item = mono_item(entry.added_at.strftime("%Y-%m-%d %H:%M:%S"), color_token="text_muted")
            self.table.setItem(row, 2, t_item)

            # Col 3: Reason
            r_item = text_item(entry.reason, color_token="text_primary")
            self.table.setItem(row, 3, r_item)

        self.table_card.refresh_empty_state()

    def _add_ip_dialog(self) -> None:
        dlg = AddIPDialog(parent=self)
        if dlg.exec() and dlg.entry:
            self.blocklist_repo.add_entry(dlg.entry)
            ToastHost.instance().show_toast(
                f"Host IP {dlg.entry.ip} enrolled in watchlist.",
                title="Watchlist Updated",
                severity="success",
            )
            self.refresh()

    def _remove_selected(self) -> None:
        row = self.table.selected_row()
        if not (0 <= row < len(self.entries)):
            ToastHost.instance().show_toast(
                "Please select a host IP from the watchlist first.",
                title="No IP Selected",
                severity="warning",
            )
            return
        ent = self.entries[row]
        if (
            QMessageBox.question(
                self, "Remove IP", f"Remove host '{ent.ip}' from the active watchlist?"
            )
            == QMessageBox.StandardButton.Yes
        ):
            self.blocklist_repo.remove_entry(ent.ip)
            ToastHost.instance().show_toast(
                f"Host IP {ent.ip} removed from watchlist.",
                title="Watchlist Updated",
                severity="info",
            )
            self.refresh()

    def _export_blocklist(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Blocklist", "threatdesk_blocklist.json", "JSON Files (*.json)"
        )
        if not path:
            return
        data = [
            {
                "ip": e.ip,
                "reason": e.reason,
                "confidence": e.confidence,
                "added_at": e.added_at.isoformat(),
            }
            for e in self.entries
        ]
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        ToastHost.instance().show_toast(
            f"Exported {len(data)} blocked IPs to JSON.",
            title="Watchlist Exported",
            severity="success",
        )

    def refresh_theme(self) -> None:
        """Re-render table rows and badges when theme changes."""
        self.table.refresh_theme()
        self.refresh()
