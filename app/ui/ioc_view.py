"""Threat Intelligence & IOC Manager View.

Features:
- Local IOC database (IPs, Domains, URLs, Hashes, User-Agents)
- AppDialog-backed IOCEditorDialog with structured Section and FieldRow inputs
- TableCard hosting AnalysisTable with SeverityBadge, mono_item, and text_item
- Search and type filtering
- Import/Export (CSV/JSON)
- TactileButtons and ToastHost feedback
"""

from __future__ import annotations

import csv
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QVBoxLayout,
    QWidget,
)

from app.models.detection import IOC, IOCType
from app.models.rule import Severity
from app.storage.repositories import IOCRepo
from app.ui.theme import GUTTER, SPACE
from app.ui.widgets.animated_button import TactileButton
from app.ui.widgets.app_dialog import AppDialog, Section
from app.ui.widgets.interactive_table import (
    AnalysisTable,
    TableCard,
    mono_item,
    text_item,
)
from app.ui.widgets.severity_badge import SeverityBadge
from app.ui.widgets.surfaces import Card, SectionHeader
from app.ui.widgets.toast_notification import ToastHost


class IOCEditorDialog(AppDialog):
    """Refined indicator editor built on AppDialog."""

    def __init__(self, ioc: IOC | None = None, parent: QWidget | None = None):
        super().__init__(
            title="Edit Indicator" if ioc else "Add Threat Indicator",
            eyebrow="THREAT INTELLIGENCE STORE",
            meta="Define an indicator of compromise for live event correlation",
            severity=ioc.severity.value if ioc else "high",
            width=580,
            height=480,
            parent=parent,
        )
        self.ioc = ioc

        body = self.body_layout()

        sec = Section(
            title="Indicator Definition",
            caption="Specify target indicator value, pattern type, and assigned threat severity",
            tone="accent",
        )

        sec.add(QLabel("Indicator Value (IP, Domain, URL, SHA256 Hash, User-Agent):"))
        self.ind_input = QLineEdit()
        self.ind_input.setPlaceholderText("e.g. 198.51.100.23 or evil-c2.internal")
        self.ind_input.setText(ioc.indicator if ioc else "")
        sec.add(self.ind_input)

        row_props = QHBoxLayout()
        row_props.setSpacing(SPACE["md"])

        col_type = QVBoxLayout()
        col_type.addWidget(QLabel("Indicator Type:"))
        self.type_combo = QComboBox()
        for t in IOCType:
            self.type_combo.addItem(t.value.upper(), t.value)
        if ioc:
            self.type_combo.setCurrentText(ioc.ioc_type.value.upper())
        col_type.addWidget(self.type_combo)
        row_props.addLayout(col_type, 1)

        col_sev = QVBoxLayout()
        col_sev.addWidget(QLabel("Severity:"))
        self.sev_combo = QComboBox()
        for s in Severity:
            self.sev_combo.addItem(s.value.upper())
        if ioc:
            self.sev_combo.setCurrentText(ioc.severity.value.upper())
        col_sev.addWidget(self.sev_combo)
        row_props.addLayout(col_sev, 1)

        sec.body().addLayout(row_props)

        sec.add(QLabel("Threat Intel Source:"))
        self.source_input = QLineEdit()
        self.source_input.setPlaceholderText("e.g. AlienVault, CISA Alert, Internal Triage")
        self.source_input.setText(ioc.source if ioc else "Internal SOC")
        sec.add(self.source_input)

        sec.add(QLabel("Analyst Notes / Forensic Context:"))
        self.notes_input = QLineEdit()
        self.notes_input.setPlaceholderText("Observed campaign, malware family, or ticket reference")
        self.notes_input.setText(ioc.notes if ioc else "")
        sec.add(self.notes_input)

        body.addWidget(sec)

        # Footer actions
        self.btn_cancel = TactileButton("Cancel", appearance="default")
        self.btn_cancel.clicked.connect(self.reject)

        self.btn_save = TactileButton("Save Indicator", appearance="primary")
        self.btn_save.clicked.connect(self._save)

        self.add_footer_action(self.btn_cancel)
        self.add_footer_action(self.btn_save)

    def _save(self) -> None:
        ind = self.ind_input.text().strip()
        if not ind:
            ToastHost.instance().show_toast(
                "Indicator value cannot be empty.",
                title="Validation Error",
                severity="warning",
            )
            return

        now = datetime.now(timezone.utc)
        self.ioc = IOC(
            ioc_id=self.ioc.ioc_id if self.ioc else f"ioc_{uuid.uuid4().hex[:8]}",
            indicator=ind,
            ioc_type=IOCType(self.type_combo.currentData()),
            severity=Severity(self.sev_combo.currentText().lower()),
            confidence=85,
            source=self.source_input.text().strip() or "Internal SOC",
            first_seen=self.ioc.first_seen if self.ioc else now,
            last_seen=now,
            notes=self.notes_input.text().strip(),
            tags=("intel",),
        )
        self.accept()


class IOCView(QWidget):
    def __init__(self, ioc_repo: IOCRepo, parent: QWidget | None = None):
        super().__init__(parent)
        self.ioc_repo = ioc_repo
        self.iocs: list[IOC] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(
            GUTTER["view"], GUTTER["view_top"], GUTTER["view"], GUTTER["view_bottom"]
        )
        layout.setSpacing(SPACE["md"])

        # 1. Header with action buttons
        self.header = SectionHeader(
            title="Threat Intelligence & Local IOC Store",
            caption="Manage indicators of compromise (IOCs) correlated live against incoming traffic",
        )

        self.btn_import = TactileButton("Import (CSV/JSON)", appearance="default")
        self.btn_import.clicked.connect(self._import_iocs)

        self.btn_export = TactileButton("Export", appearance="default")
        self.btn_export.clicked.connect(self._export_iocs)

        self.btn_add = TactileButton("+ Add Indicator", appearance="primary")
        self.btn_add.clicked.connect(self._add_ioc)

        self.header.layout().addWidget(self.btn_import)
        self.header.layout().addWidget(self.btn_export)
        self.header.layout().addWidget(self.btn_add)
        layout.addWidget(self.header)

        # 2. Controls / Filter Bar
        ctrl_card = Card(variant="inset", padding=SPACE["sm"])
        ctrl_bar = QHBoxLayout()
        ctrl_bar.setContentsMargins(0, 0, 0, 0)
        ctrl_bar.setSpacing(SPACE["sm"])

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search indicators, sources, notes...")
        self.search_input.textChanged.connect(self.refresh)
        ctrl_bar.addWidget(self.search_input, 2)

        self.type_filter = QComboBox()
        self.type_filter.addItem("All Indicator Types")
        for t in IOCType:
            self.type_filter.addItem(t.value.upper(), t.value)
        self.type_filter.currentTextChanged.connect(self.refresh)
        ctrl_bar.addWidget(self.type_filter)

        ctrl_card.body().addLayout(ctrl_bar)
        layout.addWidget(ctrl_card)

        # 3. TableCard & AnalysisTable
        self.table_card = TableCard(
            title="Active Intelligence Registry",
            caption="Locally stored indicators of compromise used for real-time correlation",
            parent=self,
        )

        self.table = AnalysisTable(
            0,
            6,
            parent=self.table_card,
            severity_column=0,
            stretch_column=5,
        )
        self.table.setHorizontalHeaderLabels(
            [
                "Severity",
                "Type",
                "Indicator Value",
                "Intel Source",
                "First Seen",
                "Forensic Notes",
            ]
        )
        self.table.setColumnWidth(0, 110)
        self.table.setColumnWidth(1, 100)
        self.table.setColumnWidth(2, 240)
        self.table.setColumnWidth(3, 150)
        self.table.setColumnWidth(4, 180)
        self.table.horizontalHeader().setSectionResizeMode(
            5, QHeaderView.ResizeMode.Stretch
        )
        self.table.itemDoubleClicked.connect(self._edit_ioc)
        self.table.row_activated.connect(self._edit_ioc)

        self.table_card.attach_table(self.table)
        self.table_card.set_empty_state(
            title="No Threat Indicators Found",
            body="No indicators of compromise enrolled. Click '+ Add Indicator' or 'Import (CSV/JSON)' to populate.",
        )
        layout.addWidget(self.table_card, 1)

        # 4. Action Buttons Footer
        footer = QHBoxLayout()
        footer.setContentsMargins(0, 0, 0, 0)
        footer.setSpacing(SPACE["sm"])

        self.btn_edit = TactileButton("Edit Indicator", appearance="default")
        self.btn_edit.clicked.connect(self._edit_ioc)
        footer.addWidget(self.btn_edit)

        self.btn_del = TactileButton("Delete Indicator", appearance="danger")
        self.btn_del.clicked.connect(self._delete_ioc)
        footer.addWidget(self.btn_del)

        footer.addStretch(1)

        self.count_label = QLabel("0 Indicators")
        self.count_label.setProperty("role", "secondary")
        self.count_label.setStyleSheet("font-weight: 600;")
        footer.addWidget(self.count_label)

        layout.addLayout(footer)
        self.refresh()

    def refresh(self) -> None:
        t_filter = self.type_filter.currentData()
        ioc_type = IOCType(t_filter) if t_filter else None
        all_iocs = self.ioc_repo.list_iocs(ioc_type)

        search = self.search_input.text().strip().lower()
        if search:
            self.iocs = [
                i
                for i in all_iocs
                if search in i.indicator.lower()
                or search in i.source.lower()
                or search in i.notes.lower()
            ]
        else:
            self.iocs = all_iocs

        self.count_label.setText(f"{len(self.iocs)} Indicators")
        self.table.setRowCount(len(self.iocs))

        for row, ioc in enumerate(self.iocs):
            # Col 0: Badge
            badge = SeverityBadge(ioc.severity)
            self.table.setCellWidget(row, 0, badge)

            # Col 1: Type
            t_item = text_item(ioc.ioc_type.value.upper(), color_token="accent")
            self.table.setItem(row, 1, t_item)

            # Col 2: Value
            ind_item = mono_item(ioc.indicator, color_token="text_primary")
            self.table.setItem(row, 2, ind_item)

            # Col 3: Source
            s_item = text_item(ioc.source, color_token="text_secondary")
            self.table.setItem(row, 3, s_item)

            # Col 4: Date
            d_item = mono_item(ioc.first_seen.strftime("%Y-%m-%d %H:%M"), color_token="text_muted")
            self.table.setItem(row, 4, d_item)

            # Col 5: Notes
            n_item = text_item(ioc.notes, color_token="text_secondary")
            self.table.setItem(row, 5, n_item)

        self.table_card.refresh_empty_state()

    def _add_ioc(self) -> None:
        dlg = IOCEditorDialog(parent=self)
        if dlg.exec() and dlg.ioc:
            self.ioc_repo.save_ioc(dlg.ioc)
            ToastHost.instance().show_toast(
                f"Indicator {dlg.ioc.indicator} saved.",
                title="IOC Added",
                severity="success",
            )
            self.refresh()

    def _edit_ioc(self) -> None:
        row = self.table.selected_row()
        if not (0 <= row < len(self.iocs)):
            ToastHost.instance().show_toast(
                "Please select an indicator from the table first.",
                title="No Indicator Selected",
                severity="warning",
            )
            return
        ioc = self.iocs[row]
        dlg = IOCEditorDialog(ioc=ioc, parent=self)
        if dlg.exec() and dlg.ioc:
            self.ioc_repo.save_ioc(dlg.ioc)
            ToastHost.instance().show_toast(
                f"Updated indicator {dlg.ioc.indicator}.",
                title="IOC Updated",
                severity="success",
            )
            self.refresh()

    def _delete_ioc(self) -> None:
        row = self.table.selected_row()
        if not (0 <= row < len(self.iocs)):
            ToastHost.instance().show_toast(
                "Please select an indicator from the table first.",
                title="No Indicator Selected",
                severity="warning",
            )
            return
        ioc = self.iocs[row]
        if (
            QMessageBox.question(
                self, "Delete IOC", f"Remove indicator '{ioc.indicator}' from the database?"
            )
            == QMessageBox.StandardButton.Yes
        ):
            self.ioc_repo.delete_ioc(ioc.ioc_id)
            ToastHost.instance().show_toast(
                f"Indicator {ioc.indicator} removed.",
                title="IOC Deleted",
                severity="info",
            )
            self.refresh()

    def _export_iocs(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Export IOCs", "threatdesk_iocs.json", "JSON Files (*.json)"
        )
        if not path:
            return
        data = [
            {
                "ioc_id": i.ioc_id,
                "indicator": i.indicator,
                "ioc_type": i.ioc_type.value,
                "severity": i.severity.value,
                "confidence": i.confidence,
                "source": i.source,
                "first_seen": i.first_seen.isoformat(),
                "last_seen": i.last_seen.isoformat(),
                "notes": i.notes,
            }
            for i in self.iocs
        ]
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        ToastHost.instance().show_toast(
            f"Exported {len(data)} IOC indicators to JSON.",
            title="IOC Export",
            severity="success",
        )

    def _import_iocs(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Import IOCs", "", "Data Files (*.json *.csv)"
        )
        if not path:
            return
        count = 0
        p = Path(path)
        now = datetime.now(timezone.utc)
        if p.suffix.lower() == ".json":
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for item in data:
                ioc = IOC(
                    ioc_id=item.get("ioc_id", f"ioc_{uuid.uuid4().hex[:8]}"),
                    indicator=item["indicator"],
                    ioc_type=IOCType(item.get("ioc_type", "ip")),
                    severity=Severity(item.get("severity", "high")),
                    confidence=item.get("confidence", 85),
                    source=item.get("source", "Imported Feed"),
                    first_seen=now,
                    last_seen=now,
                    notes=item.get("notes", ""),
                )
                self.ioc_repo.save_ioc(ioc)
                count += 1
        elif p.suffix.lower() == ".csv":
            with open(path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    ind = row.get("indicator") or row.get("ip") or row.get("value")
                    if ind:
                        ioc = IOC(
                            ioc_id=f"ioc_{uuid.uuid4().hex[:8]}",
                            indicator=ind.strip(),
                            ioc_type=IOCType(row.get("type", "ip").lower()),
                            severity=Severity(row.get("severity", "high").lower()),
                            confidence=85,
                            source=row.get("source", "CSV Import"),
                            first_seen=now,
                            last_seen=now,
                            notes=row.get("notes", ""),
                        )
                        self.ioc_repo.save_ioc(ioc)
                        count += 1

        self.refresh()
        ToastHost.instance().show_toast(
            f"Successfully imported {count} IOC indicators.",
            title="IOC Import",
            severity="success",
        )

    def refresh_theme(self) -> None:
        """Re-render table rows and badges when theme changes."""
        self.table.refresh_theme()
        self.refresh()
