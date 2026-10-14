"""Logs view for ThreatDesk.

Features:
- File picker and multi-file drag-and-drop
- Log file metadata & ingestion controls
- Paginated table backed by SQLite EventRepo using TableCard and AnalysisTable
- Search and IP filter
- Double-click row opens full forensic EventInspectorDialog
- TactileButtons for Demo load, file browse, and page controls
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Signal
from PySide6.QtGui import QColor, QDragEnterEvent, QDropEvent
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

from app.models.event import LogEvent
from app.storage.repositories import EventRepo
from app.ui.theme import GUTTER, SPACE, quality_color
from app.ui.widgets.animated_button import TactileButton
from app.ui.widgets.event_inspector import EventInspectorDialog
from app.ui.widgets.interactive_table import (
    AnalysisTable,
    TableCard,
    mono_item,
    text_item,
)
from app.ui.widgets.surfaces import Card, SectionHeader


class LogsView(QWidget):
    files_selected = Signal(list)
    load_demo_requested = Signal()

    def __init__(self, event_repo: EventRepo, parent: QWidget | None = None):
        super().__init__(parent)
        self.event_repo = event_repo
        self.setAcceptDrops(True)
        self.current_session_id: str | None = None
        self.page = 0
        self.page_size = 100
        self.current_events: list[LogEvent] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(
            GUTTER["view"], GUTTER["view_top"], GUTTER["view"], GUTTER["view_bottom"]
        )
        layout.setSpacing(SPACE["md"])

        # 1. Header
        self.header = SectionHeader(
            title="Log Files & Ingestion Workstation",
            caption="Drag & drop logs or select files to ingest. Raw log lines are forensically preserved.",
            trailing=None,
        )
        self.demo_btn = TactileButton(
            "Load Demo Logs", appearance="default", tooltip="Load pre-configured demo log session"
        )
        self.demo_btn.clicked.connect(self.load_demo_requested.emit)
        self.header.layout().addWidget(self.demo_btn)

        self.browse_btn = TactileButton(
            "Import Log Files", appearance="primary", tooltip="Browse filesystem to ingest log files"
        )
        self.browse_btn.clicked.connect(self._select_files)
        self.header.layout().addWidget(self.browse_btn)

        layout.addWidget(self.header)

        # 2. Controls & Pagination Bar in Inset Card
        ctrl_card = Card(variant="inset", padding=SPACE["sm"])
        ctrl_bar = QHBoxLayout()
        ctrl_bar.setContentsMargins(0, 0, 0, 0)
        ctrl_bar.setSpacing(SPACE["sm"])

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search raw lines, requests, paths...")
        self.search_input.textChanged.connect(self._on_search_changed)
        ctrl_bar.addWidget(self.search_input, 2)

        self.ip_filter = QLineEdit()
        self.ip_filter.setPlaceholderText("Filter by Source IP...")
        self.ip_filter.textChanged.connect(self._on_search_changed)
        ctrl_bar.addWidget(self.ip_filter, 1)

        self.btn_prev = TactileButton("◀ Prev", appearance="default")
        self.btn_prev.clicked.connect(self._prev_page)
        ctrl_bar.addWidget(self.btn_prev)

        self.page_label = QLabel("Page 1")
        self.page_label.setProperty("role", "secondary")
        self.page_label.setStyleSheet("font-weight: 600; padding: 0 4px;")
        ctrl_bar.addWidget(self.page_label)

        self.btn_next = TactileButton("Next ▶", appearance="default")
        self.btn_next.clicked.connect(self._next_page)
        ctrl_bar.addWidget(self.btn_next)

        ctrl_card.body().addLayout(ctrl_bar)
        layout.addWidget(ctrl_card)

        # 3. Logs AnalysisTable inside TableCard
        self.table_card = TableCard(
            title="Preserved Ingestion Stream",
            caption="Chronological record of ingested events with parser validation",
            parent=self,
        )

        self.table = AnalysisTable(
            0,
            7,
            parent=self.table_card,
            severity_column=None,
            stretch_column=6,
        )
        self.table.setHorizontalHeaderLabels(
            [
                "# Line",
                "Quality",
                "Timestamp",
                "Source IP",
                "Status",
                "User / Auth",
                "Request / Payload (Decoded Preview)",
            ]
        )
        self.table.setColumnWidth(0, 75)
        self.table.setColumnWidth(1, 90)
        self.table.setColumnWidth(2, 180)
        self.table.setColumnWidth(3, 140)
        self.table.setColumnWidth(4, 75)
        self.table.setColumnWidth(5, 120)
        self.table.horizontalHeader().setSectionResizeMode(
            6, QHeaderView.ResizeMode.Stretch
        )
        self.table.itemDoubleClicked.connect(self._on_row_double_clicked)
        self.table.row_activated.connect(self._on_row_activated)

        self.table_card.attach_table(self.table)
        self.table_card.set_empty_state(
            title="No Ingested Log Events",
            body="Drag and drop log files directly into this window, or import logs from the Dashboard.",
        )
        layout.addWidget(self.table_card, 1)
        self.refresh()

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent) -> None:
        paths = []
        for url in event.mimeData().urls():
            p = url.toLocalFile()
            if p and Path(p).is_file():
                paths.append(p)
        if paths:
            self.files_selected.emit(paths)

    def _select_files(self) -> None:
        files, _ = QFileDialog.getOpenFileNames(
            self,
            "Select Log Files to Ingest",
            "",
            "Log Files (*.log *.txt *.out);;All Files (*)",
        )
        if files:
            self.files_selected.emit(files)

    def set_session(self, session_id: str | None, summary_meta: str = "") -> None:
        self.current_session_id = session_id
        self.page = 0
        if summary_meta:
            self.header.set_caption(summary_meta)
        elif session_id:
            self.header.set_caption(f"Active Session: {session_id} · Preserved Raw Logs")
        else:
            self.header.set_caption("Ingest, parse, and forensically explore raw security event logs")
        self.refresh()

    def refresh(self) -> None:
        search = self.search_input.text().strip() or None
        ip_f = self.ip_filter.text().strip() or None

        self.current_events = self.event_repo.get_events(
            session_id=self.current_session_id,
            limit=self.page_size,
            offset=self.page * self.page_size,
            filter_ip=ip_f,
            search=search,
        )

        total_matching = self.event_repo.count_events(
            session_id=self.current_session_id,
            filter_ip=ip_f,
            search=search,
        )
        max_pages = max(1, (total_matching + self.page_size - 1) // self.page_size)
        # Ensure page stays strictly within [0, max_pages - 1]
        if self.page >= max_pages:
            self.page = max(0, max_pages - 1)
        elif self.page < 0:
            self.page = 0

        self.page_label.setText(f"Page {self.page + 1} of {max_pages}")
        self.btn_prev.setEnabled(self.page > 0)
        self.btn_next.setEnabled(self.page < max_pages - 1)

        self.table.setRowCount(len(self.current_events))
        for row, ev in enumerate(self.current_events):
            # Col 0: Line number
            l_item = mono_item(str(ev.line_number), color_token="text_muted")
            self.table.setItem(row, 0, l_item)

            # Col 1: Parse Quality
            q_val = ev.parse_quality.value if ev.parse_quality else "unparsed"
            q_item = text_item(q_val.upper())
            q_item.setForeground(QColor(quality_color(q_val)))
            self.table.setItem(row, 1, q_item)

            # Col 2: Timestamp
            t_item = mono_item(ev.timestamp or "-", color_token="text_secondary")
            self.table.setItem(row, 2, t_item)

            # Col 3: Source IP
            ip_item = mono_item(ev.source_ip or "-", color_token="text_primary")
            self.table.setItem(row, 3, ip_item)

            # Col 4: Status Code
            s_code = ev.status_code or "-"
            s_token = "severity_high" if s_code.startswith(("4", "5")) else "text_secondary"
            s_item = mono_item(s_code, color_token=s_token)
            self.table.setItem(row, 4, s_item)

            # Col 5: User
            u_item = text_item(ev.username or "-", color_token="text_secondary")
            self.table.setItem(row, 5, u_item)

            # Col 6: Decoded Request / Path
            req_txt = ev.normalized_request or ev.display_request()
            r_item = mono_item(req_txt, color_token="text_primary")
            self.table.setItem(row, 6, r_item)

        self.table_card.refresh_empty_state()

    def _on_search_changed(self) -> None:
        self.page = 0
        self.refresh()

    def _prev_page(self) -> None:
        if self.page > 0:
            self.page -= 1
            self.refresh()

    def _next_page(self) -> None:
        search = self.search_input.text().strip() or None
        ip_f = self.ip_filter.text().strip() or None
        total_matching = self.event_repo.count_events(
            session_id=self.current_session_id,
            filter_ip=ip_f,
            search=search,
        )
        max_pages = max(1, (total_matching + self.page_size - 1) // self.page_size)
        if self.page < max_pages - 1:
            self.page += 1
            self.refresh()

    def _on_row_double_clicked(self, item: QTableWidgetItem) -> None:
        self._inspect_row(item.row())

    def _on_row_activated(self, row: int) -> None:
        self._inspect_row(row)

    def _inspect_row(self, row: int) -> None:
        if 0 <= row < len(self.current_events):
            ev = self.current_events[row]
            dlg = EventInspectorDialog(event=ev, parent=self)
            dlg.exec()

    def refresh_theme(self) -> None:
        """Re-render table rows and badges when theme changes."""
        self.table.refresh_theme()
        self.refresh()
