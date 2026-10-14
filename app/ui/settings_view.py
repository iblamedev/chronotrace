"""Settings and Maintenance view for ThreatDesk.

Features:
- Dual-theme switcher (SegmentedControl between Graphite and Paper)
- Local SQLite database health inspection & statistics
- Prune/Purge raw event history to maintain database size
- Offline status confirmation & assurance checklist
- Built with SectionHeader, Card(variant="primary" & "inset"), TactileButton, SegmentedControl, and ToastHost
"""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QVBoxLayout,
    QWidget,
)

from app.storage.database import Database
from app.storage.repositories import EventRepo, SettingsRepo
from app.ui.theme import (
    GUTTER,
    SPACE,
    active_theme,
    resolve_theme_key,
)
from app.ui.widgets.animated_button import SegmentedControl, TactileButton
from app.ui.widgets.surfaces import Card, SectionHeader
from app.ui.widgets.toast_notification import ToastHost


class SettingsView(QWidget):
    theme_changed = Signal(str)

    def __init__(
        self, db: Database, event_repo: EventRepo, parent: QWidget | None = None
    ):
        super().__init__(parent)
        self.db = db
        self.event_repo = event_repo
        self.settings_repo = SettingsRepo(self.db)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(
            GUTTER["view"], GUTTER["view_top"], GUTTER["view"], GUTTER["view_bottom"]
        )
        layout.setSpacing(SPACE["lg"])

        # 1. Header
        self.header = SectionHeader(
            title="System Settings & Workstation Configuration",
            caption="Customize visual theme, inspect SQLite database health, and review offline assurances",
        )
        layout.addWidget(self.header)

        # 2. Appearance & Theme Card
        theme_card = Card(
            title="Visual Theme & Display Mode",
            subtitle="Curated semantic palette optimized for long analysis sessions and high-contrast scanning",
            variant="primary",
            parent=self,
        )

        theme_row = QHBoxLayout()
        theme_row.setSpacing(SPACE["md"])

        theme_label = QLabel("Active Desktop Aesthetic:")
        theme_label.setProperty("role", "body")
        theme_label.setStyleSheet("font-weight: 600;")
        theme_row.addWidget(theme_label)

        current_theme_key = resolve_theme_key(
            self.settings_repo.get("app_theme", active_theme())
        )

        self.theme_segment = SegmentedControl(
            options=[("graphite", "Graphite (Dark)"), ("paper", "Paper (Light)")],
            parent=theme_card,
            current=current_theme_key,
        )
        self.theme_segment.changed.connect(self._on_segment_changed)
        theme_row.addWidget(self.theme_segment)
        theme_row.addStretch(1)

        theme_card.body().addLayout(theme_row)
        layout.addWidget(theme_card)

        # 3. Database Persistence Card
        store_card = Card(
            title="Local SQLite Persistence",
            subtitle="Embedded database storage metrics, table row counts, and storage maintenance",
            variant="primary",
            parent=self,
        )

        self.db_path_lbl = QLabel(f"Database Path: {self.db.db_path}")
        self.db_path_lbl.setProperty("role", "mono")
        store_card.body().addWidget(self.db_path_lbl)

        self.db_stats_lbl = QLabel("Events in DB: Calculating...")
        self.db_stats_lbl.setProperty("role", "body")
        store_card.body().addWidget(self.db_stats_lbl)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(SPACE["sm"])

        self.btn_refresh = TactileButton("Refresh DB Stats", appearance="default")
        self.btn_refresh.clicked.connect(self.refresh_stats)
        btn_row.addWidget(self.btn_refresh)

        self.btn_purge = TactileButton("Purge Raw Events (Keep Rules/IOCs)", appearance="danger")
        self.btn_purge.clicked.connect(self._purge_events)
        btn_row.addWidget(self.btn_purge)
        btn_row.addStretch(1)

        store_card.body().addLayout(btn_row)
        layout.addWidget(store_card)

        # 4. Offline Assurances Card
        offline_card = Card(
            title="Defensive Security & Air-Gapped Assurances",
            subtitle="Cryptographic and architectural guarantees enforced by ThreatDesk core",
            variant="inset",
            parent=self,
        )

        self.guarantee_lbl = QLabel(
            "• <b>100% Offline:</b> ChronoTrace makes zero outbound network calls. All rule matching, behavioral correlation, and PDF reporting execute locally.<br>"
            "• <b>Inert Log Handling:</b> Log contents are treated as untrusted, inert text strings — no shell commands, scripts, or embedded payloads are ever executed.<br>"
            "• <b>Forensic Preservation:</b> Original raw lines are permanently preserved verbatim alongside decoded normalized requests."
        )
        self.guarantee_lbl.setProperty("role", "body")
        self.guarantee_lbl.setStyleSheet("line-height: 1.6; padding: 4px 0;")
        offline_card.body().addWidget(self.guarantee_lbl)
        layout.addWidget(offline_card)

        layout.addStretch(1)
        self.refresh_stats()

    def refresh_stats(self) -> None:
        count = self.event_repo.count_events()
        size_kb = 0
        if self.db.db_path.exists():
            size_kb = self.db.db_path.stat().st_size // 1024
        self.db_stats_lbl.setText(
            f"Total Stored Events: {count:,} records   ·   Database File Size: {size_kb:,} KB"
        )

    def _purge_events(self) -> None:
        count = self.event_repo.count_events()
        if count == 0:
            ToastHost.instance().show_toast(
                "There are no stored log events to purge.",
                title="Database Empty",
                severity="info",
            )
            return

        if (
            QMessageBox.question(
                self,
                "Purge Database",
                "Are you sure you want to purge all stored events and analysis sessions? Rules, watchlists, and IOCs will be retained.",
            )
            == QMessageBox.StandardButton.Yes
        ):
            conn = self.db.get_connection()
            with conn:
                conn.execute("DELETE FROM events")
                conn.execute("DELETE FROM alerts")
                conn.execute("DELETE FROM sessions")
                conn.execute("VACUUM")
            self.refresh_stats()
            ToastHost.instance().show_toast(
                "Stored log events purged and database vacuumed.",
                title="Database Vacuumed",
                severity="info",
            )

    def _on_segment_changed(self, key: str) -> None:
        if not key:
            return
        old_theme = active_theme()
        if key != old_theme:
            self.settings_repo.set("app_theme", key)
            self.theme_changed.emit(key)
            ToastHost.instance().show_toast(
                f"Theme switched to {key.title()}.",
                title="Theme Updated",
                severity="info",
            )

    def refresh_theme(self) -> None:
        """Sync segment buttons and dynamic label styles when theme changes externally."""
        curr = resolve_theme_key(self.settings_repo.get("app_theme", active_theme()))
        self.theme_segment.set_current(curr)
