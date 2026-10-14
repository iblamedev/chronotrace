"""Main application window for ThreatDesk.

Composition
-----------
* A minimal vertical :class:`~app.ui.widgets.sidebar.Sidebar` with a single
  animated active-state indicator — not a bulky dashboard menu.
* A stacked content area whose views cross-fade in, driven by
  :func:`app.ui.animations.cross_fade`.
* A refined status bar: message, progress, current page, session chip, clock.
* Two floating overlay layers: the :class:`ToastHost` (bottom-right) and the
  :class:`CommandPalette` (``Ctrl+K``).
* A seamless dual-theme toggle (``Ctrl+Shift+L``) that re-renders once and
  brightens in, rather than snapping colours.

Views
-----
0 Dashboard · 1 Log Ingestion · 2 Security Alerts · 3 Threat Intel ·
4 Hostile Watchlist · 5 Detection Rules · 6 Live File Tail ·
7 Incident Reports · 8 Settings & Storage · 9 Project Info

Background multi-threaded analysis (QThreadPool) keeps the UI non-blocking, and
the selected theme is persisted to the local SQLite settings table.
"""

from __future__ import annotations

import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.windll.user32
    dwmapi = ctypes.windll.dwmapi

    class _MARGINS(ctypes.Structure):
        _fields_ = [
            ("cxLeftWidth", ctypes.c_int),
            ("cxRightWidth", ctypes.c_int),
            ("cyTopHeight", ctypes.c_int),
            ("cyBottomHeight", ctypes.c_int),
        ]

    class _MSG(ctypes.Structure):
        _fields_ = [
            ("hwnd", wintypes.HWND),
            ("message", wintypes.UINT),
            ("wParam", wintypes.WPARAM),
            ("lParam", wintypes.LPARAM),
            ("time", wintypes.DWORD),
            ("pt", wintypes.POINT),
        ]
    class _POINT(ctypes.Structure):
        _fields_ = [
            ("x", ctypes.c_long),
            ("y", ctypes.c_long),
        ]

    user32.ScreenToClient.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
else:
    user32 = None
    dwmapi = None
    _POINT = None

from PySide6.QtCore import (
    QObject,
    QPoint,
    QRect,
    QRunnable,
    Qt,
    QThreadPool,
    QTimer,
    Signal,
)
from PySide6.QtGui import QIcon, QKeySequence, QPixmap, QShortcut
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from app.core.correlator import CorrelationEngine
from app.core.detector import RuleEngine
from app.core.normalizer import normalize_events
from app.core.parser import ParserRegistry
from app.core.severity import resolve_severity
from app.models.detection import Alert, AlertStatus, AnalysisSession
from app.models.event import LogEvent
from app.storage.database import Database
from app.storage.repositories import (
    AlertRepo,
    BlocklistRepo,
    EventRepo,
    IOCRepo,
    RuleRepo,
    SessionRepo,
    SettingsRepo,
)
from app.ui.alerts_view import AlertsView
from app.ui.animations import cross_fade
from app.ui.dashboard import DashboardView
from app.ui.ioc_view import IOCView
from app.ui.live_monitor import LiveMonitorView
from app.ui.logs_view import LogsView
from app.ui.project_info_view import ProjectInfoView
from app.ui.reports_view import ReportsView
from app.ui.rules_view import RulesView
from app.ui.settings_view import SettingsView
from app.ui.theme import (
    MOTION,
    SPACE,
    TOKENS,
    active_theme,
    apply_theme,
    next_theme_key,
    refresh_application_theme,
    set_theme,
    theme_label,
)
from app.ui.watchlist_view import WatchlistView
from app.ui.widgets.command_palette import Command, CommandPalette
from app.ui.widgets.sidebar import Sidebar
from app.ui.widgets.title_bar import ModernTitleBar
from app.ui.widgets.toast_notification import ToastHost
from app.utils.time import india_time_text

#: Navigation destinations, in stack order.
NAV_ITEMS: tuple[tuple[str, int], ...] = (
    ("Dashboard", 0),
    ("Log Ingestion", 1),
    ("Security Alerts", 2),
    ("Threat Intel", 3),
    ("Hostile Watchlist", 4),
    ("Detection Rules", 5),
    ("Live File Tail", 6),
    ("Incident Reports", 7),
    ("Settings & Storage", 8),
    ("Project Info", 9),
)

#: Human-readable page names, used by the status bar and command palette.
PAGE_NAMES = {index: label for label, index in NAV_ITEMS}


class AnalysisWorkerSignals(QObject):
    progress = Signal(int, str)
    finished = Signal(object)  # session
    error = Signal(str)


class AnalysisWorker(QRunnable):
    """Runs the full parse → normalize → detect → correlate pipeline off-thread."""

    def __init__(self, file_paths: list[str], rules: list, db_path: Path):
        super().__init__()
        self.file_paths = file_paths
        self.rules = rules
        self.db_path = db_path
        self.signals = AnalysisWorkerSignals()

    def run(self) -> None:
        worker_db = Database(self.db_path)
        try:
            self.signals.progress.emit(
                15, "Parsing structured and unstructured log lines…"
            )
            parser = ParserRegistry()
            all_events: list[LogEvent] = []
            for file_path in self.file_paths:
                all_events.extend(parser.parse_file(file_path))

            if not all_events:
                self.signals.error.emit(
                    "No log lines could be parsed from the selected files."
                )
                return

            self.signals.progress.emit(
                35, "Normalizing payloads (multi-pass URL decode & unescape)…"
            )
            normalize_events(all_events)

            self.signals.progress.emit(
                55, "Running signature threat engine against candidate texts…"
            )
            detector = RuleEngine(self.rules)
            sig_detections = []
            batch_size = 4096
            for start in range(0, len(all_events), batch_size):
                sig_detections.extend(
                    detector.detect(all_events[start : start + batch_size])
                )
                time.sleep(0)

            self.signals.progress.emit(
                75, "Performing sliding-window behavioral correlation…"
            )
            beh_detections = CorrelationEngine().correlate(all_events, sig_detections)
            all_detections = sig_detections + beh_detections

            self.signals.progress.emit(
                85, "Resolving alert severity and assembling forensic records…"
            )
            session_id = f"sess_{uuid.uuid4().hex[:8]}"
            now = datetime.now(timezone.utc)
            alerts: list[Alert] = []

            for detection in all_detections:
                detection.severity = resolve_severity(detection, beh_detections)
                alerts.append(
                    Alert(
                        alert_id=f"alt_{uuid.uuid4().hex[:8]}",
                        detection=detection,
                        created_at=now,
                        status=AlertStatus.NEW,
                        notes=detection.context_notes,
                    )
                )

            self.signals.progress.emit(
                95, "Persisting session records to the local SQLite database…"
            )
            from collections import Counter

            session = AnalysisSession(
                session_id=session_id,
                created_at=now,
                source_files=tuple(self.file_paths),
                total_events=len(all_events),
                total_detections=len(alerts),
                severity_counts=dict(
                    Counter(alert.detection.severity.value for alert in alerts)
                ),
            )

            SessionRepo(worker_db).save_session(session)
            EventRepo(worker_db).save_events(session_id, all_events)
            AlertRepo(worker_db).save_alerts(alerts, session_id)

            self.signals.progress.emit(100, "Analysis complete.")
            self.signals.finished.emit(session)
        except Exception as exc:  # noqa: BLE001
            self.signals.error.emit(str(exc))
        finally:
            worker_db.close()


class MainWindow(QMainWindow):
    def __init__(self, db: Database | None = None):
        super().__init__()
        self.setWindowTitle("ChronoTrace — Log-Based Threat Detection System")
        self.setMinimumSize(1180, 760)

        self.db = db or Database()
        self.session_repo = SessionRepo(self.db)
        self.event_repo = EventRepo(self.db)
        self.rule_repo = RuleRepo(self.db)
        self.alert_repo = AlertRepo(self.db)
        self.ioc_repo = IOCRepo(self.db)
        self.blocklist_repo = BlocklistRepo(self.db)
        self.settings_repo = SettingsRepo(self.db)

        self._apply_window_icon()

        # Activate the persisted theme before any widget is built so the first
        # paint is already correct — no flash of the wrong theme.
        apply_theme(self.settings_repo.get("app_theme", "graphite"))
        refresh_application_theme()

        self.thread_pool = QThreadPool.globalInstance()

        # Frameless window configuration for modern custom titlebar & Aero shadows
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Window)

        # ---- root structure -------------------------------------------------
        central = QWidget(self)
        central.setObjectName("ContentArea")
        self.setCentralWidget(central)

        window_layout = QVBoxLayout(central)
        window_layout.setContentsMargins(0, 0, 0, 0)
        window_layout.setSpacing(0)

        # 1. Sleek Glassy Title Bar at top edge
        self.title_bar = ModernTitleBar(central)
        self.title_bar.minimize_requested.connect(self.showMinimized)
        self.title_bar.maximize_requested.connect(self._toggle_maximize)
        self.title_bar.close_requested.connect(self.close)
        window_layout.addWidget(self.title_bar)

        # 2. Main Workspace (Sidebar + Content)
        workspace = QWidget(central)
        workspace_layout = QHBoxLayout(workspace)
        workspace_layout.setContentsMargins(0, 0, 0, 0)
        workspace_layout.setSpacing(0)
        window_layout.addWidget(workspace, 1)

        self.sidebar = Sidebar(
            NAV_ITEMS,
            workspace,
            current_theme=active_theme(),
            logo_pixmap=self._logo_pixmap(30),
        )
        self.sidebar.page_requested.connect(self._switch_page)
        self.sidebar.theme_change_requested.connect(self._on_theme_selected)
        self.sidebar.command_palette_requested.connect(self._open_command_palette)
        workspace_layout.addWidget(self.sidebar)

        self._content = QWidget(workspace)
        self._content.setObjectName("ViewRoot")
        content_layout = QVBoxLayout(self._content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(0)

        self.stack = QStackedWidget()
        content_layout.addWidget(self.stack, 1)
        content_layout.addWidget(self._build_status_bar())
        workspace_layout.addWidget(self._content, 1)

        # ---- views ----------------------------------------------------------
        self.dashboard_view = DashboardView(self.event_repo, self)
        self.logs_view = LogsView(self.event_repo, self)
        self.alerts_view = AlertsView(
            self.alert_repo, self.blocklist_repo, self.event_repo, self
        )
        self.ioc_view = IOCView(self.ioc_repo, self)
        self.watchlist_view = WatchlistView(self.blocklist_repo, self)
        self.rules_view = RulesView(self.rule_repo, self)
        self.live_view = LiveMonitorView(self.rule_repo, self)
        self.reports_view = ReportsView(self.session_repo, self.alert_repo, self)
        self.settings_view = SettingsView(self.db, self.event_repo, self)
        self.project_info_view = ProjectInfoView(self)

        self.views: list[QWidget] = [
            self.dashboard_view,
            self.logs_view,
            self.alerts_view,
            self.ioc_view,
            self.watchlist_view,
            self.rules_view,
            self.live_view,
            self.reports_view,
            self.settings_view,
            self.project_info_view,
        ]
        for view in self.views:
            self.stack.addWidget(view)

        # ---- overlays --------------------------------------------------------
        self.toast_host = ToastHost(self._content)
        self.palette = CommandPalette(self._content)
        self.palette.set_commands(self._build_commands())
        self.palette.raise_()

        # ---- inter-view wiring ----------------------------------------------
        self.dashboard_view.open_logs_requested.connect(lambda: self._switch_page(1))
        self.dashboard_view.select_files_requested.connect(self.select_log_files)
        self.dashboard_view.load_demo_requested.connect(self.load_demo_logs)
        self.dashboard_view.clear_session_requested.connect(self._clear_session)
        self.logs_view.load_demo_requested.connect(self.load_demo_logs)
        self.logs_view.files_selected.connect(self.run_analysis)
        self.alerts_view.watchlist_updated.connect(self.watchlist_view.refresh)
        self.settings_view.theme_changed.connect(self._on_theme_selected)

        QShortcut(QKeySequence("Ctrl+K"), self, self._open_command_palette)
        QShortcut(QKeySequence("Ctrl+Shift+L"), self, self._toggle_theme)
        for index in range(len(NAV_ITEMS)):
            QShortcut(
                QKeySequence(f"Ctrl+{min(9, index)}"),
                self,
                lambda i=index: self._switch_page(i),
            )

        # ---- startup state ---------------------------------------------------
        self._clock = QTimer(self)
        self._clock.setInterval(1000)
        self._clock.timeout.connect(self._tick_clock)
        self._clock.start()
        self._tick_clock()

        self.sidebar.set_active(0, animate=False)

        latest = self.session_repo.get_latest_session()
        if latest:
            self._apply_session(
                latest, self.alert_repo.get_alerts(session_id=latest.session_id)
            )

    # ------------------------------------------------------------------
    # Window chrome
    # ------------------------------------------------------------------
    def _apply_window_icon(self) -> None:
        assets = Path(__file__).resolve().parent.parent / "assets"
        for name in ("icon.ico", "logo.png"):
            candidate = assets / name
            if candidate.exists():
                self.setWindowIcon(QIcon(str(candidate)))
                return

    def _logo_pixmap(self, size: int) -> QPixmap | None:
        logo = Path(__file__).resolve().parent.parent / "assets" / "logo.png"
        if not logo.exists():
            return None
        # Render at 2x logical size and set device pixel ratio to keep the circular badge razor sharp on high-DPI
        target_px = size * 2
        pm = QPixmap(str(logo)).scaled(
            target_px,
            target_px,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )
        pm.setDevicePixelRatio(2.0)
        return pm

    def _build_status_bar(self) -> QWidget:
        bar = QFrame()
        bar.setObjectName("StatusBar")
        bar.setFixedHeight(30)

        layout = QHBoxLayout(bar)
        layout.setContentsMargins(SPACE["lg"], 0, SPACE["xl"], 0)
        layout.setSpacing(SPACE["lg"])

        self.status_msg = QLabel("Ready", bar)
        self.status_msg.setProperty("role", "secondary")
        layout.addWidget(self.status_msg, 1)

        self.progress_bar = QProgressBar(bar)
        self.progress_bar.setFixedSize(150, 4)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        self.page_tag = QLabel(PAGE_NAMES[0], bar)
        self.page_tag.setProperty("role", "micro")
        layout.addWidget(self.page_tag)

        self.session_tag = QLabel("No session loaded", bar)
        self.session_tag.setProperty("role", "mono")
        self.session_tag.setStyleSheet(f"color: {TOKENS['text_muted']};")
        layout.addWidget(self.session_tag)

        self.clock_label = QLabel("", bar)
        self.clock_label.setProperty("role", "mono")
        self.clock_label.setStyleSheet(f"color: {TOKENS['text_tertiary']};")
        layout.addWidget(self.clock_label)

        return bar

    def _tick_clock(self) -> None:
        self.clock_label.setText(india_time_text())

    # ------------------------------------------------------------------
    # Navigation & theming
    # ------------------------------------------------------------------
    def _switch_page(self, index: int) -> None:
        if not 0 <= index < self.stack.count():
            return
        previous = self.stack.currentWidget()
        incoming = self.stack.widget(index)
        self.stack.setCurrentIndex(index)
        self.sidebar.set_active(index)
        self.page_tag.setText(PAGE_NAMES.get(index, ""))

        if previous is not None and previous is not incoming:
            cross_fade(self.stack, incoming, None, duration_ms=MOTION["fast"])

    def _on_theme_selected(self, theme_key: str) -> None:
        """Switch themes seamlessly: re-render once, then brighten in."""
        if theme_key == active_theme():
            return

        set_theme(theme_key)
        self.settings_repo.set("app_theme", theme_key)
        refresh_application_theme()

        self._refresh_themed_children()
        current = self.stack.currentWidget()
        if current is not None:
            cross_fade(self.stack, current, current, duration_ms=MOTION["base"])

        self.status_msg.setText(f"Theme · {theme_label(theme_key)}")

    def _toggle_theme(self) -> None:
        self._on_theme_selected(next_theme_key(active_theme()))

    def _refresh_themed_children(self) -> None:
        """Repaint what QSS cannot reach — charts, inline stylesheets, paint code."""
        self.title_bar.refresh_theme()
        self.sidebar.refresh_theme(active_theme())
        self.toast_host.refresh_theme()
        self.palette.refresh_theme()
        self.session_tag.setStyleSheet(f"color: {TOKENS['text_muted']};")
        self.clock_label.setStyleSheet(f"color: {TOKENS['text_tertiary']};")

        for view in self.views:
            refresh = getattr(view, "refresh_theme", None)
            if callable(refresh):
                refresh()

    # ------------------------------------------------------------------
    # Command palette
    # ------------------------------------------------------------------
    def _build_commands(self) -> list[Command]:
        commands: list[Command] = [
            Command(
                key=f"go.{index}",
                label=f"Go to {label}",
                category="Navigate",
                shortcut=f"Ctrl+{min(9, index)}",
                description="Switch the workspace view",
                keywords=(label.lower(),),
                handler=lambda i=index: self._switch_page(i),
            )
            for label, index in NAV_ITEMS
        ]

        commands.extend(
            [
                Command(
                    key="action.demo",
                    label="Load demo logs",
                    category="Action",
                    description="Ingest the bundled sample attack and auth logs",
                    keywords=("sample", "demo", "load"),
                    handler=self.load_demo_logs,
                ),
                Command(
                    key="action.clear",
                    label="Clear active logs and sessions",
                    category="Action",
                    description="Purge active logs and reset dashboard metrics",
                    keywords=("clear", "reset", "purge", "delete"),
                    handler=self._clear_session,
                ),
                Command(
                    key="action.import",
                    label="Import log files…",
                    category="Action",
                    description="Open file dialog to browse and ingest log files",
                    keywords=("open", "import", "file", "ingest", "browse"),
                    handler=self.select_log_files,
                ),
                Command(
                    key="action.theme",
                    label="Toggle theme (Graphite / Paper)",
                    category="Appearance",
                    shortcut="Ctrl+Shift+L",
                    description="Switch between the dark and light theme",
                    keywords=("dark", "light", "appearance", "graphite", "paper"),
                    handler=self._toggle_theme,
                ),
            ]
        )
        return commands

    def _open_command_palette(self) -> None:
        self.palette.set_commands(self._build_commands())
        self.palette.open_palette()

    # ------------------------------------------------------------------
    # Analysis pipeline
    # ------------------------------------------------------------------
    def select_log_files(self) -> None:
        """Prompt file dialog to select log files and run analysis."""
        files, _ = QFileDialog.getOpenFileNames(
            self,
            "Select Log Files to Ingest",
            "",
            "Log Files (*.log *.txt *.out *.csv *.json);;All Files (*)",
        )
        if files:
            self.run_analysis(files)

    def load_demo_logs(self) -> None:
        # sample_data/ lives at the repository root: app/ui/main_window.py is
        # three levels below it (app/ui -> app -> repo root).
        sample_dir = Path(__file__).resolve().parents[2] / "sample_data"
        files = [
            str(path)
            for path in (sample_dir / "attacks.log", sample_dir / "login-logs.txt")
            if path.exists()
        ]

        if not files:
            self.toast_host.show_toast(
                "Demo logs unavailable",
                "Could not locate sample logs in the sample_data directory.",
                severity="warning",
                meta="sample_data",
            )
            return

        self.run_analysis(files)

    def run_analysis(self, file_paths: list[str]) -> None:
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(5)
        self.status_msg.setText("Starting threat detection pipeline…")

        worker = AnalysisWorker(
            file_paths, self.rule_repo.get_enabled_rules(), self.db.db_path
        )
        worker.signals.progress.connect(self._on_worker_progress)
        worker.signals.finished.connect(self._on_worker_finished)
        worker.signals.error.connect(self._on_worker_error)
        self.thread_pool.start(worker)

    def _on_worker_progress(self, value: int, message: str) -> None:
        self.progress_bar.setValue(value)
        self.status_msg.setText(message)

    def _on_worker_finished(self, session: AnalysisSession) -> None:
        self.progress_bar.setVisible(False)
        self.status_msg.setText(
            f"Analysis complete — {session.total_events:,} events, "
            f"{session.total_detections:,} detections."
        )

        alerts = self.alert_repo.get_alerts(session_id=session.session_id)
        QTimer.singleShot(0, lambda: self._apply_session(session, alerts))
        self._switch_page(0)

        criticals = session.severity_counts.get("critical", 0)
        self.toast_host.show_toast(
            "Analysis complete",
            f"{session.total_events:,} events parsed across "
            f"{len(session.source_files)} file(s); "
            f"{session.total_detections:,} detections raised.",
            severity="critical" if criticals else "success",
            meta=session.session_id,
            action_label="Dismiss",
        )

    def _on_worker_error(self, error_message: str) -> None:
        self.progress_bar.setVisible(False)
        self.status_msg.setText("Analysis failed.")
        self.toast_host.show_toast(
            "Analysis pipeline error",
            error_message,
            severity="error",
            duration_ms=9000,
        )

    def _apply_session(self, session: AnalysisSession, alerts: list[dict]) -> None:
        self.session_tag.setText(session.session_id)
        self.session_tag.setToolTip(
            f"Session {session.session_id}\nFiles: {', '.join(session.source_files)}"
        )
        self.dashboard_view.update_data(session, alerts)
        self.logs_view.set_session(
            session.session_id,
            f"Session {session.session_id} · {len(session.source_files)} source file(s)",
        )
        QTimer.singleShot(0, lambda: self.alerts_view.set_session(session.session_id))
        QTimer.singleShot(0, self.reports_view.refresh_sessions)
        QTimer.singleShot(0, self.settings_view.refresh_stats)

    def _clear_session(self) -> None:
        """Clear active log session, reset database records and UI telemetry."""
        total_events = self.event_repo.count_events()
        sessions = self.session_repo.list_sessions()
        if total_events == 0 and not sessions and self.dashboard_view.session is None:
            self.toast_host.show_toast(
                "No Logs to Clear",
                "No active logs or sessions are currently loaded in the workstation.",
                severity="info",
            )
            return

        reply = QMessageBox.question(
            self,
            "Clear Log Session",
            "Are you sure you want to clear the active log session and reset all metrics? Rules, watchlists, and IOC intelligence will be preserved.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        conn = self.db.get_connection()
        with conn:
            conn.execute("DELETE FROM events")
            conn.execute("DELETE FROM alerts")
            conn.execute("DELETE FROM sessions")
            conn.execute("VACUUM")

        self.session_tag.setText("No session loaded")
        self.session_tag.setToolTip("No active log session loaded")
        self.status_msg.setText("Session cleared. Ready for log ingestion.")

        self.dashboard_view.reset_data()
        self.logs_view.set_session(None)
        self.alerts_view.set_session(None)
        self.reports_view.refresh_sessions()
        self.settings_view.refresh_stats()

        self.toast_host.show_toast(
            "Session Cleared",
            "Active log stream and telemetry have been cleared.",
            severity="info",
        )

    def _toggle_maximize(self) -> None:
        """Toggle between maximized and normal window state."""
        if self.isMaximized():
            self.showNormal()
        else:
            self.showMaximized()

    def changeEvent(self, event) -> None:
        super().changeEvent(event)
        if event.type() == event.Type.WindowStateChange and hasattr(self, "title_bar"):
            self.title_bar.set_maximized_state(self.isMaximized())

    def showEvent(self, event) -> None:
        super().showEvent(event)
        if sys.platform == "win32" and user32 and dwmapi:
            try:
                hwnd = int(self.winId())
                # Add WS_THICKFRAME, WS_MINIMIZEBOX, WS_MAXIMIZEBOX for native taskbar animations & snap
                style = user32.GetWindowLongW(hwnd, -16)
                user32.SetWindowLongW(hwnd, -16, style | 0x00040000 | 0x00020000 | 0x00010000)
                # DWM Drop Shadow for frameless window
                margins = _MARGINS(1, 1, 1, 1)
                dwmapi.DwmExtendFrameIntoClientArea(hwnd, ctypes.byref(margins))
                # Windows 11 rounded window corners (DWMWA_WINDOW_CORNER_PREFERENCE = 33, DWMWCP_ROUND = 2)
                corner = ctypes.c_int(2)
                dwmapi.DwmSetWindowAttribute(hwnd, 33, ctypes.byref(corner), ctypes.sizeof(corner))
            except OSError:
                return

    def nativeEvent(self, event_type, message):
        if sys.platform == "win32" and event_type == b"windows_generic_MSG":
            msg = _MSG.from_address(int(message))
            if msg.message == 0x0084:  # WM_NCHITTEST
                hwnd = int(self.winId())
                if user32 and _POINT:
                    pt = _POINT(msg.pt.x, msg.pt.y)
                    user32.ScreenToClient(hwnd, ctypes.byref(pt))
                    dpr = self.devicePixelRatio()
                    x = int(pt.x / dpr)
                    y = int(pt.y / dpr)
                else:
                    pos = self.mapFromGlobal(QPoint(msg.pt.x, msg.pt.y))
                    x, y = pos.x(), pos.y()

                w, h = self.width(), self.height()
                border = 8

                # 1. Title bar control buttons first (never blocked by top/right resize borders)
                if hasattr(self, "title_bar"):
                    for btn in (
                        self.title_bar.btn_min,
                        self.title_bar.btn_max,
                        self.title_bar.btn_close,
                    ):
                        if btn.isVisible():
                            btn_pos = btn.mapTo(self, btn.rect().topLeft())
                            if QRect(btn_pos, btn.size()).contains(x, y):
                                return True, 1  # HTCLIENT

                # 2. Edge and corner resizing when window is not maximized
                if not self.isMaximized():
                    if x < border and y < border:
                        return True, 13  # HTTOPLEFT
                    if x > w - border and y < border:
                        return True, 14  # HTTOPRIGHT
                    if x < border and y > h - border:
                        return True, 16  # HTBOTTOMLEFT
                    if x > w - border and y > h - border:
                        return True, 17  # HTBOTTOMRIGHT
                    if x < border:
                        return True, 10  # HTLEFT
                    if x > w - border:
                        return True, 11  # HTRIGHT
                    if y < border:
                        return True, 12  # HTTOP
                    if y > h - border:
                        return True, 15  # HTBOTTOM

                # 3. Title bar dragging
                if hasattr(self, "title_bar") and 0 <= y <= self.title_bar.height():
                    return True, 2  # HTCAPTION

        return super().nativeEvent(event_type, message)

    def closeEvent(self, event) -> None:
        """Persist the active theme before exit."""
        self.settings_repo.set("app_theme", active_theme())
        super().closeEvent(event)
