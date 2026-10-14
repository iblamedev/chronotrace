"""SOC Analyst Threat Dashboard for ThreatDesk.

Designed to feel like a high-density, real-time security workstation:
- SectionHeader with actions (Load Demo Logs, Import Log Files)
- MetricRow hosting 5 MetricCard instances with animated counters
- Dual QtCharts panels (Threat Severity Donut and Top Attack Categories Bar) wrapped in Card
- High & Critical Priority Threat Stream table wrapped in TableCard and AnalysisTable
- Double-click forensic inspection via EventInspectorDialog
- Full token-driven dynamic theme updates via refresh_theme()
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from PySide6.QtCharts import (
    QBarCategoryAxis,
    QBarSeries,
    QBarSet,
    QChart,
    QChartView,
    QPieSeries,
    QValueAxis,
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QPainter
from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.models.detection import AnalysisSession
from app.storage.repositories import EventRepo
from app.ui.theme import (
    GUTTER,
    SPACE,
    chart_palette,
    qcolor,
    severity_color,
)
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


class DashboardView(QWidget):
    open_logs_requested = Signal()
    select_files_requested = Signal()
    load_demo_requested = Signal()
    clear_session_requested = Signal()

    def __init__(
        self, event_repo: EventRepo | None = None, parent: QWidget | None = None
    ):
        super().__init__(parent)
        self.event_repo = event_repo
        self.session: AnalysisSession | None = None
        self.alerts: list[dict[str, Any]] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(
            GUTTER["view"], GUTTER["view_top"], GUTTER["view"], GUTTER["view_bottom"]
        )
        layout.setSpacing(SPACE["lg"])

        # 1. Section Header Bar with quick action buttons
        self.clear_btn = TactileButton(
            "Clear Logs", appearance="default", tooltip="Clear active log session and reset dashboard metrics"
        )
        self.clear_btn.clicked.connect(self.clear_session_requested.emit)

        self.demo_btn = TactileButton(
            "Load Demo Logs", appearance="primary", tooltip="Load pre-configured demo log session"
        )
        self.demo_btn.clicked.connect(self.load_demo_requested.emit)

        self.import_btn = TactileButton(
            "Import Log Files", appearance="default", tooltip="Browse and ingest security log files"
        )
        self.import_btn.clicked.connect(self.select_files_requested.emit)

        self.header = SectionHeader(
            title="SOC Analyst Threat Dashboard",
            caption="Overview of real-time security posture and threat activity",
            trailing=None,
        )
        # Put actions in trailing slot of header layout: [Clear Logs] [Load Demo Logs] [Import Log Files]
        self.header.layout().addWidget(self.clear_btn)
        self.header.layout().addWidget(self.demo_btn)
        self.header.layout().addWidget(self.import_btn)
        layout.addWidget(self.header)

        # 2. Metric Cards Row
        self.card_events = MetricCard(
            title="Total Events",
            initial_value=0,
            subtitle="Parsed log events",
            accent_token="accent",
        )
        self.card_threats = MetricCard(
            title="Total Threats",
            initial_value=0,
            subtitle="Detected anomalies",
            accent_token="severity_high",
        )
        self.card_critical = MetricCard(
            title="Critical Threats",
            initial_value=0,
            subtitle="Immediate triage required",
            accent_token="severity_critical",
        )
        self.card_ips = MetricCard(
            title="Hostile IPs",
            initial_value=0,
            subtitle="Distinct attacker hosts",
            accent_token="severity_medium",
        )
        self.card_behavioral = MetricCard(
            title="Behavioral Patterns",
            initial_value=0,
            subtitle="Correlated multi-event attacks",
            accent_token="violet",
        )

        self.metrics_row = MetricRow(
            [
                self.card_events,
                self.card_threats,
                self.card_critical,
                self.card_ips,
                self.card_behavioral,
            ],
            parent=self,
            spacing=SPACE["md"],
        )
        layout.addWidget(self.metrics_row)

        # 3. Charts Row (Donut + Bar) inside Cards
        charts_layout = QHBoxLayout()
        charts_layout.setContentsMargins(0, 0, 0, 0)
        charts_layout.setSpacing(SPACE["md"])

        # Donut Chart Card
        self.sev_card = Card(
            title="Threat Severity Distribution",
            subtitle="Ratio of critical to informational detections",
            parent=self,
            variant="primary",
        )
        self.chart_sev_view = self._create_severity_chart()
        self.sev_card.body().addWidget(self.chart_sev_view, 1)
        charts_layout.addWidget(self.sev_card, 1)

        # Bar Chart Card
        self.cat_card = Card(
            title="Top Attack Vectors & Categories",
            subtitle="Most prevalent threat families across parsed logs",
            parent=self,
            variant="primary",
        )
        self.chart_cat_view = self._create_category_chart()
        self.cat_card.body().addWidget(self.chart_cat_view, 1)
        charts_layout.addWidget(self.cat_card, 1)

        layout.addLayout(charts_layout, 1)

        # 4. Recent High/Critical Alerts TableCard
        self.table_card = TableCard(
            title="High & Critical Priority Threat Stream",
            caption="Live feed of high-severity signature and behavioral detections",
            parent=self,
        )

        self.table = AnalysisTable(
            0,
            5,
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
                "Matched Trigger Snippet",
            ]
        )
        self.table.setColumnWidth(0, 110)
        self.table.setColumnWidth(1, 110)
        self.table.setColumnWidth(2, 240)
        self.table.setColumnWidth(3, 140)
        self.table.horizontalHeader().setSectionResizeMode(
            4, QHeaderView.ResizeMode.Stretch
        )
        self.table.itemDoubleClicked.connect(self._on_row_double_clicked)
        self.table.row_activated.connect(self._on_row_activated)

        self.table_card.attach_table(self.table)
        self.table_card.set_empty_state(
            title="No Active Threat Stream",
            body="Load demo security logs or import raw access logs to initiate automated signature scanning and behavioral correlation.",
        )
        layout.addWidget(self.table_card, 1)

    # -----------------------------------------------------------------------
    # Chart Factory Methods
    # -----------------------------------------------------------------------
    def _create_severity_chart(self) -> QChartView:
        palette = chart_palette()

        self.sev_series = QPieSeries()
        self.sev_series.setHoleSize(0.58)

        chart = QChart()
        chart.addSeries(self.sev_series)
        chart.setBackgroundBrush(Qt.BrushStyle.NoBrush)
        chart.setTitleBrush(QColor(palette["title"]))
        chart.legend().setAlignment(Qt.AlignmentFlag.AlignBottom)
        chart.legend().setLabelBrush(QColor(palette["label_strong"]))
        chart.setAnimationOptions(QChart.AnimationOption.SeriesAnimations)

        chart_view = QChartView(chart)
        chart_view.setRenderHint(QPainter.RenderHint.Antialiasing)
        chart_view.setStyleSheet("background: transparent; border: none;")
        return chart_view

    def _create_category_chart(self) -> QChartView:
        palette = chart_palette()

        self.cat_chart = QChart()
        self.cat_chart.setBackgroundBrush(Qt.BrushStyle.NoBrush)
        self.cat_chart.setTitleBrush(QColor(palette["title"]))
        self.cat_chart.legend().setVisible(False)
        self.cat_chart.setAnimationOptions(QChart.AnimationOption.SeriesAnimations)

        chart_view = QChartView(self.cat_chart)
        chart_view.setRenderHint(QPainter.RenderHint.Antialiasing)
        chart_view.setStyleSheet("background: transparent; border: none;")
        return chart_view

    # -----------------------------------------------------------------------
    # Data Updates
    # -----------------------------------------------------------------------
    def reset_data(self) -> None:
        """Reset all dashboard metrics, charts, and threat stream to clean state."""
        self.session = None
        self.alerts = []
        self.header.set_caption("Overview of real-time security posture and threat activity")

        self.card_events.set_value(0)
        self.card_threats.set_value(0)
        self.card_critical.set_value(0)
        self.card_ips.set_value(0)
        self.card_behavioral.set_value(0)

        self._refresh_severity_chart_data()
        self._refresh_category_chart_data()
        self._populate_stream_table()

    def update_data(
        self, session: AnalysisSession, alerts: list[dict[str, Any]]
    ) -> None:
        self.session = session
        self.alerts = alerts

        # Update header subtitle with session details
        sources_str = ", ".join(session.source_files) if session.source_files else "Direct Ingestion"
        self.header.set_caption(
            f"Active Session: {session.session_id} · Created: {session.created_at.strftime('%Y-%m-%d %H:%M:%S')} · Sources: {sources_str}"
        )

        # Calculate metrics
        unique_ips = {
            a.get("source_ip")
            for a in alerts
            if a.get("source_ip") and a.get("source_ip") != "-"
        }
        crit_count = session.severity_counts.get("critical", 0)
        beh_count = sum(1 for a in alerts if a.get("method") == "behavioral")

        # Animate metric cards
        self.card_events.set_value(session.total_events)
        self.card_threats.set_value(session.total_detections)
        self.card_critical.set_value(crit_count)
        self.card_ips.set_value(len(unique_ips))
        self.card_behavioral.set_value(beh_count)

        # Update Severity Donut
        self._refresh_severity_chart_data()

        # Update Categories Bar Chart
        self._refresh_category_chart_data()

        # Populate Recent High/Critical Table
        self._populate_stream_table()

    def _refresh_severity_chart_data(self) -> None:
        self.sev_series.clear()
        if not self.session:
            return

        counts = self.session.severity_counts
        for sev_name in ("critical", "high", "medium", "low", "info"):
            val = counts.get(sev_name, 0)
            if val > 0:
                s = self.sev_series.append(f"{sev_name.upper()} ({val})", val)
                s.setColor(QColor(severity_color(sev_name)))
                s.setBorderColor(qcolor("surface"))

    def _refresh_category_chart_data(self) -> None:
        self.cat_chart.removeAllSeries()
        for ax in list(self.cat_chart.axes()):
            self.cat_chart.removeAxis(ax)

        if not self.alerts:
            return

        cat_counts = Counter(a.get("category", "Other") for a in self.alerts)
        top_cats = cat_counts.most_common(5)
        if not top_cats:
            return

        palette = chart_palette()
        bar_set = QBarSet("Attacks")
        bar_set.setColor(qcolor("accent"))
        bar_set.setBorderColor(qcolor("accent_hover"))

        categories = []
        max_val = 0
        for cat_name, cnt in top_cats:
            bar_set.append(cnt)
            short_cat = cat_name.split("/")[0].strip()
            categories.append(short_cat)
            max_val = max(max_val, cnt)

        series = QBarSeries()
        series.append(bar_set)
        self.cat_chart.addSeries(series)

        axis_x = QBarCategoryAxis()
        axis_x.append(categories)
        axis_x.setLabelsColor(QColor(palette["label"]))
        axis_x.setGridLineColor(QColor(palette["grid"]))
        axis_x.setLinePenColor(QColor(palette["axis"]))
        self.cat_chart.addAxis(axis_x, Qt.AlignmentFlag.AlignBottom)
        series.attachAxis(axis_x)

        axis_y = QValueAxis()
        axis_y.setRange(0, max_val + max(2, int(max_val * 0.15)))
        axis_y.setLabelsColor(QColor(palette["label"]))
        axis_y.setGridLineColor(QColor(palette["grid"]))
        axis_y.setLinePenColor(QColor(palette["axis"]))
        self.cat_chart.addAxis(axis_y, Qt.AlignmentFlag.AlignLeft)
        series.attachAxis(axis_y)

    def _populate_stream_table(self) -> None:
        self.table.setRowCount(0)
        high_crit = [
            a for a in self.alerts if a.get("severity") in ("critical", "high")
        ][:50]
        self.table.setRowCount(len(high_crit))

        for row, a in enumerate(high_crit):
            sev = a.get("severity", "info")
            meth = a.get("method", "signature")

            # Col 0: SeverityBadge
            badge = SeverityBadge(sev, meth)
            self.table.setCellWidget(row, 0, badge)

            # Col 1: MethodChip
            chip = MethodChip(meth)
            self.table.setCellWidget(row, 1, chip)

            # Col 2: Threat Rule
            r_item = text_item(a.get("rule_name", ""), color_token="text_primary")
            self.table.setItem(row, 2, r_item)

            # Col 3: Source IP
            ip_item = mono_item(a.get("source_ip", "-"), color_token="text_secondary")
            self.table.setItem(row, 3, ip_item)

            # Col 4: Matched Trigger Snippet
            snip_text = a.get("matched_snippet", "")[:140]
            snip_item = mono_item(snip_text, color_token="text_muted")
            self.table.setItem(row, 4, snip_item)

        self.table_card.refresh_empty_state()

    # -----------------------------------------------------------------------
    # Event Handlers
    # -----------------------------------------------------------------------
    def _on_row_double_clicked(self, item: QTableWidgetItem) -> None:
        self._inspect_row(item.row())

    def _on_row_activated(self, row: int) -> None:
        self._inspect_row(row)

    def _inspect_row(self, row: int) -> None:
        high_crit = [
            a for a in self.alerts if a.get("severity") in ("critical", "high")
        ][:50]
        if 0 <= row < len(high_crit):
            alert = high_crit[row]
            ev = None
            if self.event_repo and alert.get("session_id") and alert.get("event_id"):
                ev = self.event_repo.get_event_by_line(
                    alert["session_id"], alert["event_id"]
                )
            dlg = EventInspectorDialog(event=ev, alert=alert, parent=self)
            dlg.exec()

    # -----------------------------------------------------------------------
    # Theme Refresh
    # -----------------------------------------------------------------------
    def refresh_theme(self) -> None:
        """Dynamically re-style charts and subcomponents when the theme changes."""
        palette = chart_palette()

        # Update severity donut
        self.sev_card.chart_sev_view = self.chart_sev_view
        sev_chart = self.chart_sev_view.chart()
        if sev_chart:
            sev_chart.setTitleBrush(QColor(palette["title"]))
            sev_chart.legend().setLabelBrush(QColor(palette["label_strong"]))
        self._refresh_severity_chart_data()

        # Update category bar chart
        if self.cat_chart:
            self.cat_chart.setTitleBrush(QColor(palette["title"]))
        self._refresh_category_chart_data()

        # Refresh metric cards
        self.card_events.refresh_theme()
        self.card_threats.refresh_theme()
        self.card_critical.refresh_theme()
        self.card_ips.refresh_theme()
        self.card_behavioral.refresh_theme()

        # Re-populate table rows so badges and colors reflect new tokens
        self._populate_stream_table()
