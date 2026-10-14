"""Large, elegant metric cards with animated counters and trend indicators.

A metric card reads top-to-bottom: what it measures (label), how much (big
tabular figure), how it is moving (trend), and what it means (footnote). The
counting animation runs once on update rather than continuously, so a dashboard
full of cards settles into stillness.

Exports
-------
* :class:`MetricCard` — the KPI card
* :class:`MetricRow` — convenience row builder for a set of metrics
* :class:`TrendIndicator` — the small up/down/flat delta chip
* :class:`Sparkline` — a minimal inline trend line drawn from token colours
"""

from __future__ import annotations

from collections.abc import Sequence

from PySide6.QtCore import QPointF, Qt
from PySide6.QtGui import QColor, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import QHBoxLayout, QLabel, QWidget

from app.ui.animations import animate_counter
from app.ui.theme import (
    RADIUS,
    SPACE,
    TOKENS,
    with_alpha,
)
from app.ui.widgets.surfaces import HoverSurface

__all__ = ["MetricCard", "MetricRow", "Sparkline", "TrendIndicator"]


class TrendIndicator(QLabel):
    """Small directional delta chip: rising, falling, or flat."""

    def __init__(
        self,
        delta: float | None = None,
        parent: QWidget | None = None,
        higher_is_better: bool = True,
        suffix: str = "%",
    ):
        super().__init__(parent)
        self.setProperty("badge", "true")
        self._higher_is_better = higher_is_better
        self._suffix = suffix
        self.set_trend(delta)

    def set_trend(self, delta: float | None) -> None:
        """Render the delta; ``None`` hides the chip entirely."""
        if delta is None:
            self.setText("")
            self.setVisible(False)
            return

        self.setVisible(True)
        if abs(delta) < 0.05:
            glyph, color = "–", TOKENS["text_muted"]
            text = "flat"
        elif delta > 0:
            glyph = "▲"
            color = (
                TOKENS["success"] if self._higher_is_better else TOKENS["danger"]
            )
            text = f"{delta:.1f}{self._suffix}"
        else:
            glyph = "▼"
            color = (
                TOKENS["danger"] if self._higher_is_better else TOKENS["success"]
            )
            text = f"{abs(delta):.1f}{self._suffix}"

        self.setText(f"{glyph}  {text}")
        self.setStyleSheet(
            f"""
            QLabel {{
                color: {color};
                background-color: {with_alpha(color, 0.12)};
                border: 1px solid {with_alpha(color, 0.28)};
                border-radius: {RADIUS["sm"]}px;
                padding: 2px 7px;
                font-size: 10px;
                font-weight: 600;
            }}
            """
        )


class Sparkline(QWidget):
    """Minimal inline trend line — no axes, no grid, just the shape."""

    def __init__(
        self,
        values: Sequence[float] | None = None,
        parent: QWidget | None = None,
        color_token: str = "accent",
        height: int = 26,
    ):
        super().__init__(parent)
        self._values: list[float] = list(values or [])
        self._color_token = color_token
        self.setFixedHeight(height)
        self.setMinimumWidth(60)

    def set_values(self, values: Sequence[float]) -> None:
        self._values = list(values)
        self.update()

    def set_color_token(self, token: str) -> None:
        self._color_token = token
        self.update()

    def paintEvent(self, event) -> None:
        if len(self._values) < 2:
            return

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        lo, hi = min(self._values), max(self._values)
        span = (hi - lo) or 1.0
        width = max(1, self.width() - 2)
        height = max(1, self.height() - 4)
        step = width / (len(self._values) - 1)

        points = [
            QPointF(
                1 + i * step,
                self.height() - 2 - ((value - lo) / span) * height,
            )
            for i, value in enumerate(self._values)
        ]

        # Soft filled area under the line, then the line itself.
        area = QPainterPath(QPointF(points[0].x(), self.height()))
        for point in points:
            area.lineTo(point)
        area.lineTo(points[-1].x(), self.height())
        area.closeSubpath()

        fill = QColor(TOKENS.get(self._color_token, self._color_token))
        fill.setAlphaF(0.10)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(fill)
        painter.drawPath(area)

        line = QColor(TOKENS.get(self._color_token, self._color_token))
        pen = QPen(line, 1.5)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        painter.setPen(pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPolyline(points)
        painter.end()


class MetricCard(HoverSurface):
    """A large KPI card: label, animated figure, trend, footnote, sparkline."""

    def __init__(
        self,
        title: str,
        initial_value: float = 0,
        subtitle: str = "",
        accent_token: str = "accent",
        parent: QWidget | None = None,
        decimals: int = 0,
        suffix: str = "",
        higher_is_better: bool = True,
        trend_suffix: str = "%",
    ):
        super().__init__(
            parent,
            variant="primary",
            padding=SPACE["lg"],
            spacing=SPACE["sm"],
            highlight_alpha=0.05,
            highlight_radius=220,
        )
        self.setObjectName("MetricCard")

        self._value = initial_value
        self._decimals = decimals
        self._suffix = suffix
        self._accent_token = accent_token
        self._anim = None

        # --- top row: label + trend chip ----------------------------------
        top = QWidget(self)
        top.setProperty("card", "plain")
        top_row = QHBoxLayout(top)
        top_row.setContentsMargins(0, 0, 0, 0)
        top_row.setSpacing(SPACE["sm"])

        self.title_label = QLabel(title.upper(), top)
        self.title_label.setProperty("role", "label")
        top_row.addWidget(self.title_label, 1)

        self.trend = TrendIndicator(
            None, top, higher_is_better=higher_is_better, suffix=trend_suffix
        )
        top_row.addWidget(self.trend, 0, Qt.AlignmentFlag.AlignRight)
        self.add_widget(top)

        # --- the figure ----------------------------------------------------
        self.val_label = QLabel(self)
        self.val_label.setProperty("role", "metric")
        self._set_label_text(initial_value)
        self.add_widget(self.val_label)

        # --- accent rail + footnote ---------------------------------------
        footer = QWidget(self)
        footer.setProperty("card", "plain")
        footer_row = QHBoxLayout(footer)
        footer_row.setContentsMargins(0, 0, 0, 0)
        footer_row.setSpacing(SPACE["sm"])

        self.sub_label = QLabel(subtitle, footer)
        self.sub_label.setProperty("role", "caption")
        self.sub_label.setWordWrap(True)
        footer_row.addWidget(self.sub_label, 1)

        self.add_widget(footer)

        # --- optional sparkline --------------------------------------------
        self.sparkline = Sparkline(parent=self, color_token=accent_token)
        self.sparkline.setVisible(False)
        self.add_widget(self.sparkline)

    # -- value --------------------------------------------------------------
    def _set_label_text(self, value: float) -> None:
        if self._decimals:
            text = f"{value:,.{self._decimals}f}"
        else:
            text = f"{round(value):,}"
        self.val_label.setText(f"{text}{self._suffix}")

    def set_value(self, new_value: float, animate: bool = True) -> None:
        """Animate the counter to ``new_value`` (skipped when not visible)."""
        if animate and self.isVisible() and new_value != self._value:
            self._anim = animate_counter(
                self.val_label,
                self._value,
                new_value,
                decimals=self._decimals,
                suffix=self._suffix,
            )
        else:
            self._set_label_text(new_value)
        self._value = new_value

    def set_trend(self, delta: float | None) -> None:
        self.trend.set_trend(delta)

    def set_subtitle(self, text: str) -> None:
        self.sub_label.setText(text)

    def set_sparkline(self, values: Sequence[float]) -> None:
        self.sparkline.set_values(values)
        self.sparkline.setVisible(len(values) > 1)

    def refresh_theme(self) -> None:
        """Re-resolve accent-derived children after a theme switch."""
        self.sparkline.set_color_token(self._accent_token)


def MetricRow(
    metrics: Sequence[MetricCard],
    parent: QWidget | None = None,
    spacing: int = SPACE["md"],
) -> QWidget:
    """Pack a sequence of metric cards into an evenly weighted row."""
    host = QWidget(parent)
    host.setProperty("card", "plain")
    layout = QHBoxLayout(host)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(spacing)
    for card in metrics:
        layout.addWidget(card, 1)
    return host
