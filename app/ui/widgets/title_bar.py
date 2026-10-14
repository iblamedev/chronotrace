"""Sleek, glassy modern top edge title bar for ThreatDesk.

Features:
- Glassy, translucent surface with subtle hairline gradient border.
- Crisp app brand mark (high-DPI circular emblem).
- Editorial typography matching ThreatDesk design system.
- Status chip / mode badge (e.g. "AIR-GAPPED · PROD").
- Custom vector window control buttons (Minimize, Maximize/Restore, Close)
  with polished pill hover states instead of generic Windows chrome.
- Native window interaction: double-click to maximize/restore, drag to move.
"""

from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import (
    QBrush,
    QColor,
    QMouseEvent,
    QPainter,
    QPen,
    QPixmap,
)
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QWidget,
)

from app.ui.theme import (
    RADIUS,
    SPACE,
    TOKENS,
    is_dark,
)

if sys.platform == "win32":
    import ctypes
    user32 = ctypes.windll.user32
else:
    user32 = None


class TitleBarButton(QPushButton):
    """Refined vector-drawn window button with smooth pill hover effects."""

    def __init__(self, kind: str = "close", parent: QWidget | None = None):
        super().__init__(parent)
        self.kind = kind
        self.setFixedSize(36, 28)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setStyleSheet("border: none; background: transparent;")

    def set_kind(self, kind: str) -> None:
        if self.kind != kind:
            self.kind = kind
            self.update()

    def paintEvent(self, event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        r = self.rect()
        hovered = self.underMouse()
        pressed = self.isDown()
        dark = is_dark()

        if hovered or pressed:
            if self.kind == "close":
                bg = QColor(225, 60, 60, 245 if pressed else 210)
                fg = QColor(255, 255, 255)
            else:
                alpha = 36 if pressed else 22
                bg_rgb = 255 if dark else 20
                bg = QColor(bg_rgb, bg_rgb, bg_rgb, alpha)
                fg = QColor(TOKENS["text_primary"])
            p.setBrush(QBrush(bg))
            p.setPen(Qt.PenStyle.NoPen)
            p.drawRoundedRect(r.adjusted(3, 2, -3, -2), 6, 6)
        else:
            fg = QColor(TOKENS["text_tertiary"])

        p.setPen(
            QPen(
                fg,
                1.3,
                Qt.PenStyle.SolidLine,
                Qt.PenCapStyle.RoundCap,
                Qt.PenJoinStyle.RoundJoin,
            )
        )
        cx, cy = r.width() / 2.0, r.height() / 2.0

        if self.kind == "min":
            p.drawLine(cx - 5.0, cy, cx + 5.0, cy)
        elif self.kind == "max":
            p.drawRoundedRect(cx - 4.5, cy - 4.5, 9.0, 9.0, 1.5, 1.5)
        elif self.kind == "restore":
            p.drawRoundedRect(cx - 3.5, cy - 1.5, 7.0, 7.0, 1.5, 1.5)
            p.drawLine(cx - 1.5, cy - 1.5, cx - 1.5, cy - 3.5)
            p.drawLine(cx - 1.5, cy - 3.5, cx + 5.5, cy - 3.5)
            p.drawLine(cx + 5.5, cy - 3.5, cx + 5.5, cy + 3.5)
            p.drawLine(cx + 5.5, cy + 3.5, cx + 3.5, cy + 3.5)
        elif self.kind == "close":
            d = 4.0
            p.drawLine(cx - d, cy - d, cx + d, cy + d)
            p.drawLine(cx - d, cy + d, cx + d, cy - d)

        p.end()


class ModernTitleBar(QFrame):
    """Ultra-modern glassy top bar with integrated brand identity and custom controls."""

    minimize_requested = Signal()
    maximize_requested = Signal()
    close_requested = Signal()

    HEIGHT = 40

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("ModernTitleBar")
        self.setFixedHeight(self.HEIGHT)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 0, 10, 0)
        layout.setSpacing(SPACE["sm"])

        # 1. Circular Brand Icon
        self.icon_lbl = QLabel(self)
        self.icon_lbl.setFixedSize(22, 22)
        self.icon_lbl.setStyleSheet("background: transparent; border: none;")
        self._load_logo()
        layout.addWidget(self.icon_lbl)

        # 2. Title & Workstation Tag
        self.title_lbl = QLabel("ChronoTrace", self)
        self.title_lbl.setStyleSheet(
            f"font-weight: 600; font-size: 12.5px; color: {TOKENS['text_primary']}; letter-spacing: 0.2px;"
        )
        layout.addWidget(self.title_lbl)

        self.divider_lbl = QLabel("—", self)
        self.divider_lbl.setStyleSheet(f"color: {TOKENS['text_muted']}; font-size: 11px;")
        layout.addWidget(self.divider_lbl)

        self.sub_lbl = QLabel("Log-Based Threat Detection System", self)
        self.sub_lbl.setStyleSheet(
            f"font-size: 11.5px; color: {TOKENS['text_tertiary']}; font-weight: 400;"
        )
        layout.addWidget(self.sub_lbl)

        layout.addSpacing(SPACE["xs"])

        # 3. Glassy Status Badge
        self.badge = QLabel("AIR-GAPPED", self)
        self.badge.setFixedHeight(20)
        self.badge.setStyleSheet(
            f"QLabel {{ background-color: {TOKENS['accent_soft']};"
            f" color: {TOKENS['accent']}; border: 1px solid {TOKENS['accent_border']};"
            f" border-radius: {RADIUS['pill']}px; padding: 0 8px;"
            f" font-size: 9.5px; font-weight: 600; letter-spacing: 0.6px; }}"
        )
        layout.addWidget(self.badge)

        layout.addStretch(1)

        # 4. Custom Window Control Buttons
        self.btn_min = TitleBarButton("min", self)
        self.btn_min.setToolTip("Minimize")
        self.btn_min.clicked.connect(self.minimize_requested.emit)
        layout.addWidget(self.btn_min)

        self.btn_max = TitleBarButton("max", self)
        self.btn_max.setToolTip("Maximize / Restore")
        self.btn_max.clicked.connect(self.maximize_requested.emit)
        layout.addWidget(self.btn_max)

        self.btn_close = TitleBarButton("close", self)
        self.btn_close.setToolTip("Close ChronoTrace")
        self.btn_close.clicked.connect(self.close_requested.emit)
        layout.addWidget(self.btn_close)

        self._refresh_styles()

    def _load_logo(self) -> None:
        logo_path = Path(__file__).resolve().parents[2] / "assets" / "logo.png"
        if logo_path.exists():
            pm = QPixmap(str(logo_path)).scaled(
                44, 44, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation
            )
            pm.setDevicePixelRatio(2.0)
            self.icon_lbl.setPixmap(pm)

    def set_maximized_state(self, is_max: bool) -> None:
        """Update the maximize/restore button icon according to window state."""
        self.btn_max.set_kind("restore" if is_max else "max")

    def _refresh_styles(self) -> None:
        dark = is_dark()
        if dark:
            # Glossy graphite edge with translucent hairline glow
            bg = "rgba(11, 13, 17, 0.95)"
            border_bottom = "rgba(255, 255, 255, 0.07)"
        else:
            # Clean paper frosted glass edge
            bg = "rgba(247, 246, 243, 0.96)"
            border_bottom = "rgba(24, 22, 19, 0.08)"

        self.setStyleSheet(
            f"ModernTitleBar {{ background-color: {bg}; border-bottom: 1px solid {border_bottom}; }}"
        )
        self.title_lbl.setStyleSheet(
            f"font-weight: 600; font-size: 12.5px; color: {TOKENS['text_primary']}; letter-spacing: 0.2px;"
        )
        self.divider_lbl.setStyleSheet(f"color: {TOKENS['text_muted']}; font-size: 11px;")
        self.sub_lbl.setStyleSheet(
            f"font-size: 11.5px; color: {TOKENS['text_tertiary']}; font-weight: 400;"
        )
        self.badge.setStyleSheet(
            f"QLabel {{ background-color: {TOKENS['accent_soft']};"
            f" color: {TOKENS['accent']}; border: 1px solid {TOKENS['accent_border']};"
            f" border-radius: {RADIUS['pill']}px; padding: 0 8px;"
            f" font-size: 9.5px; font-weight: 600; letter-spacing: 0.6px; }}"
        )
        self.btn_min.update()
        self.btn_max.update()
        self.btn_close.update()

    def refresh_theme(self) -> None:
        self._load_logo()
        self._refresh_styles()

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            win = self.window()
            if win is not None:
                # Check if click is on one of the action buttons
                child = self.childAt(event.position().toPoint())
                if child in (self.btn_min, self.btn_max, self.btn_close):
                    super().mousePressEvent(event)
                    return
                # Native Windows window drag
                if sys.platform == "win32" and user32:
                    user32.ReleaseCapture()
                    user32.SendMessageW(int(win.winId()), 0x00A1, 2, 0)
                    event.accept()
                    return
        super().mousePressEvent(event)

    def mouseDoubleClickEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            child = self.childAt(event.position().toPoint())
            if child in (self.btn_min, self.btn_max, self.btn_close):
                return
            self.maximize_requested.emit()
            event.accept()
            return
        super().mouseDoubleClickEvent(event)

