"""Minimal, elegant vertical sidebar navigation.

Not a bulky dashboard menu: a refined rail of nav items with a single animated
active-state indicator that *slides* between destinations, plus a quiet
workstation-status block and the theme switch.
"""

from __future__ import annotations

from collections.abc import Sequence

from PySide6.QtCore import (
    QEasingCurve,
    QPoint,
    QPropertyAnimation,
    QRect,
    Qt,
    Signal,
)
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from app.ui.theme import (
    MOTION,
    RADIUS,
    SPACE,
    TOKENS,
    repolish,
    theme_list,
)
from app.ui.widgets.animated_button import SegmentedControl

__all__ = ["Sidebar"]

#: Vertical geometry of the nav rail.
NAV_ITEM_HEIGHT = 38
NAV_ITEM_GAP = 2
NAV_SECTION_GAP = 14
INDICATOR_WIDTH = 3


class _NavButton(QPushButton):
    """A single navigation destination."""

    def __init__(
        self,
        label: str,
        index: int,
        parent: QWidget | None = None,
        glyph: str = "",
    ):
        super().__init__(label, parent)
        self.setObjectName("NavItem")
        self.index = index
        self.glyph = glyph
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(NAV_ITEM_HEIGHT)
        self.setProperty("active", "false")
        self._render()

    def _render(self) -> None:
        text = f"{self.glyph}   {super().text()}" if self.glyph else super().text()
        QPushButton.setText(self, text)

    def set_active(self, active: bool) -> None:
        self.setProperty("active", "true" if active else "false")
        repolish(self)


class Sidebar(QFrame):
    """The application's primary navigation rail."""

    page_requested = Signal(int)
    theme_change_requested = Signal(str)
    command_palette_requested = Signal()

    WIDTH = 236

    def __init__(
        self,
        nav_items: Sequence[tuple[str, int]],
        parent: QWidget | None = None,
        current_theme: str = "graphite",
        logo_pixmap=None,
    ):
        super().__init__(parent)
        self.setObjectName("Sidebar")
        self.setFixedWidth(self.WIDTH)

        self._buttons: list[_NavButton] = []
        self._current_index = 0
        self._indicator_anim: QPropertyAnimation | None = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(SPACE["md"], SPACE["lg"], SPACE["md"], SPACE["md"])
        layout.setSpacing(0)

        layout.addWidget(self._build_brand(logo_pixmap))
        layout.addSpacing(SPACE["lg"])

        # --- nav list -------------------------------------------------------
        self._nav_host = QWidget(self)
        self._nav_host.setObjectName("SidebarSection")
        nav_layout = QVBoxLayout(self._nav_host)
        nav_layout.setContentsMargins(0, 0, 0, 0)
        nav_layout.setSpacing(NAV_ITEM_GAP)

        for label, index in nav_items:
            button = _NavButton(label, index, self._nav_host)
            button.clicked.connect(lambda _=False, i=index: self._on_nav_clicked(i))
            nav_layout.addWidget(button)
            self._buttons.append(button)

        layout.addWidget(self._nav_host)

        # --- sliding active indicator --------------------------------------
        # Sits as a sibling overlaying the nav host's left gutter so it can be
        # positioned freely without affecting item layout.
        self._indicator = QFrame(self)
        self._indicator.setFixedWidth(INDICATOR_WIDTH)
        self._indicator.setStyleSheet(
            f"QFrame {{ background-color: {TOKENS['accent']}; border: none;"
            f" border-radius: {INDICATOR_WIDTH // 2}px; }}"
        )
        self._indicator.raise_()

        layout.addStretch(1)

        # --- search / command trigger ---------------------------------------
        self.search_button = QPushButton("Search commands", self)
        self.search_button.setProperty("appearance", "default")
        self.search_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.search_button.setFixedHeight(34)
        self.search_button.setStyleSheet(
            f"QPushButton {{ color: {TOKENS['text_muted']}; text-align: left;"
            f" padding-left: 12px; font-size: 12px; }}"
        )
        self.search_button.clicked.connect(self.command_palette_requested.emit)
        self.search_button.setToolTip("Open the command palette (Ctrl+K)")
        layout.addWidget(self.search_button)
        layout.addSpacing(SPACE["md"])

        # --- theme switch ---------------------------------------------------
        theme_row = QWidget(self)
        theme_row.setObjectName("SidebarSection")
        theme_layout = QVBoxLayout(theme_row)
        theme_layout.setContentsMargins(0, 0, 0, 0)
        theme_layout.setSpacing(SPACE["xs"])

        label = QLabel("APPEARANCE", theme_row)
        label.setProperty("role", "label")
        theme_layout.addWidget(label)

        # Labels are the short theme names only ("Graphite" / "Paper").
        options = [(key, label.split(" -")[0]) for key, label in theme_list()]
        self.theme_switch = SegmentedControl(options, theme_row, current=current_theme)
        self.theme_switch.changed.connect(self.theme_change_requested.emit)
        theme_layout.addWidget(self.theme_switch)

        layout.addWidget(theme_row)
        layout.addSpacing(SPACE["md"])

        layout.addWidget(self._build_footer())

    # -- construction helpers ----------------------------------------------
    def _build_brand(self, logo_pixmap) -> QWidget:
        brand = QWidget(self)
        brand.setObjectName("SidebarHeader")
        row = QHBoxLayout(brand)
        row.setContentsMargins(SPACE["xs"], 0, 0, 0)
        row.setSpacing(SPACE["sm"])

        mark = QLabel(brand)
        mark.setFixedSize(30, 30)
        mark.setStyleSheet("background-color: transparent; border: none;")
        if logo_pixmap is not None and not logo_pixmap.isNull():
            mark.setPixmap(logo_pixmap)
        else:
            # Styled wordmark fallback — no ASCII bracket glyphs.
            mark.setText("T")
            mark.setAlignment(Qt.AlignmentFlag.AlignCenter)
            mark.setStyleSheet(
                f"QLabel {{ background-color: {TOKENS['accent_muted']};"
                f" color: {TOKENS['accent']}; border: 1px solid {TOKENS['accent_border']};"
                f" border-radius: {RADIUS['md']}px; font-size: 15px; font-weight: 700; }}"
            )
        row.addWidget(mark)

        text_col = QVBoxLayout()
        text_col.setContentsMargins(0, 0, 0, 0)
        text_col.setSpacing(0)

        name = QLabel("ChronoTrace", brand)
        name.setProperty("role", "subheading")
        text_col.addWidget(name)

        tagline = QLabel("SOC Analysis Workstation", brand)
        tagline.setProperty("role", "caption")
        text_col.addWidget(tagline)

        row.addLayout(text_col, 1)
        return brand

    def _build_footer(self) -> QWidget:
        footer = QFrame(self)
        footer.setObjectName("SidebarFooter")

        layout = QVBoxLayout(footer)
        layout.setContentsMargins(SPACE["md"], SPACE["sm"], SPACE["md"], SPACE["sm"])
        layout.setSpacing(SPACE["xxs"])

        label = QLabel("WORKSTATION", footer)
        label.setProperty("role", "label")
        layout.addWidget(label)

        status_row = QHBoxLayout()
        status_row.setSpacing(SPACE["xs"])

        dot = QFrame(footer)
        dot.setFixedSize(6, 6)
        dot.setStyleSheet(
            f"QFrame {{ background-color: {TOKENS['success']}; border: none;"
            " border-radius: 3px; }"
        )
        status_row.addWidget(dot)

        status = QLabel("Air-gapped / offline", footer)
        status.setProperty("role", "micro")
        status.setStyleSheet(f"color: {TOKENS['success']};")
        status_row.addWidget(status, 1)

        layout.addLayout(status_row)
        return footer

    # -- behaviour ----------------------------------------------------------
    def _on_nav_clicked(self, index: int) -> None:
        self.page_requested.emit(index)

    def set_active(self, index: int, animate: bool = True) -> None:
        """Mark ``index`` active and slide the indicator to it."""
        self._current_index = index
        for button in self._buttons:
            button.set_active(button.index == index)
        self._move_indicator(animate=animate)

    def _target_indicator_geometry(self) -> QRect:
        button = next(
            (b for b in self._buttons if b.index == self._current_index),
            self._buttons[0] if self._buttons else None,
        )
        if button is None:
            return QRect(0, 0, INDICATOR_WIDTH, 0)

        # Position the rail just inside the sidebar's left gutter.
        top_left = button.mapTo(self, QPoint(0, 0))
        inset = 4
        return QRect(
            top_left.x() - inset,
            top_left.y() + inset,
            INDICATOR_WIDTH,
            button.height() - inset * 2,
        )

    def _move_indicator(self, animate: bool = True) -> None:
        target = self._target_indicator_geometry()

        if not animate or self._indicator_anim is not None:
            if self._indicator_anim is not None:
                self._indicator_anim.stop()
                self._indicator_anim = None
            self._indicator.setGeometry(target)
            self._indicator.raise_()
            return

        start = self._indicator.geometry()
        anim = QPropertyAnimation(self._indicator, b"geometry", self)
        anim.setDuration(MOTION["base"])
        anim.setStartValue(start)
        anim.setEndValue(target)
        anim.setEasingCurve(QEasingCurve.Type.OutCubic)

        def _clear() -> None:
            self._indicator_anim = None

        anim.finished.connect(_clear)
        self._indicator_anim = anim
        anim.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._move_indicator(animate=False)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._move_indicator(animate=False)

    def refresh_theme(self, current_theme: str) -> None:
        """Re-resolve tokens baked into inline stylesheets."""
        self._indicator.setStyleSheet(
            f"QFrame {{ background-color: {TOKENS['accent']}; border: none;"
            f" border-radius: {INDICATOR_WIDTH // 2}px; }}"
        )
        self.search_button.setStyleSheet(
            f"QPushButton {{ color: {TOKENS['text_muted']}; text-align: left;"
            f" padding-left: 12px; font-size: 12px; }}"
        )
        self.theme_switch.set_current(current_theme)
