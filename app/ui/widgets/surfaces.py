"""Layered surface primitives shared by every view.

ThreatDesk's cards are *quiet*: a hairline border, one step of surface
elevation, and on hover a barely-there lift in luminosity plus a fine border
brightening. No scaling, no drop-shadow boom, no rounded-blob decoration.

Widgets
-------
* :class:`Surface` — the base layered panel (``primary`` / ``inset`` / ``flush``)
* :class:`HoverSurface` — adds a very restrained cursor-following highlight
* :class:`Card` — ``Surface`` plus optional title/subtitle header block
* :class:`SectionHeader` — the standard in-panel section title + caption
* :class:`Divider` — hairline separator
* :class:`EmptyState` — designed empty states (never a blank rectangle)
* :class:`SkeletonBlock` — loading placeholder bar
"""

from __future__ import annotations

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QPainter, QRadialGradient
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from app.ui.theme import GUTTER, RADIUS, SPACE, qcolor

__all__ = [
    "Card",
    "Divider",
    "EmptyState",
    "HoverSurface",
    "SectionHeader",
    "SkeletonBlock",
    "Surface",
]


class Surface(QFrame):
    """Layered panel driven entirely by the ``card`` QSS property.

    ``variant`` is one of ``primary`` (default raised content surface),
    ``inset`` (recessed sub-panel), ``flush`` (surface with no interior
    padding, for panels that host a table edge-to-edge) or ``plain``.
    """

    def __init__(
        self,
        parent: QWidget | None = None,
        variant: str = "primary",
        padding: int | None = None,
        spacing: int = SPACE["md"],
    ):
        super().__init__(parent)
        self.setProperty("card", variant)
        self._layout = QVBoxLayout(self)
        inset = padding if padding is not None else GUTTER["card"]
        self._layout.setContentsMargins(inset, inset, inset, inset)
        self._layout.setSpacing(spacing)

    def body(self) -> QVBoxLayout:
        """Access the panel's vertical layout."""
        return self._layout

    def add_widget(self, widget: QWidget, stretch: int = 0) -> QWidget:
        self._layout.addWidget(widget, stretch)
        return widget


class HoverSurface(Surface):
    """Surface with a whisper-quiet cursor-aware highlight.

    The highlight is a large, very low-opacity radial gradient that tracks the
    pointer across the card. It is intentionally subtle — it should read as
    the surface catching the light, not as a spotlight. Opacity stays under
    6% and the gradient is only painted while the pointer is inside.
    """

    def __init__(
        self,
        parent: QWidget | None = None,
        variant: str = "primary",
        padding: int | None = None,
        spacing: int = SPACE["md"],
        highlight_alpha: float = 0.055,
        highlight_radius: int = 260,
    ):
        super().__init__(parent, variant=variant, padding=padding, spacing=spacing)
        self._highlight_alpha = highlight_alpha
        self._highlight_radius = highlight_radius
        self._cursor: QPointF | None = None
        self.setAttribute(Qt.WidgetAttribute.WA_Hover, True)
        self.setMouseTracking(True)

    # -- pointer tracking ---------------------------------------------------
    def enterEvent(self, event) -> None:
        self._cursor = self.mapFromGlobal(self.cursor().pos())
        self._cursor = QPointF(self._cursor)
        self.update()
        super().enterEvent(event)

    def leaveEvent(self, event) -> None:
        self._cursor = None
        self.update()
        super().leaveEvent(event)

    def mouseMoveEvent(self, event) -> None:
        self._cursor = QPointF(event.position())
        self.update()
        super().mouseMoveEvent(event)

    # -- paint --------------------------------------------------------------
    def paintEvent(self, event) -> None:
        super().paintEvent(event)
        if self._cursor is None:
            return

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        center = self._cursor
        radius = float(self._highlight_radius)
        gradient = QRadialGradient(center, radius)
        inner = qcolor("accent")
        inner.setAlphaF(self._highlight_alpha)
        middle = qcolor("accent")
        middle.setAlphaF(self._highlight_alpha * 0.35)
        outer = qcolor("accent")
        outer.setAlphaF(0.0)
        gradient.setColorAt(0.0, inner)
        gradient.setColorAt(0.55, middle)
        gradient.setColorAt(1.0, outer)

        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(gradient)

        # Clip to the card's rounded geometry so the glow respects the border.
        path_rect = QRectF(self.rect()).adjusted(1.0, 1.0, -1.0, -1.0)
        radius_px = float(RADIUS["lg"])
        painter.drawRoundedRect(path_rect, radius_px, radius_px)
        painter.end()


class Card(Surface):
    """Content card with an optional title/subtitle header block."""

    def __init__(
        self,
        title: str = "",
        subtitle: str = "",
        parent: QWidget | None = None,
        variant: str = "primary",
        padding: int | None = None,
        hover: bool = False,
        trailing: QWidget | None = None,
    ):
        basis = HoverSurface if hover else Surface
        super().__init__(parent, variant=variant, padding=padding)

        if basis is HoverSurface:
            self.__class__ = HoverSurface  # type: ignore[assignment]
            HoverSurface.__init__(
                self, parent=parent, variant=variant, padding=padding
            )

        if title:
            header = QWidget(self)
            header.setProperty("card", "plain")
            row = QHBoxLayout(header)
            row.setContentsMargins(0, 0, 0, 0)
            row.setSpacing(SPACE["md"])

            text_col = QVBoxLayout()
            text_col.setSpacing(SPACE["xxs"])

            self.title_label = QLabel(title, header)
            self.title_label.setProperty("role", "subheading")
            text_col.addWidget(self.title_label)

            self.subtitle_label = QLabel(subtitle, header)
            self.subtitle_label.setProperty("role", "caption")
            self.subtitle_label.setWordWrap(True)
            self.subtitle_label.setVisible(bool(subtitle))
            text_col.addWidget(self.subtitle_label)

            row.addLayout(text_col, 1)
            if trailing is not None:
                row.addWidget(trailing, 0, Qt.AlignmentFlag.AlignTop)
            self.body().addWidget(header)

    def set_subtitle(self, text: str) -> None:
        if hasattr(self, "subtitle_label"):
            self.subtitle_label.setText(text)
            self.subtitle_label.setVisible(bool(text))


class SectionHeader(QWidget):
    """In-panel section title with an optional caption and trailing slot."""

    def __init__(
        self,
        title: str,
        caption: str = "",
        parent: QWidget | None = None,
        trailing: QWidget | None = None,
    ):
        super().__init__(parent)
        self.setProperty("card", "plain")

        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(SPACE["md"])

        col = QVBoxLayout()
        col.setSpacing(SPACE["xxs"])

        self.title_label = QLabel(title, self)
        self.title_label.setProperty("role", "subheading")
        col.addWidget(self.title_label)

        self.caption_label = QLabel(caption, self)
        self.caption_label.setProperty("role", "caption")
        self.caption_label.setWordWrap(True)
        self.caption_label.setVisible(bool(caption))
        col.addWidget(self.caption_label)

        row.addLayout(col, 1)
        if trailing is not None:
            row.addWidget(trailing, 0, Qt.AlignmentFlag.AlignVCenter)

    def set_caption(self, text: str) -> None:
        self.caption_label.setText(text)
        self.caption_label.setVisible(bool(text))

    def add_action(self, widget: QWidget) -> None:
        self.layout().addWidget(widget, 0, Qt.AlignmentFlag.AlignVCenter)


class Divider(QFrame):
    """Hairline horizontal separator that follows the active theme."""

    def __init__(self, parent: QWidget | None = None, vertical: bool = False):
        super().__init__(parent)
        if vertical:
            self.setFixedWidth(1)
            self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Expanding)
        else:
            self.setFixedHeight(1)
            self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setProperty("divider", "true")


class EmptyState(QWidget):
    """Designed empty state: a title, an explanation, and an optional action."""

    def __init__(
        self,
        title: str,
        body: str = "",
        parent: QWidget | None = None,
        action: QWidget | None = None,
        icon_text: str = "",
    ):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(SPACE["xxl"], SPACE["xxl"], SPACE["xxl"], SPACE["xxl"])
        layout.setSpacing(SPACE["sm"])
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        if icon_text:
            glyph = QLabel(icon_text, self)
            glyph.setAlignment(Qt.AlignmentFlag.AlignCenter)
            glyph.setStyleSheet("font-size: 22px;")
            layout.addWidget(glyph)

        self.title_label = QLabel(title, self)
        self.title_label.setProperty("role", "empty-title")
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.title_label)

        self.body_label = QLabel(body, self)
        self.body_label.setProperty("role", "empty-body")
        self.body_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.body_label.setWordWrap(True)
        self.body_label.setMaximumWidth(420)
        self.body_label.setVisible(bool(body))
        layout.addWidget(self.body_label)

        if action is not None:
            layout.addSpacing(SPACE["sm"])
            layout.addWidget(action, 0, Qt.AlignmentFlag.AlignCenter)


class SkeletonBlock(QFrame):
    """Placeholder block used while a view loads."""

    def __init__(
        self,
        parent: QWidget | None = None,
        width: int = 0,
        height: int = 14,
        radius: int = RADIUS["sm"],
    ):
        super().__init__(parent)
        self.setProperty("role", "skeleton")
        if width:
            self.setFixedWidth(width)
        self.setMinimumHeight(height)
        self.setStyleSheet(
            f"QFrame {{ border-radius: {radius}px; }}"
        )
