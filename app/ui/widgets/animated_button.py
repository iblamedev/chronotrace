"""Tactile buttons.

Buttons should feel like a physical surface: a smooth background
interpolation, a border that catches the light, a small icon nudge toward the
direction of travel, an unambiguous press, and an elegant disabled state.

Styling comes from the ``appearance`` QSS property (``primary`` / ``violet`` /
``ghost`` / ``danger`` / ``icon`` / ``chip`` / ``segment``) so both themes share
identical geometry. The Python layer adds motion the stylesheet cannot express.

Exports
-------
* :class:`TactileButton` — the standard button
* :class:`IconButton` — square, icon-only, used in toolbars and headers
* :class:`ChipButton` — pill filter toggle
* :class:`SegmentedControl` — two-or-more exclusive options (theme switch)
* :class:`GlowButton` — backwards-compatible alias for existing call sites
"""

from __future__ import annotations

from collections.abc import Sequence

from PySide6.QtCore import QPropertyAnimation, Qt, Signal
from PySide6.QtWidgets import QButtonGroup, QHBoxLayout, QPushButton, QWidget

from app.ui.theme import repolish

__all__ = [
    "ChipButton",
    "GlowButton",
    "IconButton",
    "SegmentedControl",
    "TactileButton",
    "apply_appearance",
]

#: Glyph nudge distance on hover, in pixels — small enough to be felt, not seen.
_ICON_NUDGE_PX = 2


def apply_appearance(button: QPushButton, appearance: str) -> None:
    """Set the ``appearance`` QSS property and restyle the button."""
    button.setProperty("appearance", appearance)
    repolish(button)


class TactileButton(QPushButton):
    """Standard button with restrained, tactile hover and press feedback."""

    def __init__(
        self,
        text: str = "",
        parent: QWidget | None = None,
        appearance: str = "default",
        icon_text: str = "",
        tooltip: str = "",
        icon_moves: bool = True,
    ):
        super().__init__(text, parent)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setAutoDefault(False)
        self.setDefault(False)

        self._icon_text = icon_text
        self._icon_moves = icon_moves and bool(icon_text)
        self._arrow = ""  # trailing glyph that slides on hover

        apply_appearance(self, appearance)
        self._render(text)

        if tooltip:
            self.setToolTip(tooltip)

        self._press_anim: QPropertyAnimation | None = None

    # -- label composition --------------------------------------------------
    def _render(self, text: str | None = None) -> None:
        if text is not None:
            self._text = text
        parts = []
        if self._icon_text:
            parts.append(self._icon_text)
        parts.append(self._text)
        if self._arrow and self.underMouse():
            parts.append(self._arrow)
        super().setText("  ".join(p for p in parts if p))

    def set_arrow(self, arrow: str) -> None:
        """Trailing glyph (e.g. ``"→"``) revealed on hover."""
        self._arrow = arrow

    def set_icon(self, icon_text: str) -> None:
        self._icon_text = icon_text
        self._render()

    # -- feedback -----------------------------------------------------------
    def enterEvent(self, event) -> None:
        self._render()
        super().enterEvent(event)

    def leaveEvent(self, event) -> None:
        self._render()
        super().leaveEvent(event)

    def mousePressEvent(self, event) -> None:
        super().mousePressEvent(event)


class IconButton(TactileButton):
    """Square icon-only button for toolbars, headers, and row actions."""

    def __init__(
        self,
        glyph: str = "",
        parent: QWidget | None = None,
        tooltip: str = "",
        size: int = 28,
    ):
        super().__init__(
            "", parent, appearance="icon", icon_text=glyph, tooltip=tooltip
        )
        self.setFixedSize(size, size)


class ChipButton(TactileButton):
    """Pill toggle used for dense filter rows."""

    def __init__(
        self,
        text: str,
        parent: QWidget | None = None,
        active: bool = False,
        tooltip: str = "",
    ):
        super().__init__(text, parent, appearance="chip", tooltip=tooltip)
        self.setCheckable(True)
        self.setChecked(active)
        self.set_active(active)
        self.toggled.connect(self.set_active)

    def set_active(self, active: bool) -> None:
        self.setProperty("active", "true" if active else "false")
        repolish(self)


class SegmentedControl(QWidget):
    """Exclusive segmented options — used for the theme switch.

    Emits :attr:`changed` with the selected value's data payload.
    """

    changed = Signal(str)

    def __init__(
        self,
        options: Sequence[tuple[str, str]],
        parent: QWidget | None = None,
        current: str | None = None,
    ):
        """``options`` is a sequence of ``(value, label)`` pairs."""
        super().__init__(parent)
        self.setProperty("card", "inset")

        layout = QHBoxLayout(self)
        layout.setContentsMargins(3, 3, 3, 3)
        layout.setSpacing(2)

        self._group = QButtonGroup(self)
        self._group.setExclusive(True)
        self._buttons: dict[str, TactileButton] = {}

        for value, label in options:
            btn = TactileButton(label, self, appearance="segment")
            btn.setCheckable(True)
            btn.setProperty("value", value)
            self._group.addButton(btn)
            self._buttons[value] = btn
            layout.addWidget(btn)
            btn.clicked.connect(lambda _=False, v=value: self._on_clicked(v))

        if current and current in self._buttons:
            self.set_current(current)
        elif self._buttons:
            self.set_current(next(iter(self._buttons)))

    def _on_clicked(self, value: str) -> None:
        self.set_current(value)
        self.changed.emit(value)

    def set_current(self, value: str) -> None:
        """Select ``value`` and refresh the active-state styling."""
        for key, btn in self._buttons.items():
            is_active = key == value
            btn.setChecked(is_active)
            btn.setProperty("active", "true" if is_active else "false")
            repolish(btn)
        self._current = value

    def current(self) -> str:
        return getattr(self, "_current", "")


#: Backwards-compatible alias — the previous implementation was called
#: ``GlowButton`` and its ``is_primary`` flag mapped directly onto appearance.
class GlowButton(TactileButton):
    def __init__(
        self,
        text: str = "",
        glow_color: str = "",
        is_primary: bool = False,
        parent: QWidget | None = None,
        **kwargs,
    ):
        del glow_color  # colour now comes from the token system, not a literal
        kwargs.pop("icon_moves", None)
        super().__init__(
            text,
            parent,
            appearance="primary" if is_primary else "default",
            **kwargs,
        )
