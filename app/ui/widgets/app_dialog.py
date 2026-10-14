"""Premium dialog chrome shared by every modal surface.

Nothing in ThreatDesk should look like a stock OS widget. :class:`AppDialog`
supplies one coherent frame — a tinted severity rail, a title block with
eyebrow/meta line, a scrollable body, and a right-aligned footer action row —
so the Event Inspector, IOC editor, rule editor, and watchlist dialogs all feel
like parts of the same design system.

Exports
-------
* :class:`AppDialog` — the base dialog
* :class:`FieldRow` — a labelled key/value row for detail panes
* :class:`Section` — a titled block inside a dialog body
"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from app.ui.theme import (
    GUTTER,
    SPACE,
    TOKENS,
    severity_color,
)
from app.ui.widgets.surfaces import Divider

__all__ = ["AppDialog", "FieldRow", "Section"]


class Section(QFrame):
    """A titled block inside a dialog body.

    ``tone`` optionally tints the eyebrow label (``accent``, ``violet``,
    ``success``, ``warning``, ``danger``) to signal the block's role.
    """

    def __init__(
        self,
        title: str,
        caption: str = "",
        parent: QWidget | None = None,
        tone: str = "",
        variant: str = "primary",
    ):
        super().__init__(parent)
        self.setProperty("card", variant)

        layout = QVBoxLayout(self)
        padding = GUTTER["card"] if variant == "primary" else GUTTER["card_tight"]
        layout.setContentsMargins(padding, padding, padding, padding)
        layout.setSpacing(SPACE["sm"])

        head = QWidget(self)
        head.setProperty("card", "plain")
        head_col = QVBoxLayout(head)
        head_col.setContentsMargins(0, 0, 0, 0)
        head_col.setSpacing(SPACE["xxs"])

        eyebrow = QLabel(title.upper(), head)
        eyebrow.setProperty("role", "label")
        if tone:
            color = TOKENS.get(tone, tone)
            eyebrow.setStyleSheet(f"color: {color};")
        head_col.addWidget(eyebrow)

        if caption:
            caption_label = QLabel(caption, head)
            caption_label.setProperty("role", "caption")
            caption_label.setWordWrap(True)
            head_col.addWidget(caption_label)

        layout.addWidget(head)

        self._body = QVBoxLayout()
        self._body.setContentsMargins(0, 0, 0, 0)
        self._body.setSpacing(SPACE["sm"])
        layout.addLayout(self._body)

    def body(self) -> QVBoxLayout:
        return self._body

    def add(self, widget: QWidget, stretch: int = 0) -> QWidget:
        self._body.addWidget(widget, stretch)
        return widget


class FieldRow(QWidget):
    """A labelled key/value row — the backbone of every detail pane.

    Values are selectable so an analyst can copy an IP, hash, or raw payload
    straight out of the inspector.
    """

    def __init__(
        self,
        label: str,
        value: Any = "",
        parent: QWidget | None = None,
        mono: bool = False,
        label_width: int = 150,
        tone: str = "",
        selectable: bool = True,
    ):
        super().__init__(parent)
        self.setProperty("card", "plain")

        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(SPACE["md"])

        self._label = QLabel(label, self)
        self._label.setProperty("role", "caption")
        self._label.setFixedWidth(label_width)
        self._label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        row.addWidget(self._label)

        self._value = QLabel("" if value is None else str(value), self)
        self._value.setProperty("role", "mono" if mono else "body")
        if not mono:
            self._value.setStyleSheet(f"color: {TOKENS['text_primary']};")
        if tone:
            self._value.setStyleSheet(f"color: {TOKENS.get(tone, tone)};")
        self._value.setWordWrap(True)
        if selectable:
            self._value.setTextInteractionFlags(
                Qt.TextInteractionFlag.TextSelectableByMouse
            )
        row.addWidget(self._value, 1)

    def set_value(self, value: Any) -> None:
        self._value.setText("" if value is None else str(value))


class AppDialog(QDialog):
    """Base class for every modal in ThreatDesk.

    Subclasses fill :meth:`body_layout` and optionally ::`footer_layout`;
    the chrome, spacing, severity rail, and scroll behaviour are handled here so
    no individual dialog has to reinvent them.
    """

    def __init__(
        self,
        title: str = "",
        parent: QWidget | None = None,
        eyebrow: str = "",
        meta: str = "",
        severity: str | None = None,
        width: int = 880,
        height: int = 660,
        scrollable: bool = True,
    ):
        super().__init__(parent)
        self.setWindowTitle(f"ThreatDesk — {title}" if title else "ThreatDesk")
        self.setMinimumSize(width, height)
        self.setModal(True)

        root = QVBoxLayout(self)
        margins = GUTTER["view"]
        root.setContentsMargins(
            margins, GUTTER["view_top"], margins, GUTTER["view_bottom"]
        )
        root.setSpacing(SPACE["lg"])

        # --- header ---------------------------------------------------------
        header = QWidget(self)
        header.setProperty("card", "plain")
        header_row = QHBoxLayout(header)
        header_row.setContentsMargins(0, 0, 0, 0)
        header_row.setSpacing(SPACE["md"])

        if severity:
            rail = QFrame(header)
            rail.setFixedWidth(3)
            rail.setMinimumHeight(38)
            color = severity_color(severity)
            rail.setStyleSheet(
                f"QFrame {{ background-color: {color}; border: none;"
                f" border-radius: 2px; }}"
            )
            header_row.addWidget(rail, 0, Qt.AlignmentFlag.AlignTop)

        text_col = QVBoxLayout()
        text_col.setContentsMargins(0, 0, 0, 0)
        text_col.setSpacing(SPACE["xxs"])

        if eyebrow:
            self._eyebrow = QLabel(eyebrow.upper(), header)
            self._eyebrow.setProperty("role", "label")
            text_col.addWidget(self._eyebrow)

        self.title_label = QLabel(title, header)
        self.title_label.setProperty("role", "title")
        self.title_label.setWordWrap(True)
        text_col.addWidget(self.title_label)

        if meta:
            self.meta_label = QLabel(meta, header)
            self.meta_label.setProperty("role", "secondary")
            self.meta_label.setWordWrap(True)
            text_col.addWidget(self.meta_label)

        header_row.addLayout(text_col, 1)

        self._header_trailing = QHBoxLayout()
        self._header_trailing.setSpacing(SPACE["sm"])
        header_row.addLayout(self._header_trailing, 0)
        root.addWidget(header)

        root.addWidget(Divider(self))

        # --- body -----------------------------------------------------------
        self._body_container = QWidget(self)
        self._body_container.setProperty("card", "plain")
        self._body_layout = QVBoxLayout(self._body_container)
        self._body_layout.setContentsMargins(0, 0, 0, 0)
        self._body_layout.setSpacing(SPACE["lg"])

        if scrollable:
            scroll = QScrollArea(self)
            scroll.setWidgetResizable(True)
            scroll.setFrameShape(QFrame.Shape.NoFrame)
            scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
            scroll.setWidget(self._body_container)
            root.addWidget(scroll, 1)
        else:
            root.addWidget(self._body_container, 1)

        # --- footer ---------------------------------------------------------
        self._footer_row = QHBoxLayout()
        self._footer_row.setContentsMargins(0, 0, 0, 0)
        self._footer_row.setSpacing(SPACE["sm"])
        root.addLayout(self._footer_row)

    # -- extension points ---------------------------------------------------
    def body_layout(self) -> QVBoxLayout:
        """The scrollable body layout subclasses populate."""
        return self._body_layout

    def footer_layout(self) -> QHBoxLayout:
        """The footer layout; add buttons here (a stretch is auto-prepended)."""
        return self._footer_row

    def add_header_widget(self, widget: QWidget, stretch: int = 0) -> QWidget:
        self._header_trailing.addWidget(widget, stretch)
        return widget

    def add_footer_action(self, widget: QWidget) -> QWidget:
        """Append an action to the right-aligned footer."""
        if self._footer_row.count() == 0:
            self._footer_row.addStretch(1)
        self._footer_row.addWidget(widget)
        return widget

    def set_meta(self, text: str) -> None:
        if hasattr(self, "meta_label"):
            self.meta_label.setText(text)
