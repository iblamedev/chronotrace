"""Command surface (Ctrl+K) — a keyboard-first way to move around ThreatDesk.

Modelled on the command palettes in Raycast and Linear: a single glass surface
holding a search field and a filtered, keyboard-navigable action list. It is one
of the few places in the product that uses real translucency, because an overlay
genuinely benefits from reading as a layer above the workspace.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from PySide6.QtCore import QEvent, Qt, Signal
from PySide6.QtGui import QKeyEvent
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from app.ui.theme import RADIUS, SPACE, TOKENS, repolish

__all__ = ["Command", "CommandPalette"]


@dataclass
class Command:
    """A single palette entry."""

    key: str
    label: str
    category: str = ""
    shortcut: str = ""
    description: str = ""
    handler: Callable[[], None] | None = None
    keywords: tuple[str, ...] = field(default_factory=tuple)

    def matches(self, query: str) -> bool:
        """Simple ranked-ish substring match across label, category, keywords."""
        if not query:
            return True
        needle = query.lower()
        haystack = " ".join(
            (self.label, self.category, self.description, *self.keywords)
        ).lower()
        return needle in haystack

    def sort_key(self, query: str) -> tuple[int, str]:
        """Prefix matches outrank interior matches; then alphabetical."""
        needle = query.lower()
        if needle and self.label.lower().startswith(needle):
            return (0, self.label.lower())
        return (1, self.label.lower())


class _CommandRow(QFrame):
    """One selectable row in the palette list."""

    activated = Signal(object)  # emits Command
    hovered = Signal(object)

    def __init__(self, command: Command, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("CommandRow")
        self.command = command
        self.setProperty("selected", "false")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)

        row = QHBoxLayout(self)
        row.setContentsMargins(SPACE["md"], SPACE["sm"], SPACE["md"], SPACE["sm"])
        row.setSpacing(SPACE["md"])

        text_col = QVBoxLayout()
        text_col.setContentsMargins(0, 0, 0, 0)
        text_col.setSpacing(0)

        self.label = QLabel(command.label, self)
        self.label.setProperty("role", "body")
        self.label.setStyleSheet(f"color: {TOKENS['text_primary']};")
        text_col.addWidget(self.label)

        if command.description:
            desc = QLabel(command.description, self)
            desc.setProperty("role", "caption")
            text_col.addWidget(desc)

        row.addLayout(text_col, 1)

        if command.category:
            category = QLabel(command.category.upper(), self)
            category.setProperty("role", "label")
            row.addWidget(category, 0, Qt.AlignmentFlag.AlignVCenter)

        if command.shortcut:
            shortcut = QLabel(command.shortcut, self)
            shortcut.setProperty("role", "micro")
            shortcut.setStyleSheet(
                f"color: {TOKENS['text_tertiary']};"
                f" border: 1px solid {TOKENS['border']};"
                f" border-radius: {RADIUS['xs']}px;"
                " padding: 1px 6px;"
            )
            row.addWidget(shortcut, 0, Qt.AlignmentFlag.AlignVCenter)

    def set_selected(self, selected: bool) -> None:
        self.setProperty("selected", "true" if selected else "false")
        repolish(self)
        self.label.setStyleSheet(
            f"color: {TOKENS['text_primary']};"
            + (" font-weight: 600;" if selected else "")
        )

    def mousePressEvent(self, event) -> None:
        self.activated.emit(self.command)

    def enterEvent(self, event) -> None:
        self.hovered.emit(self)


class CommandPalette(QWidget):
    """Full-window overlay hosting the command surface.

    Parent it to the window's central widget. Call :meth:`open` to show it;
    it closes on ``Esc``, on activation, or when the user clicks the scrim.
    """

    #: Emitted after a command handler runs, so the window can react.
    command_invoked = Signal(object)

    def __init__(self, parent: QWidget):
        super().__init__(parent)
        self._commands: list[Command] = []
        self._rows: list[_CommandRow] = []
        self._selected = 0

        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setStyleSheet(f"background-color: {TOKENS['overlay']};")
        self.hide()

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 96, 0, 0)
        outer.setSpacing(0)
        outer.setAlignment(Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop)

        self.surface = QFrame(self)
        self.surface.setObjectName("CommandSurface")
        self.surface.setFixedWidth(620)
        self.surface.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)

        surface_layout = QVBoxLayout(self.surface)
        surface_layout.setContentsMargins(0, 0, 0, 0)
        surface_layout.setSpacing(0)

        # --- search field ---------------------------------------------------
        field = QFrame(self.surface)
        field.setObjectName("CommandField")
        field_layout = QHBoxLayout(field)
        field_layout.setContentsMargins(
            SPACE["lg"], SPACE["md"], SPACE["lg"], SPACE["md"]
        )
        field_layout.setSpacing(SPACE["sm"])

        hint = QLabel("Search", field)
        hint.setProperty("role", "caption")
        field_layout.addWidget(hint)

        self.search = QLineEdit(field)
        self.search.setPlaceholderText("Jump to a view, run an action…")
        self.search.setFrame(False)
        self.search.setStyleSheet("background: transparent; border: none;")
        self.search.setStyleSheet(
            f"QLineEdit {{ background: transparent; border: none;"
            f" color: {TOKENS['text_primary']}; font-size: 14px; }}"
        )
        self.search.textChanged.connect(self._on_query_changed)
        field_layout.addWidget(self.search, 1)

        esc = QLabel("ESC", field)
        esc.setProperty("role", "micro")
        esc.setStyleSheet(
            f"color: {TOKENS['text_tertiary']}; border: 1px solid {TOKENS['border']};"
            f" border-radius: {RADIUS['xs']}px; padding: 1px 6px;"
        )
        field_layout.addWidget(esc)
        surface_layout.addWidget(field)

        # --- results --------------------------------------------------------
        self.results_host = QWidget(self.surface)
        self.results_host.setProperty("card", "plain")
        self.results_layout = QVBoxLayout(self.results_host)
        self.results_layout.setContentsMargins(
            SPACE["sm"], SPACE["sm"], SPACE["sm"], SPACE["sm"]
        )
        self.results_layout.setSpacing(2)

        scroll = QScrollArea(self.surface)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setMaximumHeight(360)
        scroll.setWidget(self.results_host)
        surface_layout.addWidget(scroll)

        self.empty_label = QLabel("No matching commands", self.surface)
        self.empty_label.setProperty("role", "caption")
        self.empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_label.setContentsMargins(0, SPACE["xl"], 0, SPACE["xl"])
        self.empty_label.hide()
        surface_layout.addWidget(self.empty_label)

        outer.addWidget(self.surface, 0, Qt.AlignmentFlag.AlignHCenter)

        if parent is not None:
            self.setGeometry(parent.rect())
            parent.installEventFilter(self)

    # -- registry -----------------------------------------------------------
    def set_commands(self, commands: Iterable[Command]) -> None:
        """Replace the command registry and rebuild the list."""
        self._commands = list(commands)
        self._rebuild()

    def add_command(self, command: Command) -> None:
        self._commands.append(command)
        self._rebuild()

    # -- lifecycle ----------------------------------------------------------
    def open_palette(self) -> None:
        """Show the palette with a fresh query and focus on the search field."""
        if self.parentWidget() is not None:
            self.setGeometry(self.parentWidget().rect())
        self.search.clear()
        self._rebuild()
        self.show()
        self.raise_()
        self.setFocus(Qt.FocusReason.ShortcutFocusReason)
        self.search.setFocus(Qt.FocusReason.ShortcutFocusReason)

    def open(self) -> None:
        """Alias for open_palette."""
        self.open_palette()

    def close_palette(self) -> None:
        self.hide()

    def refresh_theme(self) -> None:
        """Re-resolve tokens that were inlined into stylesheets."""
        self.setStyleSheet(f"background-color: {TOKENS['overlay']};")
        self.search.setStyleSheet("background: transparent; border: none;")
        self.search.setStyleSheet(
            f"QLineEdit {{ background: transparent; border: none;"
            f" color: {TOKENS['text_primary']}; font-size: 14px; }}"
        )
        for row in self._rows:
            row.set_selected(False)
        self._rebuild()

    # -- building & filtering ----------------------------------------------
    def _rebuild(self) -> None:
        while self.results_layout.count():
            item = self.results_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        self._rows.clear()

        query = self.search.text().strip()
        visible = [c for c in self._commands if c.matches(query)]
        visible.sort(key=lambda c: c.sort_key(query))

        if not visible:
            self.empty_label.show()
            self._selected = 0
            return
        self.empty_label.hide()

        for command in visible:
            row = _CommandRow(command, self.results_host)
            row.activated.connect(self._activate)
            row.hovered.connect(self._on_row_hovered)
            self.results_layout.addWidget(row)
            self._rows.append(row)

        self.results_layout.addStretch(1)
        self._selected = 0
        self._apply_selection()

    def _on_query_changed(self, _text: str) -> None:
        self._rebuild()

    def _on_row_hovered(self, command: Command) -> None:
        for index, row in enumerate(self._rows):
            if row.command is command:
                self._selected = index
                self._apply_selection()
                return

    def _apply_selection(self) -> None:
        for index, row in enumerate(self._rows):
            row.set_selected(index == self._selected)

    def _activate(self, command: Command) -> None:
        self.close_palette()
        if command.handler is not None:
            command.handler()
        self.command_invoked.emit(command)

    # -- events -------------------------------------------------------------
    def keyPressEvent(self, event: QKeyEvent) -> None:
        key = event.key()
        if key == Qt.Key_Escape:
            self.close_palette()
            return
        if key in (Qt.Key_Down, Qt.Key_Tab):
            if self._rows:
                self._selected = (self._selected + 1) % len(self._rows)
                self._apply_selection()
            return
        if key == Qt.Key_Up:
            if self._rows:
                self._selected = (self._selected - 1) % len(self._rows)
                self._apply_selection()
            return
        if key in (Qt.Key_Return, Qt.Key_Enter):
            if self._rows:
                self._activate(self._rows[self._selected].command)
            return
        super().keyPressEvent(event)

    def mousePressEvent(self, event) -> None:
        # Clicking the scrim (not the surface) dismisses the palette.
        if not self.surface.geometry().contains(event.position().toPoint()):
            self.close_palette()

    def eventFilter(self, obj, event) -> bool:
        if event.type() == QEvent.Type.Resize and self.parentWidget() is not None:
            self.setGeometry(self.parentWidget().rect())
        return super().eventFilter(obj, event)
