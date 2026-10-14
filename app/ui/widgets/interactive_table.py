"""The security-analysis workspace table.

This is not a spreadsheet. It should read like a professional analyst console:
a fixed header that stays put while rows scroll, generous row rhythm with
compact-but-legible type, intelligent truncation, a hairline row separator, a
severity rail that makes a critical row findable at a glance, and a selection
state that eases rather than snaps.

Exports
-------
* :class:`AnalysisTable` — the table itself (drop-in replacement for the old
  ``InteractiveTable``)
* :class:`SeverityItem` — a ``QTableWidgetItem`` tinted by its severity
* :func:`mono_item` / :func:`text_item` — consistent cell construction
* :func:`empty_overlay` — placeholder shown when a table has no rows
"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import QPropertyAnimation, Qt, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QHeaderView,
    QStackedLayout,
    QTableWidget,
    QTableWidgetItem,
    QWidget,
)

from app.ui.theme import (
    RADIUS,
    SPACE,
    TOKENS,
    severity_color,
    status_color,
)
from app.ui.widgets.surfaces import EmptyState

__all__ = [
    "AnalysisTable",
    "SeverityItem",
    "TableCard",
    "empty_overlay",
    "mono_item",
    "text_item",
]

#: Standard row height — generous enough to breathe, compact enough to scan.
ROW_HEIGHT = 40
HEADER_HEIGHT = 36


class AnalysisTable(QTableWidget):
    """Dense, legible, hover-responsive table with a fixed header."""

    row_activated = Signal(int)  # emitted on double-click / Enter

    def __init__(
        self,
        rows: int = 0,
        columns: int = 0,
        parent: QWidget | None = None,
        severity_column: int | None = 0,
        stretch_column: int | None = None,
        row_height: int = ROW_HEIGHT,
    ):
        super().__init__(rows, columns, parent)

        self._severity_column = severity_column
        self._row_height = row_height

        # --- structure -----------------------------------------------------
        self.setShowGrid(False)
        self.setAlternatingRowColors(False)
        self.setWordWrap(False)
        self.setTextElideMode(Qt.TextElideMode.ElideRight)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.setCornerButtonEnabled(False)

        # --- fixed, sticky header ------------------------------------------
        v_header = self.verticalHeader()
        v_header.setVisible(False)
        v_header.setDefaultSectionSize(row_height)
        v_header.setSectionResizeMode(QHeaderView.ResizeMode.Fixed)

        h_header = self.horizontalHeader()
        h_header.setHighlightSections(False)
        h_header.setFixedHeight(HEADER_HEIGHT)
        h_header.setStretchLastSection(stretch_column is None)
        h_header.setDefaultAlignment(
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
        )
        h_header.setSectionsMovable(False)

        if stretch_column is not None:
            h_header.setSectionResizeMode(
                stretch_column, QHeaderView.ResizeMode.Stretch
            )

        # --- selection easing ----------------------------------------------
        self._selection_anim: QPropertyAnimation | None = None
        self.itemDoubleClicked.connect(self._emit_activated)

        self._apply_palette()

    # -- theming ------------------------------------------------------------
    def _apply_palette(self) -> None:
        """Refresh only the bits QSS cannot express (header/cell palette)."""
        header = self.horizontalHeader()
        palette = header.palette()
        base = QColor(TOKENS["surface"])
        palette.setColor(palette.ColorRole.Base, base)
        palette.setColor(palette.ColorRole.Text, QColor(TOKENS["text_tertiary"]))
        header.setPalette(palette)

        font = QFont(self.font())
        font.setPointSizeF(max(9.0, font.pointSizeF() - 1.0))
        font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 0.6)
        font.setWeight(QFont.Weight.DemiBold)
        header.setFont(font)

    def refresh_theme(self) -> None:
        """Called after a theme switch to re-tint header + rows."""
        self._apply_palette()
        if self._severity_column is not None:
            self.apply_severity_rails()
        self.viewport().update()

    # -- row construction helpers -------------------------------------------
    def prepare_row(self, row: int) -> None:
        """Apply shared row geometry to a freshly created row."""
        self.setRowHeight(row, self._row_height)

    def add_row(self, cells: list[QTableWidgetItem | QWidget | None]) -> int:
        """Append a row of items/widgets and return its index."""
        row = self.rowCount()
        self.insertRow(row)
        self.prepare_row(row)
        for column, cell in enumerate(cells):
            if cell is None:
                continue
            if isinstance(cell, QWidget):
                wrapper = _CellHost(cell, self)
                self.setCellWidget(row, column, wrapper)
            else:
                self.setItem(row, column, cell)
        return row

    def apply_severity_rails(self, colors: list[str] | None = None) -> None:
        """Tint the severity column's text per row.

        Where a severity *badge* widget already occupies the column, the badge
        owns the colour; this handles the plain-text case.
        """
        if self._severity_column is None:
            return
        for row in range(self.rowCount()):
            item = self.item(row, self._severity_column)
            if item is None:
                continue
            if colors is not None and row < len(colors):
                color = colors[row]
            else:
                color = severity_color(item.text())
            item.setForeground(QColor(color))

    def selected_row(self) -> int:
        """Return the selected row index, or ``-1`` when nothing is selected."""
        rows = self.selectionModel().selectedRows() if self.selectionModel() else []
        return rows[0].row() if rows else self.currentRow()

    # -- interaction --------------------------------------------------------
    def _emit_activated(self, item: QTableWidgetItem) -> None:
        self.row_activated.emit(item.row())

    def keyPressEvent(self, event) -> None:
        if event.key() in (Qt.Key_Return, Qt.Key_Enter):
            row = self.selected_row()
            if row >= 0:
                self.row_activated.emit(row)
                return
        super().keyPressEvent(event)


class _CellHost(QWidget):
    """Centres a widget in a cell with consistent padding."""

    def __init__(self, inner: QWidget, parent: QWidget | None = None):
        super().__init__(parent)
        from PySide6.QtWidgets import QHBoxLayout

        layout = QHBoxLayout(self)
        layout.setContentsMargins(SPACE["md"], SPACE["xs"], SPACE["md"], SPACE["xs"])
        layout.setSpacing(0)
        layout.addWidget(inner)
        layout.addStretch(0)


# ---------------------------------------------------------------------------
# Cell factories
# ---------------------------------------------------------------------------


def text_item(
    text: Any,
    color_token: str | None = None,
    tooltip: str | None = None,
) -> QTableWidgetItem:
    """Standard body cell, optionally tinted by a token name."""
    item = QTableWidgetItem("" if text is None else str(text))
    if color_token:
        item.setForeground(QColor(TOKENS.get(color_token, color_token)))
    if tooltip:
        item.setToolTip(tooltip)
    elif text is not None and len(str(text)) > 40:
        item.setToolTip(str(text))
    return item


def mono_item(text: Any, color_token: str = "text_secondary") -> QTableWidgetItem:
    """Monospace cell for IPs, hashes, timestamps, and raw snippets."""
    item = text_item(text, color_token=color_token)
    font = QFont("monospace")
    font.setStyleHint(QFont.StyleHint.Monospace)
    font.setPointSizeF(9.5)
    item.setFont(font)
    return item


class SeverityItem(QTableWidgetItem):
    """Cell whose text is tinted by its severity, with a matching left rail."""

    def __init__(self, severity: str, text: str | None = None):
        super().__init__((text or severity).upper())
        self._severity = str(severity).lower()
        self.setForeground(QColor(severity_color(self._severity)))
        font = QFont()
        font.setWeight(QFont.Weight.DemiBold)
        font.setPointSizeF(9.0)
        self.setFont(font)

    @property
    def severity(self) -> str:
        return self._severity


def status_item(status: str) -> QTableWidgetItem:
    """Cell tinted by alert disposition status."""
    item = QTableWidgetItem(str(status).upper())
    item.setForeground(QColor(status_color(status)))
    font = QFont()
    font.setWeight(QFont.Weight.DemiBold)
    font.setPointSizeF(9.5)
    item.setFont(font)
    return item


def empty_overlay(
    host: QTableWidget,
    title: str,
    body: str = "",
    action: QWidget | None = None,
) -> tuple[QWidget, QStackedLayout]:
    """Wrap ``host`` in a stack that can show a designed empty state.

    Returns ``(container, stack)``; switch with
    ``stack.setCurrentIndex(0 if rows else 1)``.
    """
    container = QWidget(host.parentWidget())
    stack = QStackedLayout(container)
    stack.setContentsMargins(0, 0, 0, 0)
    stack.addWidget(host)
    stack.addWidget(EmptyState(title, body, container, action=action))
    return container, stack


#: Legacy name kept so existing imports keep working.
InteractiveTable = AnalysisTable



class TableCard(QFrame):
    """A card that hosts a table flush to its edges.

    Header text sits above; the table bleeds to the card's bottom corners so it
    reads as one integrated surface rather than a table pasted into a box.
    """

    def __init__(
        self,
        title: str = "",
        caption: str = "",
        parent: QWidget | None = None,
        trailing: QWidget | None = None,
    ):
        super().__init__(parent)
        self.setProperty("card", "flush")

        from PySide6.QtWidgets import QHBoxLayout, QVBoxLayout

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        if title:
            header = QWidget(self)
            header.setStyleSheet("background-color: transparent;")
            row = QHBoxLayout(header)
            row.setContentsMargins(18, 14, 18, 12)
            row.setSpacing(SPACE["md"])

            from app.ui.widgets.surfaces import SectionHeader

            row.addWidget(SectionHeader(title, caption, header), 1)
            if trailing is not None:
                row.addWidget(trailing, 0, Qt.AlignmentFlag.AlignVCenter)

            layout.addWidget(header)

            rule = QFrame(self)
            rule.setFixedHeight(1)
            rule.setStyleSheet(
                f"QFrame {{ background-color: {TOKENS['border_subtle']}; border: none; }}"
            )
            layout.addWidget(rule)

        self._body = layout

    def body(self):
        return self._body

    def attach_table(self, table: AnalysisTable) -> AnalysisTable:
        """Add ``table`` flush to the card, stripping its outer border."""
        self._table = table
        table.setStyleSheet(
            f"""
            QTableWidget {{
                border: none;
                border-top-left-radius: 0px;
                border-top-right-radius: 0px;
                border-bottom-left-radius: {RADIUS["lg"]}px;
                border-bottom-right-radius: {RADIUS["lg"]}px;
            }}
            """
        )
        self._body.addWidget(table, 1)
        return table

    def set_empty_state(self, title: str, body: str = "", action: QWidget | None = None) -> None:
        """Add or update an integrated EmptyState overlay for this card."""
        from app.ui.widgets.surfaces import EmptyState

        if not hasattr(self, "_empty_widget"):
            self._empty_widget = EmptyState(title, body, self, action=action)
            self._body.addWidget(self._empty_widget, 1)
        else:
            self._empty_widget.title_label.setText(title)
            self._empty_widget.body_label.setText(body)

        has_rows = bool(hasattr(self, "_table") and self._table.rowCount() > 0)
        self._empty_widget.setVisible(not has_rows)
        if hasattr(self, "_table"):
            self._table.setVisible(has_rows)

    def refresh_empty_state(self) -> None:
        """Toggle visibility between table and empty state depending on row count."""
        if hasattr(self, "_empty_widget") and hasattr(self, "_table"):
            has_rows = self._table.rowCount() > 0
            self._empty_widget.setVisible(not has_rows)
            self._table.setVisible(has_rows)
