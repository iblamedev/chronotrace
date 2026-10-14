"""Severity and detection-method indicators.

Threat severity is carried by a small, deliberately typeset badge plus an
optional thin accent rail — never by flooding the interface with colour.

Visual language
---------------
* :class:`SeverityBadge` — uppercase label in the severity hue over a very
  faint tint of the same hue, with a hairline border at the same family. The
  *word* does the heavy lifting; colour reinforces it. Reads identically in
  both themes because it always derives from the active severity token.
* :class:`MethodChip` — distinguishes single-line **signature** detection from
  multi-event **behavioral** correlation (accent vs violet), which is a
  first-class concept in ThreatDesk and is called out throughout the docs,
  database schema and PDF reports.
* :class:`SeverityRail` — a 3px accent rail for table rows and inspector
  headers. This is how a critical detection becomes obvious in a dense table
  without turning the whole interface red.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QWidget

from app.models.rule import DetectionMethod, Severity
from app.ui.theme import TOKENS, method_color, severity_color, with_alpha

__all__ = ["MethodChip", "SeverityBadge", "SeverityDot", "SeverityRail"]

#: Human-facing labels. Short, unambiguous, and stable across themes.
_SEVERITY_LABELS = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
}

_METHOD_LABELS = {
    "signature": "Signature",
    "behavioral": "Behavioral",
}


def _severity_key(severity: str | Severity) -> str:
    return (
        severity.value
        if isinstance(severity, Severity)
        else str(severity).strip().lower()
    )


def _method_key(method: str | DetectionMethod | None) -> str:
    if isinstance(method, DetectionMethod):
        return method.value
    return str(method).strip().lower() if method else "signature"


class SeverityBadge(QLabel):
    """Compact severity pill: ``CRITICAL`` / ``HIGH`` / ``MEDIUM`` / ``LOW`` / ``INFO``."""

    def __init__(
        self,
        severity: str | Severity = "info",
        method: str | DetectionMethod | None = None,
        parent: QWidget | None = None,
        show_method: bool = False,
    ):
        super().__init__(parent)
        self.setProperty("badge", "true")
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._show_method = show_method
        self.set_severity(severity, method)

    def set_severity(
        self,
        severity: str | Severity,
        method: str | DetectionMethod | None = None,
    ) -> None:
        """Re-render the badge for a new severity (and optionally method)."""
        key = _severity_key(severity)
        color = severity_color(key)
        label = _SEVERITY_LABELS.get(key, key.upper())

        if self._show_method and method is not None:
            mark = "S" if _method_key(method) == "signature" else "B"
            label = f"{mark} · {label}"

        self.setText(label)
        self.setStyleSheet(
            f"""
            QLabel {{
                background-color: {with_alpha(color, 0.14)};
                color: {color};
                border: 1px solid {with_alpha(color, 0.34)};
                border-radius: 6px;
                padding: 3px 9px;
                font-size: 10px;
                font-weight: 600;
                letter-spacing: 0.09px;
            }}
            """
        )
        self.setToolTip(f"Severity: {label}")


class MethodChip(QFrame):
    """Detection-method indicator: Signature (accent) vs Behavioral (violet)."""

    def __init__(
        self,
        method: str | DetectionMethod | None = "signature",
        parent: QWidget | None = None,
        compact: bool = False,
    ):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self._compact = compact

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        self._dot = SeverityRail(color_token="accent", height=13, width=2, parent=self)
        layout.addWidget(self._dot)

        self._label = QLabel()
        layout.addWidget(self._label)

        self.set_method(method)

    def set_method(self, method: str | DetectionMethod | None) -> None:
        """Re-render the chip for a new detection method."""
        key = _method_key(method)
        color = method_color(key)
        text = _METHOD_LABELS.get(key, key.title())

        self._dot.set_color_token("violet" if key == "behavioral" else "accent")
        self._label.setText(text if not self._compact else text[0])
        self._label.setStyleSheet(
            f"color: {color}; font-size: 11px; font-weight: 600; letter-spacing: 0.02px;"
        )
        self._label.setToolTip(
            "Behavioral correlation across multiple events"
            if key == "behavioral"
            else "Single-line signature match"
        )


class SeverityRail(QFrame):
    """Thin vertical accent rail — marks a row or panel with its severity.

    Used as the leftmost element of a table row and at 3px wide in the event
    inspector header. Deliberately tiny: it should register peripherally.
    """

    def __init__(
        self,
        severity: str | Severity | None = None,
        color_token: str = "accent",
        height: int = 18,
        width: int = 3,
        parent: QWidget | None = None,
        radius: int = 2,
    ):
        super().__init__(parent)
        self._width = width
        self._radius = radius
        self._color_token = color_token
        self.setFixedWidth(width)
        if height > 0:
            self.setFixedHeight(height)
        if severity is not None:
            self.set_severity(severity)

    def set_color_token(self, color_token: str) -> None:
        self._color_token = color_token
        self._apply()

    def set_severity(self, severity: str | Severity) -> None:
        """Colour the rail by severity name."""
        self._color_token = None  # resolved from the severity below
        self._severity = severity
        self._apply()

    def _apply(self) -> None:
        if self._color_token is None:
            color = severity_color(_severity_key(getattr(self, "_severity", "info")))
        else:
            color = TOKENS.get(self._color_token, self._color_token)

        # Rails sit on both dark and light surfaces, so use a solid tint.
        self.setStyleSheet(
            f"""
            QFrame {{
                background-color: {color};
                border: none;
                border-radius: {self._radius}px;
            }}
            """
        )
        self.setFixedWidth(self._width)


class SeverityDot(QFrame):
    """Small filled dot used where a full badge would be too heavy."""

    def __init__(
        self,
        severity: str | Severity = "info",
        diameter: int = 7,
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        self._diameter = diameter
        self.setFixedSize(diameter, diameter)
        self.set_severity(severity)

    def set_severity(self, severity: str | Severity) -> None:
        key = _severity_key(severity)
        color = severity_color(key)
        self.setStyleSheet(
            f"QFrame {{ background-color: {color}; border: none;"
            f" border-radius: {self._diameter // 2}px; }}"
        )
        self.setToolTip(key.upper())
