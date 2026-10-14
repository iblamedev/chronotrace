"""Floating toast notifications.

Toasts should inform without interrupting. They stack bottom-right, slide and
fade in, hold long enough to be read, then leave. Hovering pauses the timer so
an analyst can finish reading a long snippet.

Severity hierarchy is carried by a thin leading rail plus a small tinted badge,
so a CRITICAL toast is unmistakable while a routine INFO confirmation stays
visually quiet.

Exports
-------
* :class:`Toast` — a single notification card
* :class:`ToastHost` — the stacking container; owns positioning and lifecycle
* :func:`info` / :func:`success` / :func:`warning` / :func:`error` — convenience
"""

from __future__ import annotations

from PySide6.QtCore import QEasingCurve, QPropertyAnimation, Qt, QTimer, Signal
from PySide6.QtGui import QRegion
from PySide6.QtWidgets import (
    QFrame,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from app.ui.theme import (
    MOTION,
    RADIUS,
    SPACE,
    TOKENS,
    severity_color,
)

__all__ = ["Toast", "ToastHost", "error", "info", "success", "warning"]

#: Severity token used for non-threat system messages.
_TONE_TOKENS = {
    "info": "accent",
    "success": "success",
    "warning": "warning",
    "error": "danger",
    "critical": "severity_critical",
    "high": "severity_high",
    "medium": "severity_medium",
    "low": "severity_low",
}

_GLYPHS = {
    "info": "i",
    "success": "✓",
    "warning": "!",
    "error": "×",
}


def _tone_color(severity: str) -> str:
    key = str(severity).strip().lower()
    token = _TONE_TOKENS.get(key)
    return TOKENS[token] if token else severity_color(key)


class Toast(QFrame):
    """A single floating notification card."""

    dismissed = Signal(object)  # emits self

    def __init__(
        self,
        title: str,
        message: str = "",
        severity: str = "info",
        parent: QWidget | None = None,
        duration_ms: int = 6000,
        meta: str = "",
        action_label: str = "",
    ):
        super().__init__(parent)
        self.setProperty("role", "toast")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)

        self._severity = severity
        self._duration_ms = duration_ms
        self._tone = _tone_color(severity)

        self.setFixedWidth(340)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Minimum)

        outer = QHBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # Leading severity rail — the fastest visual cue.
        self._rail = _ToastRail(self._tone, self)
        outer.addWidget(self._rail)

        body = QVBoxLayout()
        body.setContentsMargins(SPACE["md"], SPACE["md"], SPACE["sm"], SPACE["md"])
        body.setSpacing(SPACE["xs"])

        # --- title row ------------------------------------------------------
        title_row = QHBoxLayout()
        title_row.setSpacing(SPACE["sm"])

        label = QLabel(title, self)
        label.setProperty("role", "subheading")
        label.setWordWrap(True)
        title_row.addWidget(label, 1)

        close = QPushButton("×", self)
        close.setProperty("appearance", "icon")
        close.setFixedSize(20, 20)
        close.setCursor(Qt.CursorShape.PointingHandCursor)
        close.setToolTip("Dismiss")
        close.clicked.connect(self.dismiss)
        title_row.addWidget(close, 0, Qt.AlignmentFlag.AlignTop)

        body.addLayout(title_row)

        # --- message --------------------------------------------------------
        if message:
            self._message = QLabel(message, self)
            self._message.setProperty("role", "secondary")
            self._message.setWordWrap(True)
            body.addWidget(self._message)

        # --- meta + action --------------------------------------------------
        if meta or action_label:
            footer = QHBoxLayout()
            footer.setSpacing(SPACE["sm"])
            if meta:
                meta_label = QLabel(meta, self)
                meta_label.setProperty("role", "micro")
                footer.addWidget(meta_label, 1)
            if action_label:
                action = QPushButton(action_label, self)
                action.setProperty("appearance", "ghost")
                action.setCursor(Qt.CursorShape.PointingHandCursor)
                action.clicked.connect(self.dismiss)
                footer.addWidget(action, 0)
            body.addLayout(footer)

        outer.addLayout(body, 1)

        # --- auto-dismiss ---------------------------------------------------
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self.dismiss)
        if duration_ms > 0:
            self._timer.start(duration_ms)

    # -- lifecycle ----------------------------------------------------------
    def enterEvent(self, event) -> None:
        """Pause dismissal while the pointer is over the toast."""
        self._timer.stop()
        super().enterEvent(event)

    def leaveEvent(self, event) -> None:
        if self._duration_ms > 0:
            self._timer.start(min(self._duration_ms, 3500))
        super().leaveEvent(event)

    def dismiss(self) -> None:
        """Animate out, then emit :attr:`dismissed`."""
        self._timer.stop()
        effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(effect)
        anim = QPropertyAnimation(effect, b"opacity", self)
        anim.setDuration(MOTION["fast"])
        anim.setStartValue(1.0)
        anim.setEndValue(0.0)
        anim.setEasingCurve(QEasingCurve.Type.InCubic)
        anim.finished.connect(lambda: self.dismissed.emit(self))
        anim.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)

    def refresh_theme(self) -> None:
        """Re-resolve the severity rail after a theme switch."""
        self._tone = _tone_color(self._severity)
        self._rail.set_color(self._tone)
        self._rail.update()


class _ToastRail(QFrame):
    """Thin coloured rail on the leading edge of a toast."""

    def __init__(self, color: str, parent: QWidget | None = None, width: int = 3):
        super().__init__(parent)
        self._color = color
        self.setFixedWidth(width)
        self.setStyleSheet(
            f"QFrame {{ background-color: {color}; border: none;"
            f" border-top-left-radius: {RADIUS['lg']}px;"
            f" border-bottom-left-radius: {RADIUS['lg']}px; }}"
        )

    def set_color(self, color: str) -> None:
        self._color = color
        self.setStyleSheet(
            f"QFrame {{ background-color: {color}; border: none;"
            f" border-top-left-radius: {RADIUS['lg']}px;"
            f" border-bottom-left-radius: {RADIUS['lg']}px; }}"
        )


class ToastHost(QWidget):
    """Overlay that stacks :class:`Toast` cards in the bottom-right corner.

    Install one host per window and parent it to the central widget; it
    repositions itself on resize and never steals focus.
    """

    MAX_VISIBLE = 4
    MARGIN = 22
    GAP = 10
    _instance: ToastHost | None = None

    @classmethod
    def instance(cls) -> ToastHost:
        """Return the global active toast host, or create a dummy fallback if none yet."""
        if cls._instance is not None:
            return cls._instance
        # Fallback dummy host if called before main window attaches
        dummy = cls(None)
        cls._instance = dummy
        return dummy

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        ToastHost._instance = self
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, False)
        self.setAttribute(Qt.WidgetAttribute.WA_NoSystemBackground, True)
        self.setStyleSheet("background: transparent;")
        self._toasts: list[Toast] = []
        self.hide()
        if parent is not None:
            parent.installEventFilter(self)

    def show_toast(
        self,
        *args,
        title: str = "",
        message: str = "",
        severity: str = "info",
        duration_ms: int = 6000,
        meta: str = "",
        action_label: str = "",
    ) -> Toast:
        """Create, stack, and animate in a new toast.

        Supports:
          - show_toast("Message text", title="Toast Title", severity="info")
          - show_toast("Toast Title", "Message text", severity="info")
          - show_toast(title="Toast Title", message="Message text")
        """
        if len(args) == 1:
            # If title is provided as kwarg, the positional arg is the message body
            if title:
                message = args[0]
            else:
                title = args[0]
        elif len(args) >= 2:
            title = args[0]
            message = args[1]

        toast = Toast(
            title=title,
            message=message,
            severity=severity,
            parent=self,
            duration_ms=duration_ms,
            meta=meta,
            action_label=action_label,
        )
        toast.dismissed.connect(self._remove)

        # Newest sits closest to the corner; drop the oldest if over capacity.
        self._toasts.insert(0, toast)
        while len(self._toasts) > self.MAX_VISIBLE:
            stale = self._toasts.pop()
            stale.hide()
            stale.deleteLater()

        self.show()
        self.raise_()
        toast.show()
        self._relayout()

        # Entry: fade in, then slide up into place by animating on relayout.
        effect = QGraphicsOpacityEffect(toast)
        toast.setGraphicsEffect(effect)
        anim = QPropertyAnimation(effect, b"opacity", toast)
        anim.setDuration(MOTION["slow"])
        anim.setStartValue(0.0)
        anim.setEndValue(1.0)
        anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        anim.finished.connect(lambda: toast.setGraphicsEffect(None))
        anim.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)

        return toast

    def clear(self) -> None:
        """Remove every toast immediately."""
        for toast in list(self._toasts):
            toast.hide()
            toast.deleteLater()
        self._toasts.clear()
        self.hide()

    def refresh_theme(self) -> None:
        for toast in self._toasts:
            toast.refresh_theme()

    # -- internals ----------------------------------------------------------
    def _remove(self, toast: Toast) -> None:
        if toast in self._toasts:
            self._toasts.remove(toast)
        toast.hide()
        toast.deleteLater()
        self._relayout()
        if not self._toasts:
            self.hide()

    def _relayout(self) -> None:
        """Place toasts bottom-up, newest nearest the corner."""
        if self.parentWidget() is None:
            return
        host_rect = self.parentWidget().rect()
        self.setGeometry(host_rect)

        y = host_rect.height() - self.MARGIN
        for toast in self._toasts:
            toast.adjustSize()
            height = toast.sizeHint().height()
            y -= height
            x = host_rect.width() - self.MARGIN - toast.width()
            toast.move(max(self.MARGIN, x), max(self.MARGIN, y))
            y -= self.GAP
            toast.raise_()

        self._update_mask()

    def _update_mask(self) -> None:
        """Restrict mouse-event hit testing strictly to active toast cards."""
        if not self._toasts:
            self.clearMask()
            return
        region = QRegion()
        for toast in self._toasts:
            if toast.isVisible():
                region = region.united(QRegion(toast.geometry()))
        self.setMask(region)

    def eventFilter(self, obj, event) -> bool:
        if event.type() in (
            event.Type.Resize,
            event.Type.Show,
        ):
            self._relayout()
        return super().eventFilter(obj, event)


# ---------------------------------------------------------------------------
# Convenience wrappers
# ---------------------------------------------------------------------------


def info(host: ToastHost, title: str, message: str = "", **kwargs) -> Toast:
    return host.show_toast(title, message, severity="info", **kwargs)


def success(host: ToastHost, title: str, message: str = "", **kwargs) -> Toast:
    return host.show_toast(title, message, severity="success", **kwargs)


def warning(host: ToastHost, title: str, message: str = "", **kwargs) -> Toast:
    return host.show_toast(title, message, severity="warning", **kwargs)


def error(host: ToastHost, title: str, message: str = "", **kwargs) -> Toast:
    return host.show_toast(title, message, severity="error", **kwargs)


#: Legacy name — the previous implementation was a standalone widget. It now
#: maps onto :class:`Toast` so existing call sites keep working, though new code
#: should go through :class:`ToastHost` for stacking and positioning.
ToastNotification = Toast
