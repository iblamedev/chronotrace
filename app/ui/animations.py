"""Motion system for ThreatDesk — calm, deliberate, state-communicating.

Every helper here uses Qt's animation framework exclusively; nothing ever
blocks the GUI thread with ``time.sleep``.

Motion principles
-----------------
* Animation communicates **state or hierarchy** — never decoration.
* Durations come from :data:`app.ui.theme.MOTION` so the whole product shares
  one rhythm, and every curve is an ease-out family (things settle, they do
  not bounce).
* The only continuously-running animation is the live-monitor indicator, and it
  is explicitly stoppable.

Provided helpers
----------------
* :func:`animate_counter` — smooth tabular-figure numeric counting for KPIs
* :func:`fade_in` / :func:`fade_out` — opacity transitions that clean up after
  themselves (the opacity effect is removed on completion so text stays crisp)
* :func:`slide_fade_in` — the standard view/panel entrance (fade + small rise)
* :func:`staggered_entrance` — ambient, sequenced entrances for card rows
* :func:`cross_fade` — seamless theme / page swap without a jarring recolor
* :class:`PulseIndicator` — breathing live-status dot, start/stop capable
* :func:`animate_property` — low-level escape hatch for geometry/color motion
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence

from PySide6.QtCore import (
    Property,
    QEasingCurve,
    QObject,
    QParallelAnimationGroup,
    QPauseAnimation,
    QPropertyAnimation,
    QSequentialAnimationGroup,
    Qt,
)
from PySide6.QtWidgets import QGraphicsOpacityEffect, QLabel, QWidget

from app.ui.theme import MOTION, qcolor

__all__ = [
    "STAGGER_STEP_MS",
    "PulseIndicator",
    "animate_counter",
    "animate_property",
    "cross_fade",
    "fade_in",
    "fade_out",
    "slide_fade_in",
    "slide_fade_out",
    "staggered_entrance",
]

#: Delay between successive items in a staggered entrance.
STAGGER_STEP_MS = 45


# ---------------------------------------------------------------------------
# Numeric counters
# ---------------------------------------------------------------------------


class _CounterAnimator(QObject):
    """Animatable integer/float holder that writes formatted text to a label."""

    def __init__(self, label: QLabel, decimals: int = 0, suffix: str = ""):
        super().__init__(label)
        self._label = label
        self._decimals = max(0, int(decimals))
        self._suffix = suffix
        self._value = 0.0

    # -- Qt property plumbing ------------------------------------------------
    def _get_value(self) -> float:
        return self._value

    def _set_value(self, value: float) -> None:
        self._value = float(value)
        self._render()

    value = Property(float, _get_value, _set_value)

    def _render(self) -> None:
        if self._decimals:
            text = f"{self._value:,.{self._decimals}f}"
        else:
            text = f"{round(self._value):,}"
        self._label.setText(f"{text}{self._suffix}")

    def set_now(self, value: float) -> None:
        """Set the value and render immediately (no animation)."""
        self._set_value(value)


def animate_counter(
    label: QLabel,
    start: float,
    end: float,
    duration_ms: int | None = None,
    decimals: int = 0,
    suffix: str = "",
) -> QPropertyAnimation:
    """Count ``label`` smoothly from ``start`` to ``end``.

    Metrics use tabular figures (see the ``role="metric"`` QSS rule) so the
    digits do not jitter laterally while the number animates.
    """
    animator = _CounterAnimator(label, decimals=decimals, suffix=suffix)
    animator.set_now(start)

    anim = QPropertyAnimation(animator, b"value", label)
    anim.setDuration(duration_ms or int(MOTION["entrance"] * 2))
    anim.setStartValue(float(start))
    anim.setEndValue(float(end))
    anim.setEasingCurve(QEasingCurve.Type.OutCubic)
    anim.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)
    return anim


# ---------------------------------------------------------------------------
# Opacity transitions
# ---------------------------------------------------------------------------


def _ensure_opacity_effect(
    widget: QWidget, existing: QGraphicsOpacityEffect | None = None
) -> QGraphicsOpacityEffect:
    effect = existing or widget.graphicsEffect()
    if not isinstance(effect, QGraphicsOpacityEffect):
        effect = QGraphicsOpacityEffect(widget)
        widget.setGraphicsEffect(effect)
        effect.setOpacity(1.0)
    return effect


def fade_in(
    widget: QWidget,
    duration_ms: int | None = None,
    delay_ms: int = 0,
    on_finished: Callable[[], None] | None = None,
    cleanup: bool = True,
) -> QPropertyAnimation:
    """Fade ``widget`` in from transparent.

    When ``cleanup`` is true the opacity effect is removed on completion —
    leaving a ``QGraphicsOpacityEffect`` attached softens text and forces an
    off-screen render pass, which is exactly what we do not want for the
    long-lived views this is used on.
    """
    effect = _ensure_opacity_effect(widget)
    anim = QPropertyAnimation(effect, b"opacity", widget)
    anim.setDuration(duration_ms or MOTION["base"])
    anim.setStartValue(0.0)
    anim.setEndValue(1.0)
    anim.setEasingCurve(QEasingCurve.Type.OutCubic)

    def _done() -> None:
        if cleanup:
            widget.setGraphicsEffect(None)
        if on_finished:
            on_finished()

    anim.finished.connect(_done)
    if delay_ms > 0:
        group = QSequentialAnimationGroup(widget)
        group.addAnimation(QPauseAnimation(delay_ms, widget))
        group.addAnimation(anim)
        group.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)
        return anim
    anim.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)
    return anim


def fade_out(
    widget: QWidget,
    duration_ms: int | None = None,
    on_finished: Callable[[], None] | None = None,
) -> QPropertyAnimation:
    """Fade ``widget`` out to transparent, then optionally notify."""
    effect = _ensure_opacity_effect(widget)
    anim = QPropertyAnimation(effect, b"opacity", widget)
    anim.setDuration(duration_ms or MOTION["fast"])
    anim.setStartValue(effect.opacity())
    anim.setEndValue(0.0)
    anim.setEasingCurve(QEasingCurve.Type.InCubic)
    if on_finished:
        anim.finished.connect(on_finished)
    anim.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)
    return anim


# ---------------------------------------------------------------------------
# Entrances
# ---------------------------------------------------------------------------


class _PositionAnimator(QObject):
    """Animates a widget's ``pos`` so entrances can rise into place."""

    def __init__(self, widget: QWidget, parent: QObject | None = None):
        super().__init__(parent or widget)
        self._widget = widget

    def _get_pos(self):
        return self._widget.pos()

    def _set_pos(self, pos) -> None:
        self._widget.move(pos)

    pos = Property("QPoint", _get_pos, _set_pos)


def slide_fade_in(
    widget: QWidget,
    duration_ms: int | None = None,
    offset_px: int = 10,
    delay_ms: int = 0,
) -> QParallelAnimationGroup:
    """Standard entrance: fade in while rising a few pixels into place."""
    duration = duration_ms or MOTION["base"]
    base_pos = widget.pos()
    widget.move(base_pos.x(), base_pos.y() + offset_px)

    effect = _ensure_opacity_effect(widget)
    effect.setOpacity(0.0)

    fade = QPropertyAnimation(effect, b"opacity", widget)
    fade.setDuration(duration)
    fade.setStartValue(0.0)
    fade.setEndValue(1.0)
    fade.setEasingCurve(QEasingCurve.Type.OutCubic)

    mover = _PositionAnimator(widget)
    slide = QPropertyAnimation(mover, b"pos", widget)
    slide.setDuration(duration)
    slide.setStartValue(widget.pos())
    slide.setEndValue(base_pos)
    slide.setEasingCurve(QEasingCurve.Type.OutCubic)

    group = QParallelAnimationGroup(widget)
    group.addAnimation(fade)
    group.addAnimation(slide)

    def _done() -> None:
        widget.setGraphicsEffect(None)

    group.finished.connect(_done)

    if delay_ms > 0:
        wrapper = QSequentialAnimationGroup(widget)
        wrapper.addAnimation(QPauseAnimation(delay_ms, widget))
        wrapper.addAnimation(group)
        wrapper.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)
    else:
        group.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)
    return group


def slide_fade_out(
    widget: QWidget,
    duration_ms: int | None = None,
    offset_px: int = 8,
    on_finished: Callable[[], None] | None = None,
) -> QParallelAnimationGroup:
    """Exit transition: fade out while drifting slightly, then clean up."""
    duration = duration_ms or MOTION["fast"]
    start_pos = widget.pos()
    target_pos = start_pos

    effect = _ensure_opacity_effect(widget)

    fade = QPropertyAnimation(effect, b"opacity", widget)
    fade.setDuration(duration)
    fade.setStartValue(effect.opacity())
    fade.setEndValue(0.0)
    fade.setEasingCurve(QEasingCurve.Type.InCubic)

    mover = _PositionAnimator(widget)
    slide = QPropertyAnimation(mover, b"pos", widget)
    slide.setDuration(duration)
    slide.setStartValue(start_pos)
    slide.setEndValue(target_pos.translated(0, offset_px))
    slide.setEasingCurve(QEasingCurve.Type.InCubic)

    group = QParallelAnimationGroup(widget)
    group.addAnimation(fade)
    group.addAnimation(slide)
    if on_finished:
        group.finished.connect(on_finished)
    group.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)
    return group


def staggered_entrance(
    widgets: Sequence[QWidget] | Iterable[QWidget],
    step_ms: int = STAGGER_STEP_MS,
    duration_ms: int | None = None,
    offset_px: int = 10,
    max_items: int = 12,
) -> list[QParallelAnimationGroup]:
    """Sequence a subtle entrance across a row/column of cards.

    The stagger is capped so a long list never makes the user wait for the
    last card — the tail animates together with the final step.
    """
    groups: list[QParallelAnimationGroup] = []
    for index, widget in enumerate(list(widgets)[:max_items]):
        if widget is None or not widget.isVisible():
            continue
        delay = min(index, max_items - 1) * step_ms
        groups.append(
            slide_fade_in(
                widget,
                duration_ms=duration_ms,
                offset_px=offset_px,
                delay_ms=delay,
            )
        )
    return groups


# ---------------------------------------------------------------------------
# Theme / page cross-fade
# ---------------------------------------------------------------------------


def cross_fade(
    host: QWidget,
    incoming: QWidget,
    outgoing: QWidget | None = None,
    duration_ms: int | None = None,
) -> QParallelAnimationGroup:
    """Swap to ``incoming`` with a coordinated fade instead of a hard cut.

    Used both for view changes and — with ``incoming is outgoing`` — for the
    theme switch, where the incoming surface is re-rendered once with the new
    tokens and then brightened in. That reads as a coordinated transition
    rather than a jarring global recolor.
    """
    duration = duration_ms or MOTION["base"]

    incoming_effect = _ensure_opacity_effect(incoming)
    incoming_effect.setOpacity(0.0)

    group = QParallelAnimationGroup(host)

    fade_incoming = QPropertyAnimation(incoming_effect, b"opacity", incoming)
    fade_incoming.setDuration(duration)
    fade_incoming.setStartValue(0.0)
    fade_incoming.setEndValue(1.0)
    fade_incoming.setEasingCurve(QEasingCurve.Type.OutCubic)
    group.addAnimation(fade_incoming)

    if outgoing is not None and outgoing is not incoming:
        outgoing_effect = _ensure_opacity_effect(outgoing)
        fade_outgoing = QPropertyAnimation(outgoing_effect, b"opacity", outgoing)
        fade_outgoing.setDuration(duration)
        fade_outgoing.setStartValue(outgoing_effect.opacity())
        fade_outgoing.setEndValue(0.0)
        fade_outgoing.setEasingCurve(QEasingCurve.Type.OutCubic)
        group.addAnimation(fade_outgoing)

    def _done() -> None:
        incoming.setGraphicsEffect(None)

    group.finished.connect(_done)
    group.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)
    return group


# ---------------------------------------------------------------------------
# Low-level helper
# ---------------------------------------------------------------------------


def animate_property(
    target: QObject,
    property_name: bytes,
    start,
    end,
    duration_ms: int | None = None,
    easing: QEasingCurve.Type = QEasingCurve.Type.OutCubic,
    on_finished: Callable[[], None] | None = None,
) -> QPropertyAnimation:
    """Animate any Qt property — geometry, colour, blur radius, and so on."""
    anim = QPropertyAnimation(target, property_name, target)
    anim.setDuration(duration_ms or MOTION["base"])
    anim.setStartValue(start)
    anim.setEndValue(end)
    anim.setEasingCurve(easing)
    if on_finished:
        anim.finished.connect(on_finished)
    anim.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)
    return anim


# ---------------------------------------------------------------------------
# Live indicator
# ---------------------------------------------------------------------------


class PulseIndicator(QWidget):
    """Small breathing status dot for the live file tail.

    This is the one intentionally continuous animation in the product, and it
    exists to communicate "actively streaming". :meth:`stop` cancels it so a
    paused or stopped monitor is completely still.
    """

    def __init__(
        self,
        parent: QWidget | None = None,
        diameter: int = 7,
        tone: str = "success",
    ):
        super().__init__(parent)
        self._diameter = diameter
        self._tone_token = tone
        self._opacity = 1.0
        self._anim: QPropertyAnimation | None = None
        self.setFixedSize(diameter + 8, diameter + 8)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)

    # -- animated opacity ---------------------------------------------------
    def _get_opacity(self) -> float:
        return self._opacity

    def _set_opacity(self, value: float) -> None:
        self._opacity = float(value)
        self.update()

    opacity = Property(float, _get_opacity, _set_opacity)

    def set_tone(self, tone: str) -> None:
        """Switch the dot's semantic colour (``success`` / ``warning`` ...)."""
        self._tone_token = tone
        self.update()

    def start(self) -> None:
        """Begin the breathing cycle (no-op if already running)."""
        if self._anim is not None:
            return
        self._anim = QPropertyAnimation(self, b"opacity", self)
        self._anim.setDuration(MOTION["ambient"])
        self._anim.setStartValue(1.0)
        self._anim.setKeyValueAt(0.5, 0.35)
        self._anim.setEndValue(1.0)
        self._anim.setEasingCurve(QEasingCurve.Type.InOutSine)
        self._anim.setLoopCount(-1)
        self._anim.start()

    def stop(self) -> None:
        """Halt the animation and settle back to full opacity."""
        if self._anim is not None:
            self._anim.stop()
            self._anim.deleteLater()
            self._anim = None
        self._set_opacity(1.0)

    def paintEvent(self, event) -> None:
        from PySide6.QtGui import QPainter

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        color = qcolor(self._tone_token)
        color.setAlphaF(self._opacity)

        # Soft outer halo (very restrained) then the solid core.
        halo = qcolor(self._tone_token)
        halo.setAlphaF(self._opacity * 0.22)
        painter.setPen(Qt.PenStyle.NoPen)

        center = self.rect().center()
        halo_r = (self._diameter / 2) + 3
        painter.setBrush(halo)
        painter.drawEllipse(
            center,
            int(halo_r),
            int(halo_r),
        )

        painter.setBrush(color)
        core_r = self._diameter / 2
        painter.drawEllipse(center, int(core_r), int(core_r))
        painter.end()
