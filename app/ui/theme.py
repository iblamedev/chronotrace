"""ThreatDesk design system: semantic theme tokens, typography scale, and
the single token-driven Qt stylesheet (QSS) consumed by every view.

Design intent
-------------
ThreatDesk should read like a world-class product (Linear / Raycast / Arc /
Vercel / Apple), not like a stereotypical neon "hacker dashboard". That means:

* One restrained accent colour plus a disciplined severity ramp.
* No neon glows, no matrix effects, no terminal chrome, no decorative glyphs.
* A refined monochromatic foundation with layered surfaces and hairline borders.
* Everything addressed through **semantic tokens** so both themes share the exact
  same geometry, spacing, typography and interaction language.

Themes are *siblings*, not inversions. ``graphite`` is deep, atmospheric dark;
``paper`` is a genuinely independent construction with warm-white / cool-neutral
surfaces, muted shadows and dark graphite type. Tokens are named by role
(``surface``, ``border``, ``text_secondary``, ``accent`` ...) never by colour, so
a component written once behaves correctly in both themes.

Legacy compatibility
--------------------
Earlier views addressed colours through a flat ``PALETTE`` dict (``bg_surface``,
``cyan``, ``severity_critical`` ...). ``PALETTE`` is preserved and *re-derived*
from the active theme tokens by :func:`apply_theme`, so no view needs to know
which token generation it speaks.
"""

from __future__ import annotations

import colorsys
from typing import Any

# ---------------------------------------------------------------------------
# 1. Theme token definitions
# ---------------------------------------------------------------------------

#: Semantic token keys every theme defines, in presentation order.
TOKEN_ORDER: tuple[str, ...] = (
    "background",
    "background_alt",
    "surface",
    "surface_raised",
    "surface_sunken",
    "overlay",
    "map_accent",
    "inset",
    "inset_panel",
    "rail",
    "border_subtle",
    "border",
    "border_strong",
    "border_focus",
    "text_primary",
    "text_secondary",
    "text_tertiary",
    "text_muted",
    "text_inverse",
    "accent",
    "accent_hover",
    "accent_pressed",
    "accent_muted",
    "accent_border",
    "accent_soft",
    "accent_contrast",
    "violet",
    "violet_hover",
    "violet_muted",
    "violet_border",
    "success",
    "success_muted",
    "success_border",
    "warning",
    "warning_muted",
    "warning_border",
    "danger",
    "danger_muted",
    "danger_border",
    "info",
    "severity_critical",
    "severity_high",
    "severity_medium",
    "severity_low",
    "severity_info",
    "selection_bg",
    "control_bg",
    "control_hover",
    "control_pressed",
    "card_hover",
    "scrollbar",
    "scrollbar_hover",
    "focus_ring",
    "shadow_soft",
    "shadow_medium",
    "ambient",
    "legend_bg",
)

DARK: dict[str, str] = {
    "name": "Graphite",
    "mode": "dark",
    # Deep, atmospheric near-black graphite ladder.
    "background": "#08090c",
    "background_alt": "#0b0d11",
    "surface": "#0e1116",
    "surface_raised": "#14181f",
    "surface_sunken": "#0a0c10",
    "overlay": "rgba(6, 7, 9, 0.60)",
    "map_accent": "#123049",
    "inset": "#0b0d11",
    "inset_panel": "#0d1015",
    "rail": "#1a1d24",
    "border_subtle": "rgba(255, 255, 255, 0.045)",
    "border": "rgba(255, 255, 255, 0.085)",
    "border_strong": "rgba(255, 255, 255, 0.155)",
    "border_focus": "rgba(91, 194, 224, 0.55)",
    "text_primary": "#eef1f6",
    "text_secondary": "#95a0b0",
    "text_tertiary": "#7f8a99",
    "text_muted": "#5d6774",
    "text_inverse": "#08090c",
    "accent": "#6fc9e2",
    "accent_hover": "#8bd8ed",
    "accent_pressed": "#57b4d0",
    "accent_muted": "rgba(111, 201, 226, 0.16)",
    "accent_border": "rgba(111, 201, 226, 0.38)",
    "accent_soft": "rgba(111, 201, 226, 0.07)",
    "accent_contrast": "#05161d",
    "violet": "#a693f8",
    "violet_hover": "#b9a9fb",
    "violet_muted": "rgba(166, 147, 248, 0.16)",
    "violet_border": "rgba(166, 147, 248, 0.36)",
    "success": "#5ec898",
    "success_muted": "rgba(94, 200, 152, 0.16)",
    "success_border": "rgba(94, 200, 152, 0.34)",
    "warning": "#dfae4e",
    "warning_muted": "rgba(223, 174, 78, 0.16)",
    "warning_border": "rgba(223, 174, 78, 0.34)",
    "danger": "#eb6b6b",
    "danger_muted": "rgba(235, 107, 107, 0.16)",
    "danger_border": "rgba(235, 107, 107, 0.36)",
    "info": "#8c98a9",
    "severity_critical": "#ef6a6a",
    "severity_high": "#e08a54",
    "severity_medium": "#d4b154",
    "severity_low": "#76a9e8",
    "severity_info": "#8892a0",
    "selection_bg": "rgba(255, 255, 255, 0.055)",
    "control_bg": "rgba(255, 255, 255, 0.035)",
    "control_hover": "rgba(255, 255, 255, 0.07)",
    "control_pressed": "rgba(255, 255, 255, 0.10)",
    "card_hover": "#171c24",
    "scrollbar": "rgba(255, 255, 255, 0.10)",
    "scrollbar_hover": "rgba(255, 255, 255, 0.20)",
    "focus_ring": "rgba(111, 201, 226, 0.20)",
    "shadow_soft": "rgba(0, 0, 0, 0.45)",
    "shadow_medium": "rgba(0, 0, 0, 0.55)",
    "ambient": "rgba(111, 201, 226, 0.055)",
    "legend_bg": "rgba(14, 17, 22, 0.86)",
}

LIGHT: dict[str, str] = {
    "name": "Paper",
    "mode": "light",
    # Warm-white / cool-neutral construction — not an inversion of the dark set.
    "background": "#faf9f7",
    "background_alt": "#f4f3f0",
    "surface": "#ffffff",
    "surface_raised": "#ffffff",
    "surface_sunken": "#f3f2ef",
    "overlay": "rgba(38, 36, 33, 0.22)",
    "map_accent": "#bcd6e8",
    "inset": "#f4f3f0",
    "inset_panel": "#f7f6f3",
    "rail": "#e6e4de",
    "border_subtle": "rgba(24, 22, 19, 0.07)",
    "border": "rgba(24, 22, 19, 0.12)",
    "border_strong": "rgba(24, 22, 19, 0.20)",
    "border_focus": "rgba(21, 121, 153, 0.45)",
    "text_primary": "#1b1d21",
    "text_secondary": "#575c64",
    "text_tertiary": "#6b7078",
    "text_muted": "#8b8f96",
    "text_inverse": "#ffffff",
    "accent": "#157a99",
    "accent_hover": "#11657f",
    "accent_pressed": "#0d5065",
    "accent_muted": "rgba(21, 122, 153, 0.12)",
    "accent_border": "rgba(21, 122, 153, 0.32)",
    "accent_soft": "rgba(21, 122, 153, 0.06)",
    "accent_contrast": "#ffffff",
    "violet": "#6a56d6",
    "violet_hover": "#5b48c4",
    "violet_muted": "rgba(106, 86, 214, 0.12)",
    "violet_border": "rgba(106, 86, 214, 0.30)",
    "success": "#1d7a52",
    "success_muted": "rgba(29, 122, 82, 0.11)",
    "success_border": "rgba(29, 122, 82, 0.28)",
    "warning": "#9a6710",
    "warning_muted": "rgba(154, 103, 16, 0.12)",
    "warning_border": "rgba(154, 103, 16, 0.30)",
    "danger": "#bf3b3b",
    "danger_muted": "rgba(191, 59, 59, 0.10)",
    "danger_border": "rgba(191, 59, 59, 0.28)",
    "info": "#6b7078",
    "severity_critical": "#bf3b3b",
    "severity_high": "#b45f1f",
    "severity_medium": "#8f6f10",
    "severity_low": "#2f6ebb",
    "severity_info": "#767c85",
    "selection_bg": "rgba(24, 22, 19, 0.045)",
    "control_bg": "rgba(24, 22, 19, 0.035)",
    "control_hover": "rgba(24, 22, 19, 0.06)",
    "control_pressed": "rgba(24, 22, 19, 0.09)",
    "card_hover": "#f8f7f5",
    "scrollbar": "rgba(24, 22, 19, 0.16)",
    "scrollbar_hover": "rgba(24, 22, 19, 0.30)",
    "focus_ring": "rgba(21, 122, 153, 0.16)",
    "shadow_soft": "rgba(40, 38, 34, 0.07)",
    "shadow_medium": "rgba(40, 38, 34, 0.13)",
    "ambient": "rgba(21, 122, 153, 0.05)",
    "legend_bg": "rgba(255, 255, 255, 0.88)",
}

#: Theme registry. Exactly two first-class themes — a dark and a light sibling.
THEMES: dict[str, dict[str, str]] = {
    "graphite": DARK,
    "paper": LIGHT,
}

DEFAULT_THEME = "graphite"

#: Older releases shipped five themes; map retired keys forward so stored
#: settings keep working instead of silently resetting.
LEGACY_THEME_ALIASES: dict[str, str] = {
    "obsidian_teal": "graphite",
    "nordic_emerald": "graphite",
    "midnight_cobalt": "graphite",
    "tactical_amber": "graphite",
    "polar_light": "paper",
    "dark": "graphite",
    "light": "paper",
}

#: Ordered theme rotation used by the sidebar quick-toggle.
THEME_CYCLE: tuple[str, ...] = ("graphite", "paper")



# ---------------------------------------------------------------------------
# 2. Typography, spacing, radius, and motion scales
# ---------------------------------------------------------------------------

#: Type ramp. A clean Apple/Swiss-editorial hierarchy — restrained sizes with
#: clear weight and tracking differentiation rather than oversized headings.
TYPE: dict[str, dict[str, Any]] = {
    "display": {"size": 26, "weight": 600, "tracking": -0.4},
    "title": {"size": 19, "weight": 600, "tracking": -0.2},
    "heading": {"size": 15, "weight": 600, "tracking": -0.1},
    "subheading": {"size": 13, "weight": 600, "tracking": 0.0},
    "body": {"size": 13, "weight": 400, "tracking": 0.0},
    "small": {"size": 12, "weight": 400, "tracking": 0.0},
    "micro": {"size": 11, "weight": 500, "tracking": 0.04},
    "label": {"size": 10, "weight": 600, "tracking": 0.09},
    "metric": {"size": 28, "weight": 600, "tracking": -0.9},
    "mono": {"size": 12, "weight": 400, "tracking": 0.0},
    "mono_small": {"size": 11, "weight": 400, "tracking": 0.0},
}

#: 4px-base spacing scale (generous by product-UI standards).
SPACE: dict[str, int] = {
    "xxs": 2,
    "xs": 4,
    "sm": 8,
    "md": 12,
    "lg": 16,
    "xl": 22,
    "xxl": 30,
    "xxxl": 40,
}

GUTTER: dict[str, int] = {"view": 26, "view_top": 22, "view_bottom": 20, "card": 18, "card_tight": 14}

RADIUS: dict[str, int] = {"xs": 4, "sm": 6, "md": 9, "lg": 13, "xl": 18, "pill": 999}

MOTION: dict[str, int] = {
    "instant": 90,
    "fast": 150,
    "base": 220,
    "slow": 320,
    "entrance": 380,
    "ambient": 2600,
}

#: Typographic families, resolved by ``resolve_font_families`` at runtime.
FALLBACK_SANS: tuple[str, ...] = (
    "Helvetica",
    "Helvetica Neue",
    "Inter",
    "SF Pro Text",
    "Segoe UI Variable Text",
    "Segoe UI",
    "Arial",
)
FALLBACK_MONO: tuple[str, ...] = (
    "JetBrains Mono",
    "SF Mono",
    "Cascadia Mono",
    "Consolas",
    "Menlo",
    "Liberation Mono",
)

def _quote_family(name: str) -> str:
    """Quote multi-word family names so Qt and QSS parse them as one family."""
    spaced = chr(32) in name
    return ('"' + name + '"') if spaced else name
SANS_FAMILY = ", ".join(_quote_family(n) for n in FALLBACK_SANS)
MONO_FAMILY = ", ".join(_quote_family(n) for n in FALLBACK_MONO)

#: Cached font stacks; populated lazily once a QApplication exists.
_font_cache: tuple[str, str] | None = None


def resolve_font_families() -> tuple[str, str]:
    """Return ``(sans, mono)`` family stacks, preferring locally installed fonts."""
    global _font_cache
    if _font_cache is not None:
        return _font_cache
    _font_cache = (SANS_FAMILY, MONO_FAMILY)

    try:  # pragma: no cover - depends on a live Qt install
        from PySide6.QtGui import QFontDatabase
        from PySide6.QtWidgets import QApplication
    except Exception:  # noqa: BLE001
        return _font_cache
    if QApplication.instance() is None:
        return _font_cache
    try:
        installed = {str(f).lower() for f in QFontDatabase.families()}
    except Exception:  # noqa: BLE001
        return _font_cache

    def pick(candidates: tuple[str, ...], css_fallback: str) -> str:
        ordered: list[str] = []
        for name in candidates:
            if name.lower() in installed:
                ordered.append(_quote_family(name))
        for name in candidates:
            token = _quote_family(name)
            if token not in ordered:
                ordered.append(token)
        return ", ".join(ordered) or css_fallback
    _font_cache = (
        pick(FALLBACK_SANS, SANS_FAMILY),
        pick(FALLBACK_MONO, MONO_FAMILY),
    )
    return _font_cache


# ---------------------------------------------------------------------------
# 3. Colour helpers
# ---------------------------------------------------------------------------


def _parse_color(value: str) -> tuple[int, int, int, float] | None:
    """Parse ``#rgb``/``#rrggbb``/``rgb()``/``rgba()`` into ``(r, g, b, alpha)``."""
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if raw.startswith("#"):
        hexpart = raw[1:]
        if len(hexpart) == 3:
            hexpart = "".join(c * 2 for c in hexpart)
        alpha = 1.0
        if len(hexpart) == 8:
            alpha = int(hexpart[6:8], 16) / 255
            hexpart = hexpart[:6]
        if len(hexpart) != 6:
            return None
        try:
            r, g, b = (int(hexpart[i : i + 2], 16) for i in (0, 2, 4))
        except ValueError:
            return None
        return r, g, b, alpha
    lowered = raw.lower()
    if lowered.startswith(("rgba(", "rgb(")) and raw.endswith(chr(41)):
        body = raw[raw.index(chr(41)) + 1 : -1]
        parts = [p.strip() for p in body.split(",")]
        if len(parts) not in (3, 4):
            return None
        try:
            r = int(float(parts[0]))
            g = int(float(parts[1]))
            b = int(float(parts[2]))
            a = float(parts[3]) if len(parts) == 4 else 1.0
        except ValueError:
            return None
        return r, g, b, a
    return None


def to_hex(value: str, fallback: str = "#000") -> str:
    """Normalise any supported colour notation to ``#rrggbb``."""
    parsed = _parse_color(value)
    if parsed is None:
        return fallback
    r, g, b, _ = parsed
    return f"#{r:02x}{g:02x}{b:02x}"


def hex_alpha(value: str, alpha_percent: int) -> str:
    """Return ``#rrggbb`` + 2-hex-digit alpha suffix for QSS colour blending."""
    base = to_hex(value, "#000")[1:]
    return f"#{base}{max(0, min(255, alpha_percent)):02x}"


def with_alpha(value: str, alpha: float) -> str:
    """Return ``value`` re-expressed as ``rgba(...)`` with the given alpha."""
    parsed = _parse_color(value)
    if parsed is None:
        return value
    r, g, b, _ = parsed
    return f"rgba({r}, {g}, {b}, {max(0.0, min(1.0, alpha)):.3f})"


def mix(color_a: str, color_b: str, ratio: float) -> str:
    """Blend two colours in sRGB. ``ratio`` 0 -> a, 1 -> b."""
    pa, pb = _parse_color(color_a), _parse_color(color_b)
    if pa is None or pb is None:
        return color_a
    ratio = max(0.0, min(1.0, ratio))
    r = round(pa[0] + (pb[0] - pa[0]) * ratio)
    g = round(pa[1] + (pb[1] - pa[1]) * ratio)
    b = round(pa[2] + (pb[2] - pa[2]) * ratio)
    return f"#{r:02x}{g:02x}{b:02x}"


def relative_luminance(color: str) -> float:
    """WCAG relative luminance, used to pick readable foregrounds."""
    parsed = _parse_color(color)
    if parsed is None:
        return 0.0
    channels = []
    for raw in parsed[:3]:
        c = raw / 255
        channels.append(c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4)
    return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2]


def readable_on(background: str, dark: str = "#101215", light: str = "#ffffff") -> str:
    """Pick ``dark`` or ``light`` foreground for maximum contrast."""
    return dark if relative_luminance(background) > 0.55 else light


def is_dark_color(color: str) -> bool:
    return relative_luminance(color) < 0.5


def spin(color: str, lightness_delta: float, saturation_delta: float = 0.0) -> str:
    """Lighten/darken a colour in HLS space — handy for hairline borders."""
    parsed = _parse_color(color)
    if parsed is None:
        return color
    r, g, b, a = parsed
    h, l, s = colorsys.rgb_to_hls(r / 255, g / 255, b / 255)
    l = max(0.0, min(1.0, l + lightness_delta))
    s = max(0.0, min(1.0, s + saturation_delta))
    r2, g2, b2 = colorsys.hls_to_rgb(h, l, s)
    return f"rgba({round(r2 * 255)}, {round(g2 * 255)}, {round(b2 * 255)}, {a:.3f})"



# ---------------------------------------------------------------------------
# 4. Active theme state
# ---------------------------------------------------------------------------

#: Active semantic token map. Mutated in place so live references stay valid.
TOKENS: dict[str, str] = dict(DARK)

#: Flat legacy alias map consumed by views written against the older naming.
PALETTE: dict[str, str] = {}

#: Severity -> resolved colour, refreshed on every theme application.
SEVERITY_COLORS: dict[str, str] = {}

#: Detection method -> resolved colour.
METHOD_COLORS: dict[str, str] = {}

_current_theme_key: str = DEFAULT_THEME


def resolve_theme_key(theme_key: str | None) -> str:
    """Normalise a (possibly legacy or unknown) theme key to a registered one."""
    if not theme_key:
        return DEFAULT_THEME
    key = str(theme_key).strip().lower()
    if key in THEMES:
        return key
    return LEGACY_THEME_ALIASES.get(key, DEFAULT_THEME)


def _rebuild_legacy_palette() -> None:
    """Re-derive the flat legacy alias map from the active semantic tokens."""
    t = TOKENS
    PALETTE.clear()
    PALETTE.update(
        {
            "mode": t["mode"],
            "name": t["name"],
            # Surfaces
            "bg_root": t["background"],
            "bg_sidebar": t["background_alt"],
            "bg_surface": t["surface"],
            "bg_card": t["surface_raised"],
            "bg_card_hover": t["card_hover"],
            "bg_input": t["surface_sunken"],
            "bg_sunken": t["surface_sunken"],
            "inset": t["inset_panel"],
            "rail": t["rail"],
            "overlay": t["overlay"],
            "map_accent": t["map_accent"],
            # Borders
            "border": t["border"],
            "border_subtle": t["border_subtle"],
            "border_strong": t["border_strong"],
            # Text
            "text_primary": t["text_primary"],
            "text_secondary": t["text_secondary"],
            "text_tertiary": t["text_tertiary"],
            "text_muted": t["text_muted"],
            "text_faint": t["text_muted"],
            # Accent
            "cyan": t["accent"],
            "cyan_hover": t["accent_hover"],
            "cyan_glow": t["accent_soft"],
            "accent": t["accent"],
            "accent_soft": t["accent_soft"],
            "accent_muted": t["accent_muted"],
            "violet": t["violet"],
            "violet_hover": t["violet_hover"],
            "violet_glow": t["violet_muted"],
            # Status
            "success": t["success"],
            "warning": t["warning"],
            "danger": t["danger"],
            "info": t["info"],
            # Severity
            "severity_critical": t["severity_critical"],
            "severity_high": t["severity_high"],
            "severity_medium": t["severity_medium"],
            "severity_low": t["severity_low"],
            "severity_info": t["severity_info"],
            # Misc
            "legend_bg": t["legend_bg"],
            "selection_bg": t["selection_bg"],
        }
    )


def _refresh_semantic_maps() -> None:
    SEVERITY_COLORS.clear()
    SEVERITY_COLORS.update(
        {
            "critical": TOKENS["severity_critical"],
            "high": TOKENS["severity_high"],
            "medium": TOKENS["severity_medium"],
            "low": TOKENS["severity_low"],
            "info": TOKENS["severity_info"],
        }
    )
    METHOD_COLORS.clear()
    METHOD_COLORS.update({"signature": TOKENS["accent"], "behavioral": TOKENS["violet"]})


def active_theme() -> str:
    """Return the active theme registry key."""
    return _current_theme_key


def active_mode() -> str:
    """Return ``"dark"`` or ``"light"`` for the active theme."""
    return TOKENS.get("mode", "dark")


def is_dark() -> bool:
    return active_mode() == "dark"


def apply_theme(theme_key: str | None) -> None:
    """Activate a theme in place: refresh tokens, legacy aliases, semantic maps."""
    global _current_theme_key
    _current_theme_key = resolve_theme_key(theme_key)
    TOKENS.clear()
    TOKENS.update(THEMES[_current_theme_key])
    _rebuild_legacy_palette()
    _refresh_semantic_maps()


def severity_color(severity: str) -> str:
    """Resolve a severity name (case-insensitive) to its active colour."""
    return SEVERITY_COLORS.get(str(severity).strip().lower(), TOKENS["text_muted"])


def method_color(method: str) -> str:
    """Resolve a detection method to its active colour."""
    return METHOD_COLORS.get(str(method).strip().lower(), TOKENS["accent"])


def status_color(status: str) -> str:
    """Resolve an alert disposition status to its active colour."""
    value = str(status).strip().lower()
    if value == "resolved":
        return TOKENS["success"]
    if value == "acknowledged":
        return TOKENS["accent"]
    return TOKENS["severity_high"]


def quality_color(quality: str) -> str:
    """Resolve a parse-quality label to its active colour."""
    value = str(quality).strip().lower()
    if value == "full":
        return TOKENS["success"]
    if value == "partial":
        return TOKENS["severity_medium"]
    return TOKENS["severity_critical"]


# ---------------------------------------------------------------------------
# 5. Qt helpers (theme-aware colours, chart palette, re-polish)
# ---------------------------------------------------------------------------


def qcolor(token_or_hex: str, alpha: float | None = None):
    """Return a ``QColor`` from a token name or literal, with optional alpha."""
    from PySide6.QtGui import QColor

    value = TOKENS.get(token_or_hex, token_or_hex)
    parsed = _parse_color(value)
    color = QColor(parsed[0], parsed[1], parsed[2]) if parsed else QColor("#000")
    effective_alpha = alpha if alpha is not None else (parsed[3] if parsed else 1.0)
    if effective_alpha < 1.0:
        color.setAlphaF(max(0.0, min(1.0, effective_alpha)))
    return color


def chart_palette() -> dict[str, Any]:
    """Colour set for QtCharts so charts feel integrated, not pasted in."""
    return {
        "background": TOKENS["surface"],
        "plot": "transparent",
        "grid": TOKENS["border_subtle"],
        "axis": TOKENS["border"],
        "label": TOKENS["text_tertiary"],
        "label_strong": TOKENS["text_secondary"],
        "title": TOKENS["text_secondary"],
        "accent": TOKENS["accent"],
        "accent_soft": with_alpha(TOKENS["accent"], 0.55),
        "violet": TOKENS["violet"],
        "legend_bg": TOKENS["legend_bg"],
        "legend_border": TOKENS["border"],
        "tooltip_bg": TOKENS["surface_raised"],
        "tooltip_text": TOKENS["text_primary"],
        "tooltip_border": TOKENS["border_strong"],
        "severity": (
            TOKENS["severity_critical"],
            TOKENS["severity_high"],
            TOKENS["severity_medium"],
            TOKENS["severity_low"],
            TOKENS["severity_info"],
        ),
        "slate": TOKENS["accent"],
        "signal": TOKENS["accent"],
        "correlation": TOKENS["violet"],
        "sweep": with_alpha(TOKENS["accent"], 0.10),
    }


class ThemeAccess:
    """Live token accessor — widgets read tokens at paint time, never cached."""

    def __getitem__(self, key: str) -> str:
        return TOKENS.get(key, PALETTE.get(key, key))

    def get(self, key: str, default: str | None = None) -> str | None:
        return TOKENS.get(key, PALETTE.get(key, default))

    def __contains__(self, key: str) -> bool:
        return key in TOKENS or key in PALETTE


THEME = ThemeAccess()


def repolish(*widgets) -> None:
    """Re-run style resolution on widgets after a token change."""
    for widget in widgets:
        if widget is None:
            continue
        try:
            style = widget.style()
            style.unpolish(widget)
            style.polish(widget)
            widget.update()
        except Exception:  # noqa: BLE001, S112
            continue


def refresh_application_theme() -> None:
    """Re-apply the compiled stylesheet to the running application.

    Theme switching must be instantaneous: re-applying on ``QApplication``
    restyles every widget in a single pass, then a light repolish nudges
    containers that delegate styling to their children.
    """
    try:  # pragma: no cover - requires a live QApplication
        from PySide6.QtWidgets import QApplication
    except Exception:  # noqa: BLE001
        return

    app = QApplication.instance()
    if app is None:
        return

    global GLOBAL_QSS
    GLOBAL_QSS = build_qss()
    app.setStyleSheet(GLOBAL_QSS)
    for widget in app.allWidgets():
        repolish(widget)



# ---------------------------------------------------------------------------
# 6. Global stylesheet — single source of truth for both themes
# ---------------------------------------------------------------------------


def build_qss(palette: dict[str, str] | None = None) -> str:
    """Compile the full application stylesheet from the active theme tokens.

    ``palette`` is accepted for backwards compatibility with callers that used to
    pass a flat palette dict; the semantic ``TOKENS`` map is authoritative.
    """
    del palette  # tokens are the single source of truth now

    t = TOKENS
    sans, mono = resolve_font_families()
    accent = t["accent"]
    on_accent = t["accent_contrast"]
    on_violet = "#10102a" if is_dark() else "#ffffff"

    return f"""
/* =====================================================================
   ThreatDesk — global design system stylesheet (semantic tokens only)
   Dark: "Graphite"   Light: "Paper"   (identical geometry & motion)
   ===================================================================== */

* {{
    outline: none;
}}

QWidget {{
    color: {t["text_primary"]};
    font-family: {sans};
    font-size: {TYPE["body"]["size"]}px;
    font-weight: {TYPE["body"]["weight"]};
    background-color: transparent;
}}

QMainWindow, QDialog {{
    background-color: {t["background"]};
}}

QWidget#ContentArea, QWidget#ViewRoot, QWidget#ViewBody, QStackedWidget {{
    background-color: {t["background"]};
}}

QWidget#TransparentHost {{
    background-color: transparent;
}}

/* ------------------------------------------------------------ Surfaces */
QFrame[card="primary"] {{
    background-color: {t["surface"]};
    border: 1px solid {t["border"]};
    border-radius: {RADIUS["lg"]}px;
}}

QFrame[card="flush"] {{
    background-color: {t["surface"]};
    border: 1px solid {t["border"]};
    border-radius: {RADIUS["lg"]}px;
}}

QFrame[card="inset"] {{
    background-color: {t["inset_panel"]};
    border: 1px solid {t["border_subtle"]};
    border-radius: {RADIUS["md"]}px;
}}

QFrame[card="plain"] {{
    background-color: transparent;
    border: none;
}}

QFrame[divider="true"] {{
    background-color: {t["border_subtle"]};
    border: none;
    min-height: 1px;
    max-height: 1px;
}}

QFrame[rail="true"] {{
    background-color: {t["border_subtle"]};
    border: none;
    border-radius: 1px;
}}

QFrame[glass="true"] {{
    background-color: {t["surface_raised"]};
    border: 1px solid {t["border_strong"]};
    border-radius: {RADIUS["xl"]}px;
}}

QLabel[role="skeleton"] {{
    background-color: {t["surface_raised"]};
    border-radius: {RADIUS["sm"]}px;
    color: transparent;
}}

/* ---------------------------------------------------------- Typography */
QLabel[role="display"] {{
    font-size: {TYPE["display"]["size"]}px;
    font-weight: {TYPE["display"]["weight"]};
    letter-spacing: {TYPE["display"]["tracking"]}px;
    color: {t["text_primary"]};
}}

QLabel[role="title"] {{
    font-size: {TYPE["title"]["size"]}px;
    font-weight: {TYPE["title"]["weight"]};
    letter-spacing: {TYPE["title"]["tracking"]}px;
    color: {t["text_primary"]};
}}

QLabel[role="heading"] {{
    font-size: {TYPE["heading"]["size"]}px;
    font-weight: {TYPE["heading"]["weight"]};
    color: {t["text_primary"]};
}}

QLabel[role="subheading"] {{
    font-size: {TYPE["subheading"]["size"]}px;
    font-weight: {TYPE["subheading"]["weight"]};
    color: {t["text_primary"]};
}}

QLabel[role="body"] {{
    font-size: {TYPE["body"]["size"]}px;
    color: {t["text_secondary"]};
}}

QLabel[role="secondary"] {{
    font-size: {TYPE["small"]["size"]}px;
    color: {t["text_secondary"]};
}}

QLabel[role="micro"] {{
    font-size: {TYPE["micro"]["size"]}px;
    color: {t["text_tertiary"]};
}}

QLabel[role="caption"] {{
    font-size: {TYPE["small"]["size"]}px;
    color: {t["text_muted"]};
}}

QLabel[role="label"] {{
    font-size: {TYPE["label"]["size"]}px;
    font-weight: {TYPE["label"]["weight"]};
    letter-spacing: {TYPE["label"]["tracking"]}px;
    color: {t["text_tertiary"]};
}}

QLabel[role="metric"] {{
    font-size: {TYPE["metric"]["size"]}px;
    font-weight: {TYPE["metric"]["weight"]};
    letter-spacing: {TYPE["metric"]["tracking"]}px;
    color: {t["text_primary"]};
}}

QLabel[role="accent"] {{
    color: {accent};
    font-weight: 600;
}}

QLabel[role="mono"] {{
    font-family: {mono};
    font-size: {TYPE["mono"]["size"]}px;
    color: {t["text_secondary"]};
}}

QLabel[role="mono-strong"] {{
    font-family: {mono};
    font-size: {TYPE["mono"]["size"]}px;
    color: {t["text_primary"]};
}}

QLabel[tone="success"] {{ color: {t["success"]}; }}
QLabel[tone="warning"] {{ color: {t["warning"]}; }}
QLabel[tone="danger"]  {{ color: {t["danger"]}; }}
QLabel[tone="accent"]  {{ color: {accent}; }}
QLabel[tone="violet"]  {{ color: {t["violet"]}; }}
/* ------------------------------------------------------------- Buttons */
QPushButton {{
    background-color: {t["control_bg"]};
    color: {t["text_primary"]};
    border: 1px solid {t["border"]};
    border-radius: {RADIUS["md"]}px;
    padding: 6px 14px;
    font-size: {TYPE["small"]["size"]}px;
    font-weight: 500;
    min-height: 20px;
}}

QPushButton:hover {{
    background-color: {t["control_hover"]};
    border-color: {t["border_strong"]};
}}

QPushButton:pressed {{
    background-color: {t["control_pressed"]};
    border-color: {t["border_strong"]};
}}

QPushButton:focus {{
    border-color: {t["accent_border"]};
}}

QPushButton:disabled {{
    background-color: transparent;
    color: {t["text_muted"]};
    border-color: {t["border_subtle"]};
}}

QPushButton[appearance="primary"] {{
    background-color: {accent};
    color: {on_accent};
    border: 1px solid {accent};
    font-weight: 600;
}}

QPushButton[appearance="primary"]:hover {{
    background-color: {t["accent_hover"]};
    border-color: {t["accent_hover"]};
}}

QPushButton[appearance="primary"]:pressed {{
    background-color: {t["accent_pressed"]};
    border-color: {t["accent_pressed"]};
}}

QPushButton[appearance="primary"]:disabled {{
    background-color: {t["accent_muted"]};
    color: {t["text_muted"]};
    border-color: transparent;
}}

QPushButton[appearance="violet"] {{
    background-color: {t["violet"]};
    color: {on_violet};
    border: 1px solid {t["violet"]};
    font-weight: 600;
}}

QPushButton[appearance="violet"]:hover {{
    background-color: {t["violet_hover"]};
    border-color: {t["violet_hover"]};
}}

QPushButton[appearance="violet"]:disabled {{
    background-color: {t["violet_muted"]};
    color: {t["text_muted"]};
    border-color: transparent;
}}

QPushButton[appearance="ghost"] {{
    background-color: transparent;
    border-color: transparent;
    color: {t["text_secondary"]};
}}

QPushButton[appearance="ghost"]:hover {{
    background-color: {t["control_bg"]};
    color: {t["text_primary"]};
}}

QPushButton[appearance="danger"] {{
    background-color: transparent;
    color: {t["danger"]};
    border-color: {t["danger_border"]};
}}

QPushButton[appearance="danger"]:hover {{
    background-color: {t["danger_muted"]};
}}

QPushButton[appearance="icon"] {{
    background-color: transparent;
    border-color: transparent;
    padding: 5px;
    border-radius: {RADIUS["sm"]}px;
    color: {t["text_tertiary"]};
    min-height: 16px;
}}

QPushButton[appearance="icon"]:hover {{
    background-color: {t["control_hover"]};
    color: {t["text_primary"]};
}}

QPushButton[appearance="chip"] {{
    background-color: transparent;
    border-color: {t["border"]};
    border-radius: {RADIUS["pill"]}px;
    padding: 4px 12px;
    font-size: {TYPE["micro"]["size"]}px;
    color: {t["text_secondary"]};
}}

QPushButton[appearance="chip"]:hover {{
    border-color: {t["accent_border"]};
    color: {t["text_primary"]};
    background-color: {t["accent_soft"]};
}}

QPushButton[appearance="chip"][active="true"] {{
    border-color: {t["accent_border"]};
    background-color: {t["accent_muted"]};
    color: {t["text_primary"]};
}}

/* Segmented control — theme switch, range selectors */
QPushButton[appearance="segment"] {{
    background-color: transparent;
    border: 1px solid transparent;
    border-radius: {RADIUS["sm"]}px;
    padding: 4px 12px;
    font-size: {TYPE["micro"]["size"]}px;
    color: {t["text_tertiary"]};
}}

QPushButton[appearance="segment"]:hover {{
    color: {t["text_primary"]};
    background-color: {t["control_bg"]};
}}

QPushButton[appearance="segment"][active="true"] {{
    background-color: {t["surface_raised"]};
    border-color: {t["border"]};
    color: {t["text_primary"]};
    font-weight: 600;
}}

/* -------------------------------------------------------------- Inputs */
QLineEdit, QSpinBox, QDoubleSpinBox, QDateEdit, QTimeEdit {{
    background-color: {t["surface_sunken"]};
    color: {t["text_primary"]};
    border: 1px solid {t["border"]};
    border-radius: {RADIUS["md"]}px;
    padding: 6px 11px;
    selection-background-color: {t["accent_muted"]};
    selection-color: {t["text_primary"]};
    min-height: 20px;
}}

QLineEdit:hover, QSpinBox:hover, QDoubleSpinBox:hover {{
    border-color: {t["border_strong"]};
}}

QLineEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus {{
    border-color: {t["accent_border"]};
    background-color: {t["surface"]};
}}

QLineEdit:disabled, QSpinBox:disabled {{
    color: {t["text_muted"]};
}}

QLineEdit[role="search"] {{
    padding-left: 30px;
}}

QLineEdit[mono="true"] {{
    font-family: {mono};
    font-size: {TYPE["mono"]["size"]}px;
}}

QTextEdit, QPlainTextEdit {{
    background-color: {t["surface_sunken"]};
    color: {t["text_primary"]};
    border: 1px solid {t["border"]};
    border-radius: {RADIUS["md"]}px;
    padding: 9px 11px;
    selection-background-color: {t["accent_muted"]};
    selection-color: {t["text_primary"]};
}}

QPlainTextEdit[role="forensic"] {{
    font-family: {mono};
    font-size: {TYPE["mono"]["size"]}px;
    background-color: {t["inset"]};
    border: 1px solid {t["border_subtle"]};
    border-radius: {RADIUS["md"]}px;
    padding: 12px 14px;
}}

QPlainTextEdit[role="forensic"][tone="raw"] {{ color: {t["accent"]}; }}
QPlainTextEdit[role="forensic"][tone="normalized"] {{ color: {t["success"]}; }}
QPlainTextEdit[role="forensic"][tone="trigger"] {{ color: {t["severity_high"]}; }}
QPlainTextEdit[role="forensic"][tone="context"] {{ color: {t["violet"]}; }}

/* ------------------------------------------------------------ ComboBox */
QComboBox {{
    background-color: {t["control_bg"]};
    color: {t["text_primary"]};
    border: 1px solid {t["border"]};
    border-radius: {RADIUS["md"]}px;
    padding: 6px 28px 6px 11px;
    font-size: {TYPE["small"]["size"]}px;
    min-height: 20px;
}}

QComboBox:hover {{
    border-color: {t["border_strong"]};
    background-color: {t["control_hover"]};
}}

QComboBox:focus, QComboBox:on {{
    border-color: {t["accent_border"]};
}}

QComboBox:disabled {{
    color: {t["text_muted"]};
    border-color: {t["border_subtle"]};
}}

QComboBox::drop-down {{
    subcontrol-origin: padding;
    subcontrol-position: center right;
    border: none;
    width: 24px;
}}

QComboBox::down-arrow {{
    image: none;
    width: 7px;
    height: 7px;
    margin-right: 4px;
}}

QComboBox QAbstractItemView {{
    background-color: {t["surface_raised"]};
    color: {t["text_primary"]};
    border: 1px solid {t["border_strong"]};
    border-radius: {RADIUS["md"]}px;
    padding: 5px;
    outline: none;
    selection-background-color: {t["accent_muted"]};
    selection-color: {t["text_primary"]};
}}

/* ------------------------------------------------------------ CheckBox */
QCheckBox, QRadioButton {{
    color: {t["text_primary"]};
    spacing: 8px;
    font-size: {TYPE["small"]["size"]}px;
}}

QCheckBox::indicator, QRadioButton::indicator {{
    width: 15px;
    height: 15px;
    border: 1px solid {t["border_strong"]};
    border-radius: {RADIUS["xs"]}px;
    background-color: {t["surface_sunken"]};
}}

QCheckBox::indicator:hover, QRadioButton::indicator:hover {{
    border-color: {t["accent_border"]};
}}

QCheckBox::indicator:checked {{
    background-color: {accent};
    border-color: {accent};
}}

QRadioButton::indicator {{
    border-radius: 8px;
}}

/* -------------------------------------------------------------- Tables */
QTableView, QTableWidget, QTreeView, QListView {{
    background-color: {t["surface"]};
    alternate-background-color: {t["surface"]};
    color: {t["text_primary"]};
    border: 1px solid {t["border"]};
    border-radius: {RADIUS["lg"]}px;
    gridline-color: transparent;
    selection-background-color: {t["selection_bg"]};
    selection-color: {t["text_primary"]};
    font-size: {TYPE["small"]["size"]}px;
    outline: none;
}}

QTableView::item, QTableWidget::item {{
    padding: 9px 12px;
    border: none;
    border-bottom: 1px solid {t["border_subtle"]};
    color: {t["text_secondary"]};
}}

QTableView::item:hover, QTableWidget::item:hover {{
    background-color: {t["surface_raised"]};
    color: {t["text_primary"]};
}}

QTableView::item:selected, QTableWidget::item:selected {{
    background-color: {t["selection_bg"]};
    color: {t["text_primary"]};
}}

QHeaderView {{
    background-color: {t["surface"]};
    border: none;
}}

QHeaderView::section {{
    background-color: {t["surface"]};
    color: {t["text_tertiary"]};
    padding: 6px 12px;
    border: none;
    border-bottom: 1px solid {t["border"]};
    font-size: {TYPE["label"]["size"]}px;
    font-weight: {TYPE["label"]["weight"]};
    letter-spacing: {TYPE["label"]["tracking"]}px;
}}

QHeaderView::section:hover {{
    color: {t["text_secondary"]};
}}

QHeaderView::up-arrow, QHeaderView::down-arrow {{
    width: 0px;
    height: 0px;
}}

QTableCornerButton::section {{
    background-color: {t["surface"]};
    border: none;
    border-bottom: 1px solid {t["border"]};
}}

/* ---------------------------------------------------------- Scrollbars */
QScrollBar:vertical {{
    background: transparent;
    width: 10px;
    margin: 5px 2px 5px 0px;
}}

QScrollBar::handle:vertical {{
    background: {t["scrollbar"]};
    min-height: 34px;
    border-radius: 4px;
}}

QScrollBar::handle:vertical:hover {{
    background: {t["scrollbar_hover"]};
}}

QScrollBar:horizontal {{
    background: transparent;
    height: 10px;
    margin: 0px 5px 2px 5px;
}}

QScrollBar::handle:horizontal {{
    background: {t["scrollbar"]};
    min-width: 34px;
    border-radius: 4px;
}}

QScrollBar::handle:horizontal:hover {{
    background: {t["scrollbar_hover"]};
}}

QScrollBar::add-line, QScrollBar::sub-line,
QScrollBar::add-page, QScrollBar::sub-page {{
    background: none;
    border: none;
    height: 0px;
    width: 0px;
}}

QScrollArea, QAbstractScrollArea {{
    background-color: transparent;
    border: none;
}}

/* ---------------------------------------------------------------- Tabs */
QTabWidget::pane {{
    border: 1px solid {t["border"]};
    background-color: {t["surface"]};
    border-radius: {RADIUS["lg"]}px;
    top: -1px;
}}

QTabWidget::tab-bar {{
    left: 2px;
}}

QTabBar {{
    background: transparent;
}}

QTabBar::tab {{
    background: transparent;
    color: {t["text_tertiary"]};
    padding: 9px 15px;
    margin-right: 3px;
    border: none;
    border-bottom: 2px solid transparent;
    font-size: {TYPE["small"]["size"]}px;
    font-weight: 500;
}}

QTabBar::tab:hover {{
    color: {t["text_primary"]};
}}

QTabBar::tab:selected {{
    color: {t["text_primary"]};
    border-bottom: 2px solid {accent};
    font-weight: 600;
}}
/* --------------------------------------------------- Progress & Sliders */
QProgressBar {{
    background-color: {t["surface_sunken"]};
    border: none;
    border-radius: 3px;
    text-align: center;
    color: transparent;
}}

QProgressBar::chunk {{
    background-color: {accent};
    border-radius: 3px;
}}

QSlider::groove:horizontal {{
    height: 3px;
    background: {t["border"]};
    border-radius: 2px;
}}

QSlider::handle:horizontal {{
    background: {accent};
    width: 13px;
    height: 13px;
    margin: -5px 0;
    border-radius: 7px;
}}

/* -------------------------------------------------- Menus and Tooltips */
QMenu {{
    background-color: {t["surface_raised"]};
    color: {t["text_primary"]};
    border: 1px solid {t["border_strong"]};
    border-radius: {RADIUS["md"]}px;
    padding: 6px;
}}

QMenu::item {{
    padding: 7px 16px;
    border-radius: {RADIUS["sm"]}px;
    font-size: {TYPE["small"]["size"]}px;
}}

QMenu::item:selected {{
    background-color: {t["accent_muted"]};
    color: {t["text_primary"]};
}}

QMenu::separator {{
    height: 1px;
    background: {t["border_subtle"]};
    margin: 5px 8px;
}}

QToolTip {{
    background-color: {t["surface_raised"]};
    color: {t["text_primary"]};
    border: 1px solid {t["border_strong"]};
    border-radius: {RADIUS["sm"]}px;
    padding: 6px 9px;
    font-size: {TYPE["micro"]["size"]}px;
}}

QMessageBox {{
    background-color: {t["surface"]};
}}

QMessageBox QLabel {{
    color: {t["text_primary"]};
    font-size: {TYPE["body"]["size"]}px;
}}

/* --------------------------------------------------------- Sidebar nav */
QFrame#Sidebar {{
    background-color: {t["background_alt"]};
    border-right: 1px solid {t["border_subtle"]};
}}

QFrame#SidebarHeader, QFrame#SidebarSection {{
    background-color: transparent;
    border: none;
}}

QPushButton#NavItem {{
    background-color: transparent;
    color: {t["text_tertiary"]};
    border: none;
    border-radius: {RADIUS["md"]}px;
    padding: 0px 12px;
    text-align: left;
    font-size: {TYPE["small"]["size"]}px;
    font-weight: 500;
}}

QPushButton#NavItem:hover {{
    background-color: {t["control_bg"]};
    color: {t["text_primary"]};
}}

QPushButton#NavItem[active="true"] {{
    background-color: {t["surface_raised"]};
    color: {t["text_primary"]};
    font-weight: 600;
}}

QPushButton#NavItem[active="true"]:hover {{
    background-color: {t["surface_raised"]};
}}

QFrame#SidebarFooter {{
    background-color: {t["surface_sunken"]};
    border: 1px solid {t["border_subtle"]};
    border-radius: {RADIUS["md"]}px;
}}

QFrame#StatusBar {{
    background-color: {t["background_alt"]};
    border-top: 1px solid {t["border_subtle"]};
}}

QFrame#ViewHeader {{
    background-color: transparent;
    border: none;
}}

QFrame#Toolbar {{
    background-color: {t["background"]};
    border-bottom: 1px solid {t["border_subtle"]};
}}

/* -------------------------------------------------------- Metric cards */
QFrame#MetricCard {{
    background-color: {t["surface"]};
    border: 1px solid {t["border"]};
    border-radius: {RADIUS["lg"]}px;
}}

QFrame#MetricCard:hover {{
    background-color: {t["card_hover"]};
    border-color: {t["border_strong"]};
}}

QFrame#PanelCard {{
    background-color: {t["surface"]};
    border: 1px solid {t["border"]};
    border-radius: {RADIUS["lg"]}px;
}}

/* ---------------------------------------------------- Command surface */
QFrame#CommandSurface {{
    background-color: {t["surface_raised"]};
    border: 1px solid {t["border_strong"]};
    border-radius: {RADIUS["xl"]}px;
}}

QFrame#CommandField {{
    background-color: transparent;
    border: none;
    border-bottom: 1px solid {t["border_subtle"]};
}}

QFrame#CommandRow {{
    background-color: transparent;
    border: none;
    border-radius: {RADIUS["md"]}px;
}}

QFrame#CommandRow[selected="true"] {{
    background-color: {t["accent_soft"]};
}}

/* -------------------------------------------------- Toast & popovers */
QFrame[role="toast"] {{
    background-color: {t["surface_raised"]};
    border: 1px solid {t["border_strong"]};
    border-radius: {RADIUS["lg"]}px;
}}

QFrame[role="popover"] {{
    background-color: {t["surface_raised"]};
    border: 1px solid {t["border_strong"]};
    border-radius: {RADIUS["lg"]}px;
}}

QFrame[role="inspector"] {{
    background-color: {t["surface"]};
    border: 1px solid {t["border"]};
    border-radius: {RADIUS["lg"]}px;
}}

QFrame[role="section"] {{
    background-color: transparent;
    border: none;
}}

/* ------------------------------------------------------- Empty states */
QLabel[role="empty-title"] {{
    font-size: {TYPE["heading"]["size"]}px;
    font-weight: 600;
    color: {t["text_secondary"]};
}}

QLabel[role="empty-body"] {{
    font-size: {TYPE["small"]["size"]}px;
    color: {t["text_muted"]};
}}

/* -------------------------------------------------- Severity badges */
QLabel[badge="true"] {{
    border-radius: {RADIUS["sm"]}px;
    padding: 3px 9px;
    font-size: {TYPE["label"]["size"]}px;
    font-weight: 600;
    letter-spacing: {TYPE["label"]["tracking"]}px;
}}

/* ------------------------------------------------------ Scroll area */
QScrollArea > QWidget > QWidget {{
    background-color: transparent;
}}
"""



# ---------------------------------------------------------------------------
# 7. Public theme entry points
# ---------------------------------------------------------------------------


def build_app_stylesheet() -> str:
    """Compile the stylesheet for the currently active theme."""
    return build_qss()


def set_theme(theme_key: str | None) -> str:
    """Activate ``theme_key`` and return the compiled stylesheet.

    Kept as the single entry point used by the window and settings view so the
    previous flat-palette API stays source-compatible.
    """
    apply_theme(theme_key)
    return build_qss()


def theme_label(theme_key: str | None = None) -> str:
    """Human-readable label, e.g. ``"Paper / Light"``."""
    key = resolve_theme_key(theme_key or _current_theme_key)
    theme = THEMES[key]
    mode = "Light" if theme["mode"] == "light" else "Dark"
    return f'{theme["name"]} - {mode}'


def theme_list() -> list[tuple[str, str]]:
    """Return ``[(key, label), ...]`` for settings and quick toggles."""
    return [(key, theme_label(key)) for key in THEME_CYCLE if key in THEMES]


def next_theme_key(current: str | None = None) -> str:
    """Return the theme key that follows ``current`` in the toggle cycle."""
    key = resolve_theme_key(current or _current_theme_key)
    order = list(THEME_CYCLE)
    if key not in order:
        return order[0]
    return order[(order.index(key) + 1) % len(order)]


# Prime module state on import so widgets may read tokens immediately.
apply_theme(DEFAULT_THEME)

#: Legacy module-level constant kept for external importers.
GLOBAL_QSS: str = build_qss()


__all__ = [
    "DARK",
    "DEFAULT_THEME",
    "GLOBAL_QSS",
    "GUTTER",
    "LIGHT",
    "METHOD_COLORS",
    "MONO_FAMILY",
    "MOTION",
    "PALETTE",
    "RADIUS",
    "SANS_FAMILY",
    "SEVERITY_COLORS",
    "SPACE",
    "THEME",
    "THEMES",
    "THEME_CYCLE",
    "TOKENS",
    "TOKEN_ORDER",
    "TYPE",
    "active_mode",
    "active_theme",
    "apply_theme",
    "build_app_stylesheet",
    "build_qss",
    "chart_palette",
    "is_dark",
    "is_dark_color",
    "method_color",
    "mix",
    "next_theme_key",
    "qcolor",
    "quality_color",
    "readable_on",
    "refresh_application_theme",
    "relative_luminance",
    "repolish",
    "resolve_font_families",
    "resolve_theme_key",
    "set_theme",
    "severity_color",
    "spin",
    "status_color",
    "theme_label",
    "theme_list",
    "to_hex",
    "with_alpha",
]
