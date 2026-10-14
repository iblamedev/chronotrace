"""Payload normalization prior to detection.

Never mutates or discards the raw request — only ever adds a normalized_request
to the LogEvent so the analyst can always compare raw vs. decoded side by side
(Event Inspector requirement: RAW EVENT vs NORMALIZED EVENT sections).
"""

from __future__ import annotations

import html
from urllib.parse import unquote

from app.models.event import LogEvent

MAX_DECODE_PASSES = 3  # guards against decode loops on adversarial input


def normalize_payload(text: str) -> str:
    """URL-decode (repeatedly, safely) + HTML-unescape + whitespace normalize.

    Repeated URL-decoding catches double/triple-encoded traversal and script
    payloads (%252e%252e%252f -> %2e%2e%2f -> ../) without looping forever on
    strings that don't actually keep decoding to something new.
    """
    if not text:
        return text

    decoded = text
    for _ in range(MAX_DECODE_PASSES):
        next_pass = unquote(decoded)
        if next_pass == decoded:
            break
        decoded = next_pass

    decoded = html.unescape(decoded)

    # Collapse repeated whitespace but keep the string otherwise intact —
    # don't lowercase globally, since case sometimes carries signal (e.g.
    # Windows paths, base64), and rules use re.IGNORECASE where it matters.
    decoded = " ".join(decoded.split())

    return decoded


def normalize_event(event: LogEvent) -> LogEvent:
    """Populate event.normalized_request from event.request, in place."""
    source = event.request or event.path
    if source:
        event.normalized_request = normalize_payload(source)
    return event


def normalize_events(events: list[LogEvent]) -> list[LogEvent]:
    for event in events:
        normalize_event(event)
    return events
