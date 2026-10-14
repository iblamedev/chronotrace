"""Time helpers used by the user interface."""

from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo


INDIA_TIMEZONE = ZoneInfo("Asia/Kolkata")


def india_time_text(value: datetime | None = None) -> str:
    """Return a 24-hour clock string in India Standard Time."""
    current = value or datetime.now(INDIA_TIMEZONE)
    return current.astimezone(INDIA_TIMEZONE).strftime("%H:%M:%S")
