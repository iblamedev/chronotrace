"""Data model for a single parsed log line.

A LogEvent always preserves the original raw line, even when parsing only
partially succeeds. Downstream normalization adds a second, decoded view of
the request/message field without ever discarding the raw one.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ParseQuality(str, Enum):
    """How confidently this line was parsed."""

    FULL = "full"  # Matched a known structured format exactly
    PARTIAL = "partial"  # Fallback parser recovered some fields only
    UNPARSED = "unparsed"  # Nothing recognizable; raw line kept as-is


@dataclass
class LogEvent:
    """A single normalized log line, format-agnostic.

    Fields are Optional because different log formats (Apache combined,
    auth-log, arbitrary text) do not all carry the same information, and a
    partially-parsed line should not silently invent values.
    """

    line_number: int
    raw_line: str
    source_file: str

    timestamp: str | None = None
    source_ip: str | None = None
    status_code: str | None = None
    request: str | None = None  # e.g. "GET /path?query HTTP/1.1"
    user_agent: str | None = None
    username: str | None = None  # present for auth-log style events
    path: str | None = None

    parser_used: str | None = None  # name of the parser that produced this event
    parse_quality: ParseQuality = ParseQuality.UNPARSED

    # Populated by the normalizer stage. Never overwrites raw_line.
    normalized_request: str | None = None

    def display_request(self) -> str:
        """Best-effort human-readable request/message field for table display."""
        return self.request or self.path or self.raw_line[:160]
