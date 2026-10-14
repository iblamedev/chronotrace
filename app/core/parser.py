"""Log parsing.

Design: each format gets its own parser with a `matches()` sniff test and a
`parse_line()` implementation. The ParserRegistry tries each registered
parser (in priority order) per line, falling back to a generic parser that
never fails outright — every line becomes a LogEvent, even if most fields
stay None. This mirrors the "never crash on a malformed line" requirement
and fixes the gap in the original prototype, where a non-Apache log (like
the supplied auth-log sample) degraded to almost all-"-" fields.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod

from app.models.event import LogEvent, ParseQuality


class LineParser(ABC):
    """Base interface for a single log-format parser."""

    name: str = "base"

    @abstractmethod
    def matches(self, line: str) -> bool:
        """Cheap sniff test: does this line look like this format?"""

    @abstractmethod
    def parse_line(self, line: str, line_number: int, source_file: str) -> LogEvent:
        """Parse a line already confirmed (or assumed) to match this format."""


class ApacheCombinedParser(LineParser):
    """Apache/nginx combined access log format.

    Example:
    1.2.3.4 - - [02/Nov/2025:12:01:02 +0530] "GET /index.php?id=1 HTTP/1.1" 200 512 "-" "Mozilla/5.0"
    """

    name = "apache_combined"

    PATTERN = re.compile(
        r"(?P<ip>\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"
        r'"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
        r'(?:\s+"(?P<referrer>[^"]*)")?'
        r'(?:\s+"(?P<useragent>[^"]*)")?'
    )

    def matches(self, line: str) -> bool:
        return bool(self.PATTERN.search(line))

    def parse_line(self, line: str, line_number: int, source_file: str) -> LogEvent:
        m = self.PATTERN.search(line)
        assert m is not None
        request = m.group("request")
        path = None
        if request:
            parts = request.split()
            if len(parts) >= 2:
                path = parts[1]
        return LogEvent(
            line_number=line_number,
            raw_line=line,
            source_file=source_file,
            timestamp=m.group("time"),
            source_ip=m.group("ip"),
            status_code=m.group("status"),
            request=request,
            path=path,
            user_agent=m.group("useragent"),
            parser_used=self.name,
            parse_quality=ParseQuality.FULL,
        )


class AuthLogParser(LineParser):
    """Custom space-delimited auth log format found in the sample data.

    Example:
    401 Unauthorised 49.99.13.16 admin 2019-03-21T21:08:15 /login
    200 OK           12.55.22.88 jr22  2019-03-18T09:21:17 /login

    Status text may be one or two tokens ("200 OK" / "401 Unauthorised"), so
    this is matched by anchoring on the ISO timestamp and IP instead of fixed
    column widths, which are unreliable once whitespace is collapsed.
    """

    name = "auth_log"

    # status-code, then anything, then an IPv4, a username token, an ISO
    # timestamp, and a trailing path.
    PATTERN = re.compile(
        r"^(?P<status>\d{3})\s+\S+\s+"
        r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
        r"(?P<user>\S+)\s+"
        r"(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\s+"
        r"(?P<path>\S+)"
    )

    def matches(self, line: str) -> bool:
        return bool(self.PATTERN.match(line.strip()))

    def parse_line(self, line: str, line_number: int, source_file: str) -> LogEvent:
        m = self.PATTERN.match(line.strip())
        assert m is not None
        return LogEvent(
            line_number=line_number,
            raw_line=line,
            source_file=source_file,
            timestamp=m.group("time"),
            source_ip=m.group("ip"),
            status_code=m.group("status"),
            username=m.group("user"),
            path=m.group("path"),
            request=f"{m.group('user')} -> {m.group('path')}",
            parser_used=self.name,
            parse_quality=ParseQuality.FULL,
        )


class GenericFallbackParser(LineParser):
    """Last resort: never fails, extracts whatever it can find.

    This replaces the prototype's Apache-only fallback. It independently
    hunts for an IPv4 address and a timestamp-shaped substring (ISO or
    Apache-bracket style) anywhere in the line, and keeps the raw line as
    the request/message field so nothing is lost.
    """

    name = "generic_fallback"

    IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
    ISO_TIME_RE = re.compile(r"\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}")
    APACHE_TIME_RE = re.compile(r"\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s*[+-]\d{4}")
    STATUS_RE = re.compile(r"\b([1-5]\d{2})\b")

    def matches(self, line: str) -> bool:
        return True  # always applicable as a last resort

    def parse_line(self, line: str, line_number: int, source_file: str) -> LogEvent:
        ip_m = self.IP_RE.search(line)
        time_m = self.ISO_TIME_RE.search(line) or self.APACHE_TIME_RE.search(line)
        status_m = self.STATUS_RE.search(line)

        snippet = line.strip()
        if len(snippet) > 200:
            snippet = snippet[:200] + "..."

        return LogEvent(
            line_number=line_number,
            raw_line=line,
            source_file=source_file,
            timestamp=time_m.group(0) if time_m else None,
            source_ip=ip_m.group(1) if ip_m else None,
            status_code=status_m.group(1) if status_m else None,
            request=snippet,
            parser_used=self.name,
            parse_quality=ParseQuality.PARTIAL
            if (ip_m or time_m)
            else ParseQuality.UNPARSED,
        )


class ParserRegistry:
    """Tries structured parsers in order before falling back to generic.

    Structured parsers are tried in the order registered; the first one
    whose `matches()` sniff test passes wins for that line. This means a
    single file can mix formats line-by-line without misclassifying the
    whole file, which matters once multiple log sources get merged.
    """

    def __init__(self, parsers: list[LineParser] | None = None):
        self.parsers: list[LineParser] = parsers or [
            ApacheCombinedParser(),
            AuthLogParser(),
        ]
        self.fallback = GenericFallbackParser()

    def parse_line(self, line: str, line_number: int, source_file: str) -> LogEvent:
        stripped = line.rstrip("\n").rstrip("\r")
        if not stripped.strip():
            return LogEvent(
                line_number=line_number,
                raw_line=line,
                source_file=source_file,
                parse_quality=ParseQuality.UNPARSED,
            )
        for parser in self.parsers:
            if parser.matches(stripped):
                return parser.parse_line(stripped, line_number, source_file)
        return self.fallback.parse_line(stripped, line_number, source_file)

    def parse_file(self, path: str) -> list[LogEvent]:
        events: list[LogEvent] = []
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f, start=1):
                events.append(self.parse_line(line, i, path))
        return events
