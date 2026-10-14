"""Threat intelligence and IOC correlation engine.

Matches parsed events against local IOC definitions:
- IP addresses
- User-Agents
- Domains / URLs / URIs
Surfaces high-confidence threat intel matches across dashboard, alerts, and inspector.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.models.detection import IOC, IOCType
from app.models.event import LogEvent
from app.storage.repositories import IOCRepo


@dataclass
class ThreatIntelMatch:
    event: LogEvent
    ioc: IOC
    matched_field: str
    matched_value: str


class ThreatIntelEngine:
    def __init__(self, ioc_repo: IOCRepo):
        self.ioc_repo = ioc_repo

    def match_event(self, event: LogEvent) -> list[ThreatIntelMatch]:
        """Check all IOC types against candidate fields of an event."""
        matches: list[ThreatIntelMatch] = []

        # 1. IP match
        if event.source_ip:
            ip_ioc = self.ioc_repo.find_match(event.source_ip)
            if ip_ioc and ip_ioc.ioc_type in (IOCType.IP, IOCType.CUSTOM):
                matches.append(
                    ThreatIntelMatch(
                        event=event,
                        ioc=ip_ioc,
                        matched_field="source_ip",
                        matched_value=event.source_ip,
                    )
                )

        # 2. User-Agent match
        if event.user_agent:
            ua_ioc = self.ioc_repo.find_match(event.user_agent)
            if ua_ioc and ua_ioc.ioc_type == IOCType.USER_AGENT:
                matches.append(
                    ThreatIntelMatch(
                        event=event,
                        ioc=ua_ioc,
                        matched_field="user_agent",
                        matched_value=event.user_agent,
                    )
                )

        # 3. URL / Domain / URI match
        req_text = event.normalized_request or event.request or ""
        if req_text:
            for ioc in self.ioc_repo.list_iocs():
                if (
                    ioc.ioc_type
                    in (IOCType.DOMAIN, IOCType.URL, IOCType.URI, IOCType.HASH)
                    and ioc.indicator.lower() in req_text.lower()
                ):
                    matches.append(
                        ThreatIntelMatch(
                            event=event,
                            ioc=ioc,
                            matched_field="request",
                            matched_value=ioc.indicator,
                        )
                    )

        return matches
