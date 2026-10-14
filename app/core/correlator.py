"""Behavioral correlation engine.

Cross-event, windowed correlation over already-produced DetectionResults and
raw events, grouped by source IP within a sliding time window (or sequence window).

Implements:
1. Brute-force / credential stuffing:
   same source IP, >= N failed-login hits (tags 'auth' or 'correlation-input')
   within window -> BEHAVIORAL detection, severity CRITICAL, category "Credential Attack".
2. Scanner / enumeration activity:
   same source IP, repeated 4xx/5xx or repeated recon-tagged hits above threshold
   within window -> BEHAVIORAL, severity MEDIUM-HIGH.
3. Multi-signature hostile source:
   same source IP triggers >= N distinct signature rule categories within a session
   -> BEHAVIORAL, severity HIGH, category "Coordinated Attack Pattern".
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime, timezone

from app.models.detection import DetectionResult
from app.models.event import LogEvent
from app.models.rule import DetectionMethod, Severity


def _parse_timestamp(ts_str: str | None) -> float | None:
    """Best effort timestamp parser returning epoch seconds."""
    if not ts_str:
        return None
    # ISO-like e.g. 2019-03-18T09:21:17 or 2019-03-18 09:21:17
    try:
        clean_ts = ts_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean_ts)
        return dt.timestamp()
    except (ValueError, TypeError):
        pass

    # Apache style: 02/Nov/2025:12:01:02 +0530
    m = re.search(
        r"(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}(?:\s+[+-]\d{4})?)", ts_str
    )
    if m:
        try:
            val = m.group(1)
            parts = val.split()
            dt = datetime.strptime(parts[0], "%d/%b/%Y:%H:%M:%S").replace(
                tzinfo=timezone.utc
            )
            return dt.timestamp()
        except (ValueError, TypeError):
            pass

    return None


class CorrelationEngine:
    """Sliding-window behavioral correlation engine."""

    def __init__(
        self,
        brute_force_threshold: int = 3,
        brute_force_window_sec: float = 120.0,
        recon_threshold: int = 4,
        recon_window_sec: float = 120.0,
        multi_category_threshold: int = 3,
    ):
        self.brute_force_threshold = brute_force_threshold
        self.brute_force_window_sec = brute_force_window_sec
        self.recon_threshold = recon_threshold
        self.recon_window_sec = recon_window_sec
        self.multi_category_threshold = multi_category_threshold

    def correlate(
        self,
        events: Iterable[LogEvent],
        detections: Iterable[DetectionResult],
    ) -> list[DetectionResult]:
        """Runs behavioral correlation rules over the events and existing detections."""
        all_events = list(events)
        all_detections = list(detections)

        # Map event object to list of its detections
        event_detections = defaultdict(list)
        for d in all_detections:
            event_detections[id(d.event)].append(d)

        # Group events by source IP (excluding None / empty)
        by_ip: dict[str, list[LogEvent]] = defaultdict(list)
        for ev in all_events:
            ip = (ev.source_ip or "").strip()
            if ip and ip != "-":
                by_ip[ip].append(ev)

        behavioral_results: list[DetectionResult] = []

        for ip, ip_events in by_ip.items():
            # Sort events by timestamp if available, else preserve sequence by line_number
            ip_events_sorted = sorted(
                ip_events,
                key=lambda e: (_parse_timestamp(e.timestamp) or 0.0, e.line_number),
            )

            # 1. Brute-force / Credential Stuffing Correlation
            bf_results = self._correlate_brute_force(
                ip, ip_events_sorted, event_detections
            )
            behavioral_results.extend(bf_results)

            # 2. Scanner / Enumeration Activity Correlation
            scanner_results = self._correlate_scanner_activity(
                ip, ip_events_sorted, event_detections
            )
            behavioral_results.extend(scanner_results)

            # 3. Multi-signature Hostile Source Correlation
            multi_results = self._correlate_multi_category(
                ip, ip_events_sorted, event_detections
            )
            behavioral_results.extend(multi_results)

        return behavioral_results

    def _correlate_brute_force(
        self,
        ip: str,
        events: list[LogEvent],
        event_detections: dict[int, list[DetectionResult]],
    ) -> list[DetectionResult]:
        """Detect repeated failed logins / auth probes within a sliding window."""
        results: list[DetectionResult] = []

        # Find events with failed login or auth indicators
        auth_events: list[LogEvent] = []
        for e in events:
            dets = event_detections.get(id(e), [])
            is_auth_fail = any(
                d.rule_id
                in ("failed-login", "multi-failed-login", "credential-stuffing-probe")
                for d in dets
            )
            is_401 = e.status_code == "401"
            if is_auth_fail or is_401:
                auth_events.append(e)

        if len(auth_events) < self.brute_force_threshold:
            return results

        # Sliding window check
        windows: list[list[LogEvent]] = []
        n = len(auth_events)
        i = 0
        while i < n:
            current_window = [auth_events[i]]
            t0 = _parse_timestamp(auth_events[i].timestamp)
            j = i + 1
            while j < n:
                tj = _parse_timestamp(auth_events[j].timestamp)
                if t0 is not None and tj is not None:
                    if tj - t0 <= self.brute_force_window_sec:
                        current_window.append(auth_events[j])
                        j += 1
                    else:
                        break
                else:
                    # Fallback sequence window (up to 10 sequential events)
                    if j - i < 10:
                        current_window.append(auth_events[j])
                        j += 1
                    else:
                        break

            if len(current_window) >= self.brute_force_threshold:
                windows.append(current_window)
                i = j  # Move past current clustered window to prevent duplicate alerts
            else:
                i += 1

        for win in windows:
            distinct_users = {e.username for e in win if e.username}
            distinct_lines = [e.line_number for e in win]
            user_str = (
                f" across {len(distinct_users)} user(s): {', '.join(sorted(distinct_users))}"
                if distinct_users
                else ""
            )
            anchor_event = win[-1]

            results.append(
                DetectionResult(
                    event=anchor_event,
                    rule_id="behavioral-brute-force",
                    rule_name="Brute-Force / Credential Stuffing Pattern",
                    category="Credential Attack",
                    severity=Severity.CRITICAL,
                    confidence=95,
                    method=DetectionMethod.BEHAVIORAL,
                    matched_snippet=f"{len(win)} failed login attempts from IP {ip}{user_str} (Lines {distinct_lines})",
                    recommendation="Immediately inspect IP reputation and consider automated blocklist entry for IP.",
                    contributing_events=win,
                    context_notes=f"Detected {len(win)} auth failures within sliding window. Targeted accounts: {len(distinct_users)}.",
                )
            )

        return results

    def _correlate_scanner_activity(
        self,
        ip: str,
        events: list[LogEvent],
        event_detections: dict[int, list[DetectionResult]],
    ) -> list[DetectionResult]:
        """Detect automated directory/URL enumeration or burst of 4xx/5xx responses."""
        results: list[DetectionResult] = []

        scanner_events: list[LogEvent] = []
        for e in events:
            dets = event_detections.get(id(e), [])
            has_recon = any(
                d.category in ("Reconnaissance", "Anomaly / Protocol")
                or d.rule_id
                in (
                    "discovery-recon",
                    "scanner-ua",
                    "repeated-4xx-5xx",
                    "default-admin-probe",
                )
                for d in dets
            )
            is_err = e.status_code and e.status_code.startswith(("4", "5"))
            if has_recon or is_err:
                scanner_events.append(e)

        if len(scanner_events) < self.recon_threshold:
            return results

        # Check in sliding window
        windows: list[list[LogEvent]] = []
        n = len(scanner_events)
        i = 0
        while i < n:
            current_window = [scanner_events[i]]
            t0 = _parse_timestamp(scanner_events[i].timestamp)
            j = i + 1
            while j < n:
                tj = _parse_timestamp(scanner_events[j].timestamp)
                if t0 is not None and tj is not None:
                    if tj - t0 <= self.recon_window_sec:
                        current_window.append(scanner_events[j])
                        j += 1
                    else:
                        break
                else:
                    if j - i < 15:
                        current_window.append(scanner_events[j])
                        j += 1
                    else:
                        break

            if len(current_window) >= self.recon_threshold:
                windows.append(current_window)
                i = j
            else:
                i += 1

        for win in windows:
            status_codes = [e.status_code for e in win if e.status_code]
            lines = [e.line_number for e in win]
            anchor_event = win[-1]
            sev = Severity.HIGH if len(win) >= 6 else Severity.MEDIUM

            results.append(
                DetectionResult(
                    event=anchor_event,
                    rule_id="behavioral-scanner-recon",
                    rule_name="Automated Scanner / Enumeration Activity",
                    category="Enumeration / Recon",
                    severity=sev,
                    confidence=85,
                    method=DetectionMethod.BEHAVIORAL,
                    matched_snippet=f"{len(win)} probe/error requests from IP {ip} (StatusCodes: {set(status_codes)}, Lines {lines[:8]})",
                    recommendation="Verify User-Agent and investigate if source IP is an unauthorized vulnerability scanner.",
                    contributing_events=win,
                    context_notes=f"Rapid enumeration probe sequence observed: {len(win)} events within correlation window.",
                )
            )

        return results

    def _correlate_multi_category(
        self,
        ip: str,
        events: list[LogEvent],
        event_detections: dict[int, list[DetectionResult]],
    ) -> list[DetectionResult]:
        """Detect source IP triggering multiple distinct signature categories."""
        results: list[DetectionResult] = []

        categories_seen: dict[str, list[DetectionResult]] = defaultdict(list)
        for e in events:
            for d in event_detections.get(id(e), []):
                # Only count signature detections for multi-signature hostile source
                if d.method == DetectionMethod.SIGNATURE and d.category:
                    categories_seen[d.category].append(d)

        # Exclude pure Anomaly / Protocol from counting towards hostile categories if alone
        significant_categories = [
            c for c in categories_seen if c != "Anomaly / Protocol"
        ]
        if len(significant_categories) >= self.multi_category_threshold:
            contributing = [
                d.event for cat_dets in categories_seen.values() for d in cat_dets
            ]
            # Deduplicate contributing events while preserving order
            seen_ids = set()
            unique_contrib = []
            for ev in contributing:
                if id(ev) not in seen_ids:
                    seen_ids.add(id(ev))
                    unique_contrib.append(ev)

            anchor_event = unique_contrib[-1]
            cat_list = ", ".join(sorted(significant_categories))
            results.append(
                DetectionResult(
                    event=anchor_event,
                    rule_id="behavioral-multi-category",
                    rule_name="Multi-Signature Hostile Source",
                    category="Coordinated Attack Pattern",
                    severity=Severity.HIGH,
                    confidence=90,
                    method=DetectionMethod.BEHAVIORAL,
                    matched_snippet=f"IP {ip} triggered {len(significant_categories)} distinct attack categories: {cat_list}",
                    recommendation="High risk hostile actor conducting multi-vector attack; enforce network perimeter block.",
                    contributing_events=unique_contrib,
                    context_notes=f"Triggered attack vectors: {cat_list}.",
                )
            )

        return results
