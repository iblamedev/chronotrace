"""Interactive SOC Event Inspector dialog.

Subclasses AppDialog to provide a cohesive forensic modal experience:
- Section 1: Overview & Metadata (Timestamp, Source File, Line Number, Parser, Quality)
- Section 2: Network & Protocol Fields (Source IP, Port, HTTP Method, Path, Status Code, User Agent, Account)
- Section 3: Raw Preserved Log Line (Monospace, read-only, forensic evidence)
- Section 4: Normalized & Decoded Payload (Multi-pass unescaped, decoded URL/hex/unicode)
- Section 5: Detection Logic & Trigger Match (Exact regex pattern, trigger snippet, contributing factors)
- Section 6: Local Threat Intelligence & IOC Cross-Reference (Live query of local IOC database)
- Section 7: Analyst Remediation Guidance (Structured playbook recommendation)
- Footer Actions: Add IP to Watchlist, Copy Raw Line, Close Inspector
"""

from __future__ import annotations

import sqlite3
from typing import Any

from PySide6.QtWidgets import (
    QApplication,
    QLabel,
    QPlainTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.models.detection import Alert, BlocklistEntry
from app.models.event import LogEvent
from app.storage.database import Database
from app.storage.repositories import BlocklistRepo, IOCRepo
from app.ui.theme import TOKENS
from app.ui.widgets.animated_button import TactileButton
from app.ui.widgets.app_dialog import AppDialog, FieldRow, Section
from app.ui.widgets.severity_badge import MethodChip, SeverityBadge
from app.ui.widgets.surfaces import Card
from app.ui.widgets.toast_notification import ToastHost


class EventInspectorDialog(AppDialog):
    """Forensic Event Inspector dialog following the ThreatDesk design system."""

    def __init__(
        self,
        event: LogEvent | None = None,
        alert: dict[str, Any] | Alert | None = None,
        parent: QWidget | None = None,
    ):
        # Extract properties
        rule_name = "Log Event Inspection"
        severity = "info"
        method = "signature"
        snippet = ""
        recommendation = ""
        notes = ""
        source_ip = event.source_ip if event else "-"

        if alert:
            if isinstance(alert, dict):
                rule_name = alert.get("rule_name", rule_name)
                severity = alert.get("severity", severity)
                method = alert.get("method", method)
                snippet = alert.get("matched_snippet", "")
                recommendation = alert.get("recommendation", "")
                notes = alert.get("notes", "")
                source_ip = alert.get("source_ip", source_ip)
            else:
                rule_name = alert.detection.rule_name
                severity = alert.detection.severity.value
                method = alert.detection.method.value
                snippet = alert.detection.matched_snippet
                recommendation = alert.detection.recommendation
                notes = alert.notes or ""
                source_ip = (
                    alert.detection.event.source_ip
                    if alert.detection.event
                    else source_ip
                )

        meta_str = f"Source Host: {source_ip} · Detection: {method.title()}"
        if event and event.timestamp:
            meta_str = f"Timestamp: {event.timestamp} · " + meta_str

        super().__init__(
            title=rule_name,
            eyebrow="FORENSIC EVENT INSPECTOR",
            meta=meta_str,
            severity=severity,
            width=900,
            height=700,
            parent=parent,
        )

        self.event = event
        self.alert = alert
        self.source_ip = source_ip

        # Header trailing badges
        badge = SeverityBadge(severity, method)
        chip = MethodChip(method)
        self.add_header_widget(chip)
        self.add_header_widget(badge)

        body: QVBoxLayout = self.body_layout()

        # -------------------------------------------------------------------
        # Section 1: Overview & Metadata
        # -------------------------------------------------------------------
        sec_overview = Section(
            title="Overview & Ingestion Metadata",
            caption="Forensic origin, timestamp, and parser ingestion details",
            tone="accent",
        )
        if event:
            sec_overview.add(FieldRow("Source File", event.source_file, mono=True))
            sec_overview.add(FieldRow("Line Number", str(event.line_number), mono=True))
            sec_overview.add(FieldRow("Ingest Timestamp", event.timestamp or "N/A", mono=True))
            parser_text = f"{event.parser_used} ({event.parse_quality.value if event.parse_quality else 'unparsed'})"
            sec_overview.add(FieldRow("Parser & Fidelity", parser_text))
        else:
            sec_overview.add(FieldRow("Event Source", "Direct Detection Alert", mono=True))
            sec_overview.add(FieldRow("Primary Entity", source_ip, mono=True))
        body.addWidget(sec_overview)

        # -------------------------------------------------------------------
        # Section 2: Network & Protocol Fields
        # -------------------------------------------------------------------
        sec_protocol = Section(
            title="Network & Protocol Analysis",
            caption="Extracted Layer 4-7 telemetry and identity attributes",
            tone="accent",
        )
        if event:
            sec_protocol.add(FieldRow("Source IP", event.source_ip or "-", mono=True))
            if event.source_port:
                sec_protocol.add(FieldRow("Source Port", str(event.source_port), mono=True))
            if event.http_method:
                sec_protocol.add(FieldRow("HTTP Method", event.http_method, mono=True))
            if event.path or event.request:
                sec_protocol.add(FieldRow("Request URI / Path", event.path or event.request, mono=True))
            if event.status_code:
                sec_protocol.add(FieldRow("HTTP Status Code", str(event.status_code), mono=True))
            if event.user_agent:
                sec_protocol.add(FieldRow("User Agent", event.user_agent))
            if event.username:
                sec_protocol.add(FieldRow("User / Identity", event.username, mono=True))
        else:
            sec_protocol.add(FieldRow("Source IP", source_ip, mono=True))
        body.addWidget(sec_protocol)

        # -------------------------------------------------------------------
        # Section 3: Preserved Raw Log Line
        # -------------------------------------------------------------------
        sec_raw = Section(
            title="Raw Preserved Log Line",
            caption="Untampered, verbatim log entry recorded during ingestion",
            variant="inset",
        )
        self.raw_box = QPlainTextEdit()
        self.raw_box.setReadOnly(True)
        self.raw_box.setPlainText(
            event.raw_line if (event and event.raw_line) else "Verbatim raw log line unavailable."
        )
        self.raw_box.setMaximumHeight(85)
        sec_raw.add(self.raw_box)
        body.addWidget(sec_raw)

        # -------------------------------------------------------------------
        # Section 4: Normalized & Decoded Payload
        # -------------------------------------------------------------------
        sec_norm = Section(
            title="Normalized & Decoded Payload",
            caption="Multi-pass unescaped, URL-decoded, and normalized request string",
            variant="inset",
        )
        self.norm_box = QPlainTextEdit()
        self.norm_box.setReadOnly(True)
        norm_text = ""
        if event:
            norm_text = event.normalized_request or event.request or event.raw_line or ""
        self.norm_box.setPlainText(norm_text or "No normalized payload available.")
        self.norm_box.setMaximumHeight(85)
        sec_norm.add(self.norm_box)
        body.addWidget(sec_norm)

        # -------------------------------------------------------------------
        # Section 5: Detection Logic & Trigger Match
        # -------------------------------------------------------------------
        sec_detect = Section(
            title="Detection Logic & Trigger Condition",
            caption="Rule trigger signature, matched snippet, or behavioral correlation",
            tone="danger" if severity in ("critical", "high") else "warning",
        )
        sec_detect.add(FieldRow("Trigger Rule", rule_name))
        sec_detect.add(FieldRow("Detection Type", f"{method.title()} Engine Match"))

        if snippet:
            self.snip_box = QPlainTextEdit()
            self.snip_box.setReadOnly(True)
            self.snip_box.setPlainText(snippet)
            self.snip_box.setMaximumHeight(70)
            sec_detect.add(self.snip_box)

        if notes:
            sec_detect.add(FieldRow("Correlation Context", notes))
        body.addWidget(sec_detect)

        # -------------------------------------------------------------------
        # Section 6: Local Threat Intelligence & IOC Cross-Reference
        # -------------------------------------------------------------------
        sec_ioc = Section(
            title="Threat Intelligence & IOC Cross-Reference",
            caption="Air-gapped lookup against local indicator database",
            tone="violet",
        )
        ioc_hit_str = self._lookup_local_ioc(source_ip)
        sec_ioc.add(FieldRow("Target Indicator", source_ip, mono=True))
        sec_ioc.add(FieldRow("IOC Intelligence Status", ioc_hit_str))
        body.addWidget(sec_ioc)

        # -------------------------------------------------------------------
        # Section 7: Analyst Remediation Guidance
        # -------------------------------------------------------------------
        sec_rem = Section(
            title="Analyst Remediation Guidance",
            caption="Recommended triage and containment protocol for this detection",
            variant="inset",
            tone="accent",
        )
        rec_text = (
            recommendation
            or "Follow standard SOC triage procedure: verify host activity, review authentication logs, and isolate source host if malicious intent is confirmed."
        )
        rec_card = Card(variant="inset")
        rec_label = QLabel(rec_text)
        rec_label.setWordWrap(True)
        rec_label.setStyleSheet(f"color: {TOKENS['text_primary']}; line-height: 1.4;")
        rec_card.body().addWidget(rec_label)
        sec_rem.add(rec_card)
        body.addWidget(sec_rem)

        # -------------------------------------------------------------------
        # Footer Action Row
        # -------------------------------------------------------------------
        self.btn_watchlist = TactileButton(
            "Add IP to Watchlist",
            appearance="default",
            tooltip="Add this host IP to local blocklist / watchlist",
        )
        self.btn_watchlist.clicked.connect(self._add_to_watchlist)

        self.btn_copy_raw = TactileButton(
            "Copy Raw Line",
            appearance="default",
            tooltip="Copy raw log line to clipboard",
        )
        self.btn_copy_raw.clicked.connect(self._copy_raw_line)

        self.btn_close = TactileButton(
            "Close Inspector",
            appearance="primary",
            tooltip="Close this inspection window",
        )
        self.btn_close.clicked.connect(self.accept)

        self.add_footer_action(self.btn_watchlist)
        self.add_footer_action(self.btn_copy_raw)
        self.add_footer_action(self.btn_close)

    # -----------------------------------------------------------------------
    # Helper Methods
    # -----------------------------------------------------------------------
    def _lookup_local_ioc(self, ip: str) -> str:
        """Perform offline local query against the IOC and Blocklist repositories."""
        if not ip or ip == "-":
            return "No valid IP entity associated with this event."

        try:
            db = Database()
            ioc_repo = IOCRepo(db)
            blocklist_repo = BlocklistRepo(db)

            matched_ioc = ioc_repo.find_match(ip)
            is_blocked = blocklist_repo.is_blocked(ip)

            details = []
            if matched_ioc:
                details.append(
                    f"MATCH FOUND: Known {matched_ioc.ioc_type.value.upper()} (Severity: {matched_ioc.severity.value.upper()}, Confidence: {matched_ioc.confidence}%, Source: {matched_ioc.source})"
                )
            if is_blocked:
                details.append("Host is currently enrolled in Local Hostile Watchlist.")

            if details:
                return " | ".join(details)
            return "No match found in local offline IOC database (Benign / Unflagged host)."
        except (sqlite3.Error, OSError, ValueError) as exc:
            return f"IOC lookup unavailable: {exc}"

    def _add_to_watchlist(self) -> None:
        """Add current source IP to the local blocklist database."""
        if not self.source_ip or self.source_ip == "-":
            return

        try:
            db = Database()
            repo = BlocklistRepo(db)
            if repo.is_blocked(self.source_ip):
                ToastHost.instance().show_toast(
                    f"Host {self.source_ip} is already on the watchlist.",
                    title="Watchlist",
                    severity="info",
                )
                return

            entry = BlocklistEntry(
                ip=self.source_ip,
                reason=f"Added via Forensic Inspector from {self.title_label.text()}",
                confidence=90,
                suggested_by_detection=True,
            )
            repo.add_entry(entry)
            ToastHost.instance().show_toast(
                f"Successfully added {self.source_ip} to watchlist.",
                title="Watchlist Updated",
                severity="success",
            )
        except (sqlite3.Error, OSError, ValueError) as exc:
            ToastHost.instance().show_toast(
                f"Failed to add IP: {exc}",
                title="Watchlist Error",
                severity="error",
            )

    def _copy_raw_line(self) -> None:
        """Copy the raw line text to system clipboard."""
        raw_text = self.raw_box.toPlainText()
        if raw_text:
            clipboard = QApplication.clipboard()
            clipboard.setText(raw_text)
            ToastHost.instance().show_toast(
                "Raw log line copied to clipboard.",
                title="Copied",
                severity="info",
            )
