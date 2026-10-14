"""Repository layer for SQLite persistence in ThreatDesk.

Entities:
- SessionRepo: AnalysisSession tracking and summary
- EventRepo: LogEvent storage, pagination, search, and cleanup
- RuleRepo: DetectionRule CRUD, built-in vs custom queries
- AlertRepo: Alert status updates, filtering by severity/status/search
- IOCRepo: IOC indicators CRUD, matching engine helper
- BlocklistRepo: Locally tracked suspicious/malicious source IPs
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from typing import Any

from app.models.detection import (
    IOC,
    Alert,
    AlertStatus,
    AnalysisSession,
    BlocklistEntry,
    IOCType,
)
from app.models.event import LogEvent, ParseQuality
from app.models.rule import DetectionMethod, DetectionRule, RuleCategory, Severity
from app.storage.database import Database


class SessionRepo:
    def __init__(self, db: Database):
        self.db = db

    def save_session(self, session: AnalysisSession) -> None:
        conn = self.db.get_connection()
        with conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO sessions (
                    session_id, created_at, source_files, total_events,
                    total_detections, severity_counts_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    session.session_id,
                    session.created_at.isoformat(),
                    json.dumps(list(session.source_files)),
                    session.total_events,
                    session.total_detections,
                    json.dumps(session.severity_counts),
                ),
            )

    def get_latest_session(self) -> AnalysisSession | None:
        conn = self.db.get_connection()
        cur = conn.execute("SELECT * FROM sessions ORDER BY created_at DESC LIMIT 1")
        row = cur.fetchone()
        if not row:
            return None
        return AnalysisSession(
            session_id=row["session_id"],
            created_at=datetime.fromisoformat(row["created_at"]),
            source_files=tuple(json.loads(row["source_files"])),
            total_events=row["total_events"],
            total_detections=row["total_detections"],
            severity_counts=json.loads(row["severity_counts_json"] or "{}"),
        )

    def list_sessions(self) -> list[AnalysisSession]:
        conn = self.db.get_connection()
        cur = conn.execute("SELECT * FROM sessions ORDER BY created_at DESC")
        rows = cur.fetchall()
        return [
            AnalysisSession(
                session_id=r["session_id"],
                created_at=datetime.fromisoformat(r["created_at"]),
                source_files=tuple(json.loads(r["source_files"])),
                total_events=r["total_events"],
                total_detections=r["total_detections"],
                severity_counts=json.loads(r["severity_counts_json"] or "{}"),
            )
            for r in rows
        ]


class EventRepo:
    def __init__(self, db: Database):
        self.db = db

    def save_events(self, session_id: str, events: list[LogEvent]) -> list[int]:
        """Bulk save events for a session, returning assigned DB autoincrement IDs."""
        conn = self.db.get_connection()
        inserted_ids: list[int] = []
        with conn:
            for ev in events:
                cur = conn.execute(
                    """
                    INSERT INTO events (
                        session_id, line_number, raw_line, source_file, timestamp,
                        source_ip, status_code, request, normalized_request,
                        user_agent, username, path, parser_used, parse_quality
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        session_id,
                        ev.line_number,
                        ev.raw_line,
                        ev.source_file,
                        ev.timestamp,
                        ev.source_ip,
                        ev.status_code,
                        ev.request,
                        ev.normalized_request,
                        ev.user_agent,
                        ev.username,
                        ev.path,
                        ev.parser_used,
                        ev.parse_quality.value
                        if ev.parse_quality
                        else ParseQuality.UNPARSED.value,
                    ),
                )
                inserted_ids.append(cur.lastrowid)
        return inserted_ids

    def get_events(
        self,
        session_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
        filter_ip: str | None = None,
        search: str | None = None,
    ) -> list[LogEvent]:
        conn = self.db.get_connection()
        query = "SELECT * FROM events WHERE 1=1"
        params: list[Any] = []
        if session_id:
            query += " AND session_id = ?"
            params.append(session_id)
        if filter_ip:
            query += " AND source_ip = ?"
            params.append(filter_ip)
        if search:
            query += " AND (raw_line LIKE ? OR request LIKE ? OR source_ip LIKE ?)"
            s = f"%{search}%"
            params.extend([s, s, s])

        query += " ORDER BY id ASC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = conn.execute(query, params).fetchall()
        return [
            LogEvent(
                line_number=r["line_number"],
                raw_line=r["raw_line"],
                source_file=r["source_file"],
                timestamp=r["timestamp"],
                source_ip=r["source_ip"],
                status_code=r["status_code"],
                request=r["request"],
                user_agent=r["user_agent"],
                username=r["username"],
                path=r["path"],
                parser_used=r["parser_used"],
                parse_quality=ParseQuality(r["parse_quality"])
                if r["parse_quality"]
                else ParseQuality.UNPARSED,
                normalized_request=r["normalized_request"],
            )
            for r in rows
        ]

    def count_events(
        self,
        session_id: str | None = None,
        filter_ip: str | None = None,
        search: str | None = None,
    ) -> int:
        conn = self.db.get_connection()
        query = "SELECT COUNT(*) AS c FROM events WHERE 1=1"
        params: list[Any] = []
        if session_id:
            query += " AND session_id = ?"
            params.append(session_id)
        if filter_ip:
            query += " AND source_ip = ?"
            params.append(filter_ip)
        if search:
            query += " AND (raw_line LIKE ? OR request LIKE ? OR source_ip LIKE ?)"
            s = f"%{search}%"
            params.extend([s, s, s])
        row = conn.execute(query, params).fetchone()
        return row["c"] if row else 0

    def get_event_by_line(self, session_id: str, line_number: int) -> LogEvent | None:
        conn = self.db.get_connection()
        row = conn.execute(
            "SELECT * FROM events WHERE session_id = ? AND line_number = ? LIMIT 1",
            (session_id, line_number),
        ).fetchone()
        if not row:
            return None
        return LogEvent(
            line_number=row["line_number"],
            raw_line=row["raw_line"],
            source_file=row["source_file"],
            timestamp=row["timestamp"],
            source_ip=row["source_ip"],
            status_code=row["status_code"],
            request=row["request"],
            user_agent=row["user_agent"],
            username=row["username"],
            path=row["path"],
            parser_used=row["parser_used"],
            parse_quality=ParseQuality(row["parse_quality"])
            if row["parse_quality"]
            else ParseQuality.UNPARSED,
            normalized_request=row["normalized_request"],
        )

    def purge_session_events(self, session_id: str) -> None:
        conn = self.db.get_connection()
        with conn:
            conn.execute("DELETE FROM events WHERE session_id = ?", (session_id,))


class RuleRepo:
    def __init__(self, db: Database):
        self.db = db

    def get_all_rules(self) -> list[DetectionRule]:
        conn = self.db.get_connection()
        rows = conn.execute(
            "SELECT * FROM rules ORDER BY is_builtin DESC, name ASC"
        ).fetchall()
        return [self._row_to_rule(r) for r in rows]

    def get_enabled_rules(self) -> list[DetectionRule]:
        conn = self.db.get_connection()
        rows = conn.execute(
            "SELECT * FROM rules WHERE enabled = 1 ORDER BY is_builtin DESC, name ASC"
        ).fetchall()
        return [self._row_to_rule(r) for r in rows]

    def get_rule(self, rule_id: str) -> DetectionRule | None:
        conn = self.db.get_connection()
        row = conn.execute(
            "SELECT * FROM rules WHERE rule_id = ?", (rule_id,)
        ).fetchone()
        return self._row_to_rule(row) if row else None

    def save_rule(self, rule: DetectionRule) -> None:
        conn = self.db.get_connection()
        with conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO rules (
                    rule_id, name, category, description, pattern, severity,
                    confidence, enabled, tags, recommendation, is_builtin, method
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    rule.rule_id,
                    rule.name,
                    rule.category.value
                    if isinstance(rule.category, RuleCategory)
                    else str(rule.category),
                    rule.description,
                    rule.pattern,
                    rule.severity.value,
                    rule.confidence,
                    1 if rule.enabled else 0,
                    ",".join(rule.tags),
                    rule.recommendation,
                    1 if rule.is_builtin else 0,
                    rule.method.value,
                ),
            )

    def set_enabled(self, rule_id: str, enabled: bool) -> None:
        conn = self.db.get_connection()
        with conn:
            conn.execute(
                "UPDATE rules SET enabled = ? WHERE rule_id = ?",
                (1 if enabled else 0, rule_id),
            )

    def delete_rule(self, rule_id: str) -> bool:
        """Deletes a custom rule. Built-in rules cannot be deleted."""
        conn = self.db.get_connection()
        with conn:
            cur = conn.execute(
                "DELETE FROM rules WHERE rule_id = ? AND is_builtin = 0", (rule_id,)
            )
            return cur.rowcount > 0

    def _row_to_rule(self, r: sqlite3.Row) -> DetectionRule:
        cat_val = r["category"]
        try:
            category = RuleCategory(cat_val)
        except ValueError:
            category = RuleCategory.ANOMALY

        tags = tuple(filter(None, (r["tags"] or "").split(",")))
        return DetectionRule(
            rule_id=r["rule_id"],
            name=r["name"],
            category=category,
            description=r["description"],
            pattern=r["pattern"],
            severity=Severity(r["severity"]),
            confidence=r["confidence"],
            enabled=bool(r["enabled"]),
            tags=tags,
            recommendation=r["recommendation"] or "",
            is_builtin=bool(r["is_builtin"]),
            method=DetectionMethod(r["method"])
            if r["method"]
            else DetectionMethod.SIGNATURE,
        )


class AlertRepo:
    def __init__(self, db: Database):
        self.db = db

    def save_alerts(self, alerts: list[Alert], session_id: str) -> None:
        conn = self.db.get_connection()
        with conn:
            for a in alerts:
                event_line = (
                    a.detection.event.line_number if a.detection.event else None
                )
                source_ip = a.detection.event.source_ip if a.detection.event else None
                conn.execute(
                    """
                    INSERT OR REPLACE INTO alerts (
                        alert_id, session_id, event_id, rule_id, rule_name,
                        category, severity, confidence, method, matched_snippet,
                        recommendation, status, notes, created_at, source_ip
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        a.alert_id,
                        session_id,
                        event_line,
                        a.detection.rule_id,
                        a.detection.rule_name,
                        a.detection.category,
                        a.detection.severity.value,
                        a.detection.confidence,
                        a.detection.method.value,
                        a.detection.matched_snippet,
                        a.detection.recommendation,
                        a.status.value,
                        a.notes,
                        a.created_at.isoformat(),
                        source_ip,
                    ),
                )

    def get_alerts(
        self,
        session_id: str | None = None,
        severity: str | None = None,
        status: str | None = None,
        method: str | None = None,
        search: str | None = None,
        limit: int = 250,
    ) -> list[dict[str, Any]]:
        conn = self.db.get_connection()
        query = "SELECT * FROM alerts WHERE 1=1"
        params: list[Any] = []
        if session_id:
            query += " AND session_id = ?"
            params.append(session_id)
        if severity:
            query += " AND severity = ?"
            params.append(severity.lower())
        if status:
            query += " AND status = ?"
            params.append(status.lower())
        if method:
            query += " AND method = ?"
            params.append(method.lower())
        if search:
            query += (
                " AND (rule_name LIKE ? OR matched_snippet LIKE ? OR source_ip LIKE ?)"
            )
            s = f"%{search}%"
            params.extend([s, s, s])

        query += " ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, created_at DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def update_status(
        self, alert_id: str, status: AlertStatus, notes: str | None = None
    ) -> None:
        conn = self.db.get_connection()
        with conn:
            if notes is not None:
                conn.execute(
                    "UPDATE alerts SET status = ?, notes = ? WHERE alert_id = ?",
                    (status.value, notes, alert_id),
                )
            else:
                conn.execute(
                    "UPDATE alerts SET status = ? WHERE alert_id = ?",
                    (status.value, alert_id),
                )


class IOCRepo:
    def __init__(self, db: Database):
        self.db = db

    def list_iocs(self, ioc_type: IOCType | None = None) -> list[IOC]:
        conn = self.db.get_connection()
        if ioc_type:
            rows = conn.execute(
                "SELECT * FROM iocs WHERE ioc_type = ? ORDER BY indicator ASC",
                (ioc_type.value,),
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM iocs ORDER BY indicator ASC").fetchall()
        return [
            IOC(
                ioc_id=r["ioc_id"],
                indicator=r["indicator"],
                ioc_type=IOCType(r["ioc_type"]),
                severity=Severity(r["severity"]),
                confidence=r["confidence"],
                source=r["source"],
                first_seen=datetime.fromisoformat(r["first_seen"]),
                last_seen=datetime.fromisoformat(r["last_seen"]),
                notes=r["notes"] or "",
                tags=tuple(filter(None, (r["tags"] or "").split(","))),
            )
            for r in rows
        ]

    def save_ioc(self, ioc: IOC) -> None:
        conn = self.db.get_connection()
        with conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO iocs (
                    ioc_id, indicator, ioc_type, severity, confidence, source,
                    first_seen, last_seen, notes, tags
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ioc.ioc_id,
                    ioc.indicator,
                    ioc.ioc_type.value,
                    ioc.severity.value,
                    ioc.confidence,
                    ioc.source,
                    ioc.first_seen.isoformat(),
                    ioc.last_seen.isoformat(),
                    ioc.notes,
                    ",".join(ioc.tags),
                ),
            )

    def find_match(self, value: str) -> IOC | None:
        if not value:
            return None
        conn = self.db.get_connection()
        row = conn.execute(
            "SELECT * FROM iocs WHERE indicator = ? COLLATE NOCASE", (value.strip(),)
        ).fetchone()
        if not row:
            return None
        return IOC(
            ioc_id=row["ioc_id"],
            indicator=row["indicator"],
            ioc_type=IOCType(row["ioc_type"]),
            severity=Severity(row["severity"]),
            confidence=row["confidence"],
            source=row["source"],
            first_seen=datetime.fromisoformat(row["first_seen"]),
            last_seen=datetime.fromisoformat(row["last_seen"]),
            notes=row["notes"] or "",
            tags=tuple(filter(None, (row["tags"] or "").split(","))),
        )

    def delete_ioc(self, ioc_id: str) -> bool:
        conn = self.db.get_connection()
        with conn:
            cur = conn.execute("DELETE FROM iocs WHERE ioc_id = ?", (ioc_id,))
            return cur.rowcount > 0


class BlocklistRepo:
    def __init__(self, db: Database):
        self.db = db

    def list_entries(self) -> list[BlocklistEntry]:
        conn = self.db.get_connection()
        rows = conn.execute("SELECT * FROM blocklist ORDER BY added_at DESC").fetchall()
        return [
            BlocklistEntry(
                ip=r["ip"],
                reason=r["reason"],
                confidence=r["confidence"],
                added_at=datetime.fromisoformat(r["added_at"]),
                suggested_by_detection=r["suggested_by_detection"],
            )
            for r in rows
        ]

    def add_entry(self, entry: BlocklistEntry) -> None:
        conn = self.db.get_connection()
        with conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO blocklist (
                    ip, reason, confidence, added_at, suggested_by_detection
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    entry.ip,
                    entry.reason,
                    entry.confidence,
                    entry.added_at.isoformat(),
                    entry.suggested_by_detection,
                ),
            )

    def remove_entry(self, ip: str) -> bool:
        conn = self.db.get_connection()
        with conn:
            cur = conn.execute("DELETE FROM blocklist WHERE ip = ?", (ip,))
            return cur.rowcount > 0

    def is_blocked(self, ip: str) -> bool:
        if not ip:
            return False
        conn = self.db.get_connection()
        row = conn.execute(
            "SELECT 1 FROM blocklist WHERE ip = ?", (ip.strip(),)
        ).fetchone()
        return bool(row)


class SettingsRepo:
    """Repository for key-value application settings."""

    def __init__(self, db: Database):
        self.db = db

    def get(self, key: str, default: str | None = None) -> str | None:
        conn = self.db.get_connection()
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return str(row["value"]) if row else default

    def set(self, key: str, value: str) -> None:
        conn = self.db.get_connection()
        with conn:
            conn.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                (key, str(value)),
            )
