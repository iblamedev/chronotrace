"""SQLite local database manager and schema migrations.

ThreatDesk is an offline native SOC workstation storing:
- sessions: analysis session history and aggregate counts
- events: parsed and normalized log lines (prunable/paginated)
- rules: detection rules (seeded from default_rules, custom rules persisted)
- alerts: prioritized detections promoted to dispositionable alerts
- iocs: local threat intelligence indicators
- blocklist: tracked suspicious/malicious source IPs
- settings: key/value configuration settings
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent.parent / "chronotrace.db"


class Database:
    def __init__(self, db_path: Path | str | None = None):
        self.db_path = Path(db_path) if db_path else DEFAULT_DB_PATH
        self._conn: sqlite3.Connection | None = None
        self.init_schema()

    def get_connection(self) -> sqlite3.Connection:
        if self._conn is None:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(
                str(self.db_path),
                check_same_thread=False,
                detect_types=sqlite3.PARSE_DECLTYPES,
            )
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA foreign_keys = ON")
            self._conn.execute("PRAGMA journal_mode = WAL")
        return self._conn

    def init_schema(self) -> None:
        """Create tables and indexes if they do not exist."""
        conn = self.get_connection()
        with conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    source_files TEXT NOT NULL,
                    total_events INTEGER DEFAULT 0,
                    total_detections INTEGER DEFAULT 0,
                    severity_counts_json TEXT DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    line_number INTEGER NOT NULL,
                    raw_line TEXT NOT NULL,
                    source_file TEXT NOT NULL,
                    timestamp TEXT,
                    source_ip TEXT,
                    status_code TEXT,
                    request TEXT,
                    normalized_request TEXT,
                    user_agent TEXT,
                    username TEXT,
                    path TEXT,
                    parser_used TEXT,
                    parse_quality TEXT,
                    FOREIGN KEY(session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
                CREATE INDEX IF NOT EXISTS idx_events_ip ON events(source_ip);

                CREATE TABLE IF NOT EXISTS rules (
                    rule_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    category TEXT NOT NULL,
                    description TEXT NOT NULL,
                    pattern TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence INTEGER NOT NULL DEFAULT 80,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    tags TEXT DEFAULT '',
                    recommendation TEXT DEFAULT '',
                    is_builtin INTEGER NOT NULL DEFAULT 0,
                    method TEXT NOT NULL DEFAULT 'signature'
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    event_id INTEGER,
                    rule_id TEXT NOT NULL,
                    rule_name TEXT NOT NULL,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence INTEGER NOT NULL,
                    method TEXT NOT NULL,
                    matched_snippet TEXT NOT NULL,
                    recommendation TEXT DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'new',
                    notes TEXT DEFAULT '',
                    created_at TEXT NOT NULL,
                    source_ip TEXT,
                    FOREIGN KEY(session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_alerts_session ON alerts(session_id);
                CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
                CREATE INDEX IF NOT EXISTS idx_alerts_ip ON alerts(source_ip);

                CREATE TABLE IF NOT EXISTS iocs (
                    ioc_id TEXT PRIMARY KEY,
                    indicator TEXT UNIQUE NOT NULL,
                    ioc_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence INTEGER NOT NULL,
                    source TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    notes TEXT DEFAULT '',
                    tags TEXT DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_iocs_indicator ON iocs(indicator);

                CREATE TABLE IF NOT EXISTS blocklist (
                    ip TEXT PRIMARY KEY,
                    reason TEXT NOT NULL,
                    confidence INTEGER NOT NULL DEFAULT 80,
                    added_at TEXT NOT NULL,
                    suggested_by_detection TEXT
                );

                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )
            self._seed_default_rules(conn)
            self._seed_demo_intelligence(conn)

    def _seed_default_rules(self, conn: sqlite3.Connection) -> None:
        """Seed built-in rules into database without overwriting user customizations."""
        from app.rules.default_rules import get_default_rules

        default_rules = get_default_rules()
        for r in default_rules:
            # Only insert if rule_id does not already exist
            conn.execute(
                """
                INSERT OR IGNORE INTO rules (
                    rule_id, name, category, description, pattern, severity,
                    confidence, enabled, tags, recommendation, is_builtin, method
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
                """,
                (
                    r.rule_id,
                    r.name,
                    r.category.value,
                    r.description,
                    r.pattern,
                    r.severity.value,
                    r.confidence,
                    1 if r.enabled else 0,
                    ",".join(r.tags),
                    r.recommendation,
                    r.method.value,
                ),
            )

    def _seed_demo_intelligence(self, conn: sqlite3.Connection) -> None:
        """Add offline sample intelligence without replacing analyst records."""
        now = datetime.now(timezone.utc).isoformat()

        demo_iocs = (
            (
                "demo-ioc-ip-001",
                "198.51.100.23",
                "ip",
                "critical",
                96,
                "ChronoTrace Demo Feed",
                "Documentation-only TEST-NET source used to demonstrate IP correlation.",
                "demo,source-ip",
            ),
            (
                "demo-ioc-domain-001",
                "malware.example.com",
                "domain",
                "high",
                91,
                "ChronoTrace Demo Feed",
                "Reserved example domain representing a command-and-control hostname.",
                "demo,c2",
            ),
            (
                "demo-ioc-url-001",
                "https://phishing.example.invalid/login",
                "url",
                "high",
                94,
                "ChronoTrace Demo Feed",
                "Reserved URL used to demonstrate suspicious request matching.",
                "demo,phishing",
            ),
            (
                "demo-ioc-hash-001",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "hash",
                "medium",
                88,
                "ChronoTrace Demo Feed",
                "Synthetic SHA-256 value for local IOC workflow testing.",
                "demo,sha256",
            ),
            (
                "demo-ioc-ua-001",
                "DemoScanner/1.0",
                "user_agent",
                "medium",
                82,
                "ChronoTrace Demo Feed",
                "Synthetic scanner user-agent for event enrichment demonstrations.",
                "demo,recon",
            ),
            (
                "snapshot-tweetfeed-ip-001",
                "203.0.113.19",
                "ip",
                "high",
                90,
                "TweetFeed snapshot",
                "Bundled offline snapshot of the JSON feed shape from the supplied ingester.",
                "snapshot,tweetfeed",
            ),
            (
                "snapshot-urlhaus-url-001",
                "https://dropper.example.invalid/update.bin",
                "url",
                "critical",
                97,
                "URLHaus snapshot",
                "Bundled offline snapshot of the CSV feed shape from the supplied ingester.",
                "snapshot,urlhaus,malware",
            ),
            (
                "snapshot-urlhaus-domain-001",
                "cdn-payload.example.invalid",
                "domain",
                "high",
                92,
                "URLHaus snapshot",
                "Synthetic host extracted from the local feed snapshot for search and filtering demos.",
                "snapshot,urlhaus",
            ),
            (
                "snapshot-unit42-hash-001",
                "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
                "hash",
                "high",
                95,
                "Unit 42 Timely Intel snapshot",
                "Bundled offline snapshot of the key-value IOC format handled by the supplied ingester.",
                "snapshot,unit42,sha256",
            ),
            (
                "snapshot-unit42-domain-001",
                "c2-lab.example.invalid",
                "domain",
                "critical",
                98,
                "Unit 42 Timely Intel snapshot",
                "Synthetic command-and-control hostname for local correlation demonstrations.",
                "snapshot,unit42,c2",
            ),
        )
        for row in demo_iocs:
            conn.execute(
                """
                INSERT OR IGNORE INTO iocs (
                    ioc_id, indicator, ioc_type, severity, confidence, source,
                    first_seen, last_seen, notes, tags
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (*row[:6], now, now, row[6], row[7]),
            )

        demo_watchlist = (
            (
                "198.51.100.23",
                "Repeated SQL injection and credential probing in demo telemetry.",
                96,
                "demo-watch-001",
            ),
            (
                "203.0.113.45",
                "Command-injection source retained for analyst triage demonstration.",
                93,
                "demo-watch-002",
            ),
            (
                "192.0.2.77",
                "High-volume reconnaissance and path traversal activity.",
                89,
                "demo-watch-003",
            ),
            (
                "203.0.113.88",
                "Repeated failed authentication events across protected endpoints.",
                86,
                "demo-watch-004",
            ),
        )
        for ip, reason, confidence, suggested_by_detection in demo_watchlist:
            conn.execute(
                """
                INSERT OR IGNORE INTO blocklist (
                    ip, reason, confidence, added_at, suggested_by_detection
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (ip, reason, confidence, now, suggested_by_detection),
            )

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None
