# ChronoTrace — Native Enterprise SOC Workstation

ChronoTrace is an **offline, native desktop SOC threat detection and forensic log analysis workstation** built with Python 3.14, PySide6 (Qt 6.10), SQLite, and ReportLab. It combines high-density security telemetry with an Apple/Linear/Raycast aesthetic, featuring a semantic dual-theme token system (`Graphite` dark / `Paper` light), real-time forensic parsing, payload normalization, multi-signature regex matching, windowed behavioral correlation, local threat intelligence lookups, and publication-ready PDF reporting.

---

## Core Principles & Architectural Assurances

- **100% Offline & Air-Gapped**: Zero outbound network requests. All rule compilation, behavioral correlation, and PDF generation execute strictly on the local machine.
- **Defensive & Non-Executable**: Log contents are treated as untrusted, inert text strings. Shell payloads, scripts, URLs, and commands are strictly non-executable.
- **Forensic Preservation**: Original raw lines are permanently preserved verbatim alongside multi-pass normalized decoded requests.
- **Signature vs. Behavioral Duality**: Single-line signature detections (`cyan` / `accent`) and multi-event behavioral correlations (`violet`) are visually and structurally differentiated throughout the UI, database schema, and PDF reports.
- **Dual Semantic Design System**: Two first-class theme modes:
  - **Graphite (Dark)**: Deep slate backgrounds (`#12151a`), crisp hairlines, and restrained luminosity.
  - **Paper (Light)**: Warm off-white surfaces (`#fcfbf9`), high-contrast Swiss typography, and clean contrast ratios.
- **Keyboard-Driven Workstation**:
  - `Ctrl + K`: Raycast-style floating fuzzy command palette.
  - `Ctrl + Shift + L`: Instant dark/light theme toggle.
  - `Ctrl + 0` through `Ctrl + 9`: Rapid page switching.

---

## Key Modules & Capabilities

1. **SOC Analyst Threat Dashboard (`app/ui/dashboard.py`)**:
   - `SectionHeader` with instant session overview and quick actions (`Load Demo Logs`, `Import Log Files`).
   - `MetricRow` hosting 5 `MetricCard` instances with animated counters (`Total Events`, `Total Threats`, `Critical Threats`, `Hostile IPs`, `Behavioral Patterns`).
   - Dual transparent QtCharts panels (`Threat Severity Distribution` donut with 0.58 inner hole and `Top Attack Vectors` bar chart) integrated via `chart_palette()`.
   - High & Critical Priority Threat Stream table housed in a flush `TableCard` using `AnalysisTable`, `SeverityBadge`, and `MethodChip`.

2. **Forensic Event Inspector (`app/ui/widgets/event_inspector.py`)**:
   - Modal dialog subclassing `AppDialog` across 7 forensic inspection sections:
     1. Ingestion Metadata & Parser Fidelity (`Full`, `Partial`, `Unparsed`).
     2. Network & Protocol Fields (Source IP, Port, HTTP Method, URI, Status Code, User-Agent, Identity).
     3. Verbatim Preserved Raw Log Line (Read-only monospace forensic evidence).
     4. Normalized & Decoded Payload (Multi-pass unescaped, URL/hex/unicode decoded).
     5. Detection Logic & Trigger Condition (Exact regex pattern, trigger snippet, correlation context).
     6. Air-Gapped Local IOC Cross-Reference (Live query against internal IOC & blocklist repositories).
     7. Analyst Remediation Guidance (Structured playbook recommendations).
   - Footer action bar: `Add IP to Watchlist`, `Copy Raw Line`, and `Close Inspector`.

3. **Security Alerts Ledger (`app/ui/alerts_view.py`)**:
   - Filter bar: Multi-attribute filtering by Severity, Method (Signature vs Behavioral), Status (New, Acknowledged, Resolved), and free-text search.
   - Flush `TableCard` hosting `AnalysisTable` with inline severity rails and action buttons.
   - Real-time toast notifications on alert disposition updates and blocklist enrollments.

4. **Log Ingestion Workstation (`app/ui/logs_view.py`)**:
   - Multi-file drag-and-drop and native file browsing.
   - High-throughput paginated `AnalysisTable` with parse quality indicators and rapid search.

5. **Detection Rule Engine & Regex Sandbox (`app/ui/rules_view.py`)**:
   - Catalog of 23 built-in rules covering SQLi, XSS, Command Injection, LFI/RFI, SSRF, Traversal, and Recon.
   - `RuleEditorDialog` for creating and editing custom detection rules with on-the-fly regex syntax validation.
   - Live Regex Sandbox & Match Simulator for testing regex patterns against raw payloads safely.
   - JSON export and import capabilities.

6. **Behavioral Correlation Engine (`app/core/correlator.py`)**:
   - Multi-event sliding window correlation per host entity:
     - **Brute-Force / Credential Stuffing**: >= 3 failed logins within window (CRITICAL).
     - **Scanner / Enumeration Activity**: Rapid 4xx/5xx or recon probing (MEDIUM-HIGH).
     - **Multi-Signature Hostile Source**: >= 3 distinct attack categories triggered by one IP (HIGH).

7. **Threat Intelligence & Local IOC Store (`app/ui/ioc_view.py`)**:
   - Local indicator store for IPs, Domains, URLs, Hashes, and User-Agents.
   - CSV/JSON bulk import and export with live traffic correlation.

8. **Hostile IP Watchlist (`app/ui/watchlist_view.py`)**:
   - Analyst defensive tracking with confidence ratings and forensic reasoning.

9. **Real-Time File Tail Stream (`app/ui/live_monitor.py`)**:
   - Background worker thread tailing log files with zero UI latency.
   - Breathing `PulseIndicator` dot with synchronized live status badges and floating toasts.

10. **Executive & Technical PDF Reports (`app/ui/reports_view.py`, `app/core/report_generator.py`)**:
    - Publication-quality vector PDF reports generated via ReportLab with executive incident summaries, severity metrics, and remediation playbooks.

11. **System Settings & Preferences (`app/ui/settings_view.py`)**:
    - `SegmentedControl` visual theme switcher (`Graphite` vs `Paper`).
    - SQLite database health statistics, table record counts, and database vacuum maintenance.

12. **Project Information & Team Roles (`app/ui/project_info_view.py`)**:
    - Swiss-editorial overview of project specifications, contributor responsibilities, and air-gapped system architecture.

---

## Installation & Usage

### 1. Requirements
Ensure Python 3.12+ (tested up to Python 3.14) is installed. Install dependencies:
```bash
pip install -r requirements.txt
```
*(Core dependencies: `PySide6`, `reportlab`, `pyinstaller`, `pillow`, `ruff`)*

### 2. Launching ThreatDesk
Run the native desktop application:
```bash
python -m app.main
```

### 3. Quick Demo Walkthrough
- Click **"Load Demo Logs"** from the top right of the **Dashboard** or **Log Ingestion** screen.
- ThreatDesk immediately ingests `sample_data/attacks.log` and `sample_data/login-logs.txt`, runs signature and behavioral correlation engines, updates all KPI counters, renders QtCharts, and populates the alerts ledger.
- Double-click any row in the threat stream to inspect the full forensic evidence drawer.
- Press `Ctrl + Shift + L` to experience the seamless transition between the **Graphite** dark theme and **Paper** light theme.

---

## Verification & Automated Test Suite

Run the full automated test suite:
```bash
# 1. Comprehensive Unit & Pipeline Test Suite
python -m unittest tests/test_suite.py

# 2. Phase 2 End-to-End Pipeline & DB Persistence
python tests/test_phase2.py

# 3. ReportLab PDF Generation Verification
python tests/test_report.py

# 4. 50,000-Line Performance Benchmark
python tests/test_performance.py

# 5. Code Quality & Lint Validation
python -m ruff check app tests
```

---

## Standalone Native Build (PyInstaller)

To compile a standalone Windows executable with embedded icons, fonts, and assets:
```powershell
python -m PyInstaller --clean threatdesk.spec
```
The compiled native executable will be located at:
`dist/ThreatDesk/ThreatDesk.exe`
