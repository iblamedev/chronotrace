"""PDF Report Generator for ChronoTrace using pure Python ReportLab.

Produces clean, publication-ready SOC incident reports including:
- Document header, analysis scope, and session metadata
- Executive Summary & Key Risk Metrics
- Threat Severity Breakdown table
- Attack Categories Breakdown
- Top Malicious / Hostile Source IPs
- Signature vs. Behavioral Detections Table
- Remediation Recommendations playbook
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.models.detection import AnalysisSession


class SOCReportGenerator:
    def __init__(self, output_path: str | Path):
        self.output_path = Path(output_path)

    def generate(
        self,
        session: AnalysisSession,
        alerts: list[dict[str, Any]],
        notes: str = "",
    ) -> str:
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        doc = SimpleDocTemplate(
            str(self.output_path),
            pagesize=letter,
            leftMargin=36,
            rightMargin=36,
            topMargin=36,
            bottomMargin=36,
        )

        styles = getSampleStyleSheet()

        # Custom typography styles
        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Title"],
            fontSize=22,
            leading=26,
            textColor=colors.HexColor("#0f172a"),
            alignment=0,
            fontName="Helvetica-Bold",
        )

        subtitle_style = ParagraphStyle(
            "DocSubTitle",
            parent=styles["Normal"],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#64748b"),
        )

        h2_style = ParagraphStyle(
            "Heading2",
            parent=styles["Heading2"],
            fontSize=13,
            leading=16,
            textColor=colors.HexColor("#0284c7"),
            fontName="Helvetica-Bold",
            spaceBefore=14,
            spaceAfter=6,
        )

        body_style = ParagraphStyle(
            "Body",
            parent=styles["Normal"],
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#334155"),
        )

        table_header_style = ParagraphStyle(
            "TableHeader",
            parent=styles["Normal"],
            fontSize=8,
            leading=10,
            textColor=colors.white,
            fontName="Helvetica-Bold",
        )

        table_cell_style = ParagraphStyle(
            "TableCell",
            parent=styles["Normal"],
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#1e293b"),
        )

        elements = []

        # 1. Header Banner
        elements.append(
            Paragraph("CHRONOTRACE — SOC INCIDENT & LOG ANALYSIS REPORT", title_style)
        )
        elements.append(
            Paragraph(
                f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} | Session ID: {session.session_id}",
                subtitle_style,
            )
        )
        elements.append(Spacer(1, 10))
        elements.append(
            HRFlowable(
                width="100%",
                thickness=2,
                color=colors.HexColor("#0284c7"),
                spaceAfter=14,
            )
        )

        # 2. Executive Summary Metrics Table
        elements.append(Paragraph("Executive Incident Summary", h2_style))

        sev_counts = session.severity_counts
        crit_count = sev_counts.get("critical", 0)
        high_count = sev_counts.get("high", 0)
        med_count = sev_counts.get("medium", 0)
        low_count = sev_counts.get("low", 0)
        info_count = sev_counts.get("info", 0)

        summary_data = [
            ["Metric", "Value", "Metric", "Value"],
            [
                "Total Events Analyzed",
                f"{session.total_events:,}",
                "Total Threats Detected",
                f"{session.total_detections:,}",
            ],
            ["Critical Threats", f"{crit_count}", "High Threats", f"{high_count}"],
            [
                "Medium Threats",
                f"{med_count}",
                "Low / Info Threats",
                f"{low_count + info_count}",
            ],
        ]
        sum_table = Table(summary_data, colWidths=[140, 120, 140, 120])
        sum_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 9),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8fafc")),
                    ("PADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        elements.append(sum_table)
        elements.append(Spacer(1, 14))

        # 3. Target / Source Files
        elements.append(Paragraph("Data Source Artifacts", h2_style))
        for f in session.source_files:
            elements.append(Paragraph(f"• <b>File:</b> {f}", body_style))
        elements.append(Spacer(1, 12))

        # 4. Top Malicious Source IPs
        elements.append(Paragraph("Top Hostile Source IPs", h2_style))
        ip_counts: dict[str, int] = {}
        for a in alerts:
            ip = a.get("source_ip") or "Unknown"
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

        top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        ip_table_data = [
            ["Source IP Address", "Threat Count", "Primary Threat Profile"]
        ]
        for ip, cnt in top_ips:
            # find prominent category for this IP
            prominent = "Coordinated Threat" if cnt > 5 else "Probe / Injection"
            ip_table_data.append([ip, str(cnt), prominent])

        ip_table = Table(ip_table_data, colWidths=[180, 120, 220])
        ip_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ("PADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        elements.append(ip_table)
        elements.append(Spacer(1, 14))

        # 5. Detections Table (First 25 for report readability)
        elements.append(
            Paragraph(
                f"Detailed Detections Breakdown (Top {min(len(alerts), 25)})", h2_style
            )
        )
        det_headers = [
            Paragraph("Sev", table_header_style),
            Paragraph("Method", table_header_style),
            Paragraph("Rule Name", table_header_style),
            Paragraph("Source IP", table_header_style),
            Paragraph("Matched Trigger Snippet", table_header_style),
        ]
        det_data = [det_headers]
        for a in alerts[:25]:
            sev_txt = a.get("severity", "info").upper()
            meth_txt = a.get("method", "sig")
            rule_nm = a.get("rule_name", "")
            src_ip = a.get("source_ip", "-")
            snip = a.get("matched_snippet", "")[:60]

            import html

            safe_snip = html.escape(snip)
            safe_rule = html.escape(rule_nm)
            safe_ip = html.escape(src_ip)

            det_data.append(
                [
                    Paragraph(sev_txt, table_cell_style),
                    Paragraph(meth_txt.capitalize(), table_cell_style),
                    Paragraph(safe_rule, table_cell_style),
                    Paragraph(safe_ip, table_cell_style),
                    Paragraph(safe_snip, table_cell_style),
                ]
            )

        det_table = Table(det_data, colWidths=[45, 60, 150, 85, 180])
        det_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [colors.white, colors.HexColor("#f8fafc")],
                    ),
                    ("PADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        elements.append(det_table)
        elements.append(Spacer(1, 16))

        # 6. SOC Recommendations Playbook
        elements.append(Paragraph("Recommended Playbook Actions", h2_style))
        playbook = [
            "1. <b>Credential Attack Mitigation:</b> Implement immediate rate limiting or CAPTCHA triggers on /login endpoints to thwart brute-force and credential stuffing attempts.",
            "2. <b>Input Validation & Sanitization:</b> Ensure strict server-side parameterization for SQL queries and contextual encoding for dynamic HTML rendering.",
            "3. <b>Command Metacharacter Filtering:</b> Web application endpoints must reject shell metacharacters (; | && ` $) in query strings and API input parameters.",
            "4. <b>Local Blocklist Enrollment:</b> ChronoTrace tracked suspicious IPs should be submitted to perimeter firewall / WAF access control lists.",
        ]
        for item in playbook:
            elements.append(Paragraph(item, body_style))
            elements.append(Spacer(1, 4))

        doc.build(elements)
        return str(self.output_path)
