"""Project Information, Team Roles & Architecture Overview View.

Quiet, editorial typography without bracket decorations:
- Apple/Linear/Raycast aesthetic
- Semantic tokens from app.ui.theme
- Cards and SectionHeaders
- Minimalist brand emblem integration
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from app.ui.theme import GUTTER, SPACE, TOKENS
from app.ui.widgets.surfaces import Card, SectionHeader


class ProjectInfoView(QWidget):
    """View dedicated to project specifications, team roles, and architecture."""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)

        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(
            GUTTER["view"], GUTTER["view_top"], GUTTER["view"], GUTTER["view_bottom"]
        )
        layout.setSpacing(SPACE["lg"])

        # 1. Header with Logo & App Info Card
        header_card = Card(variant="primary", parent=container)
        h_lay = QHBoxLayout()
        h_lay.setContentsMargins(0, 0, 0, 0)
        h_lay.setSpacing(SPACE["xl"])

        logo_lbl = QLabel()
        logo_path = Path(__file__).resolve().parent.parent / "assets" / "logo.png"
        if logo_path.exists():
            pixmap = QPixmap(str(logo_path)).scaled(
                128, 128, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation
            )
            pixmap.setDevicePixelRatio(2.0)
            logo_lbl.setPixmap(pixmap)
        h_lay.addWidget(logo_lbl, 0, Qt.AlignmentFlag.AlignTop)

        title_box = QVBoxLayout()
        title_box.setSpacing(SPACE["xxs"])

        t_eyebrow = QLabel("ENTERPRISE SOC WORKSTATION", header_card)
        t_eyebrow.setProperty("role", "label")
        title_box.addWidget(t_eyebrow)

        t_main = QLabel("ChronoTrace", header_card)
        t_main.setProperty("role", "display")
        title_box.addWidget(t_main)

        t_sub = QLabel(
            "Native Offline Log Threat Detection, Multi-Signature Matching & Behavioral Correlation",
            header_card,
        )
        t_sub.setProperty("role", "subheading")
        t_sub.setStyleSheet(f"color: {TOKENS['accent']};")
        title_box.addWidget(t_sub)

        t_ver = QLabel(
            "Version 2.1.0 Production Release · Air-Gapped Defensive Architecture · Windows x64 Native",
            header_card,
        )
        t_ver.setProperty("role", "secondary")
        title_box.addWidget(t_ver)

        h_lay.addLayout(title_box, 1)
        header_card.body().addLayout(h_lay)
        layout.addWidget(header_card)

        # 2. Team Roles Card
        team_card = Card(
            title="Project Team & Roles",
            subtitle="Contributor responsibilities for ChronoTrace",
            variant="primary",
            parent=container,
        )

        members = [
            {
                "role": "Lead Architect & Security Operations Engineering",
            },
            {
                "role": "Threat Detection Engine & Signature Rules",
            },
            {
                "role": "Behavioral Correlation & Threat Intelligence",
            },
            {
                "role": "Security Analysis & Incident Reporting",
            },
            {
                "role": "Forensic Inspection & Workstation Infrastructure",
            },
        ]

        for m in members:
            m_card = Card(variant="inset", parent=team_card)
            m_head = SectionHeader(
                title=m["role"],
                caption="Project contributor",
                trailing=None,
            )
            m_card.body().addWidget(m_head)
            team_card.body().addWidget(m_card)

        layout.addWidget(team_card)

        # 3. Technical Architecture Card
        specs_card = Card(
            title="System Specifications & Defensive Assurances",
            subtitle="Core operational properties and air-gapped architectural safeguards",
            variant="inset",
            parent=container,
        )

        specs_text = QLabel(
            "• <b>Offline Native GUI:</b> PySide6 (Qt 6.10) with custom semantic dual-theme token styling (zero Electron/Chromium runtime overhead).<br>"
            "• <b>Dual Detection Engines:</b> Fast single-line regex signature scanner (accent) plus windowed multi-event behavioral correlator (violet).<br>"
            "• <b>Inert Execution Barrier:</b> All log payloads, URLs, and scripts are treated as untrusted strings — strictly non-executable.<br>"
            "• <b>Persistent Storage:</b> Zero-configuration embedded SQLite database with indexed lookups and transactional safety.<br>"
            "• <b>Incident Reporting:</b> High-fidelity vector PDF generation via ReportLab with executive metrics and remediation guidelines.<br>"
            "• <b>Platform Packaging:</b> Standalone native Windows binary packaged via PyInstaller."
        )
        specs_text.setProperty("role", "body")
        specs_text.setStyleSheet(
            f"color: {TOKENS['text_secondary']}; line-height: 1.7; padding: 4px 0;"
        )
        specs_text.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        specs_card.body().addWidget(specs_text)

        layout.addWidget(specs_card)
        layout.addStretch(1)

        scroll.setWidget(container)

        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.addWidget(scroll)
