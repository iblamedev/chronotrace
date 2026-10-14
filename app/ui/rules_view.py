"""Rule management view for ThreatDesk.

Features:
- List all built-in and custom rules with tags, category, severity
- Enable/disable toggle (persisted via RuleRepo)
- Add/edit/delete custom detection rules using AppDialog-backed RuleEditorDialog
- Live Regex Sandbox: test any regex against user-provided sample text with instant feedback
- Import/Export rules as JSON
- TableCard & AnalysisTable with SeverityBadge, MethodChip, mono_item, text_item
"""

from __future__ import annotations

import json
import re
import uuid

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from app.models.rule import DetectionMethod, DetectionRule, RuleCategory, Severity
from app.storage.repositories import RuleRepo
from app.ui.theme import GUTTER, SPACE, TOKENS
from app.ui.widgets.animated_button import TactileButton
from app.ui.widgets.app_dialog import AppDialog, Section
from app.ui.widgets.interactive_table import (
    AnalysisTable,
    TableCard,
    mono_item,
    text_item,
)
from app.ui.widgets.severity_badge import SeverityBadge
from app.ui.widgets.surfaces import Card, SectionHeader
from app.ui.widgets.toast_notification import ToastHost


class RuleEditorDialog(AppDialog):
    """Rule configuration modal built on AppDialog."""

    def __init__(
        self, rule: DetectionRule | None = None, parent: QWidget | None = None
    ):
        super().__init__(
            title="Edit Detection Rule" if rule else "Create Custom Detection Rule",
            eyebrow="DETECTION RULE ENGINE",
            meta="Define pattern matching logic and severity scoring for incoming log telemetry",
            severity=rule.severity.value if rule else "high",
            width=620,
            height=540,
            parent=parent,
        )
        self.rule = rule

        body = self.body_layout()

        sec = Section(
            title="Rule Metadata & Scoring",
            caption="Rule naming, taxonomy category, and alert severity",
            tone="accent",
        )

        sec.add(QLabel("Rule Name:"))
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("e.g. Blind SQL Injection Pattern")
        self.name_input.setText(rule.name if rule else "")
        sec.add(self.name_input)

        sec.add(QLabel("Taxonomy Category:"))
        self.cat_combo = QComboBox()
        for c in RuleCategory:
            self.cat_combo.addItem(c.value)
        if rule:
            self.cat_combo.setCurrentText(
                rule.category.value
                if isinstance(rule.category, RuleCategory)
                else str(rule.category)
            )
        sec.add(self.cat_combo)

        row_meta = QHBoxLayout()
        row_meta.setSpacing(SPACE["md"])

        col_sev = QVBoxLayout()
        col_sev.addWidget(QLabel("Assigned Severity:"))
        self.sev_combo = QComboBox()
        for s in Severity:
            self.sev_combo.addItem(s.value.upper())
        if rule:
            self.sev_combo.setCurrentText(rule.severity.value.upper())
        col_sev.addWidget(self.sev_combo)
        row_meta.addLayout(col_sev, 1)

        col_conf = QVBoxLayout()
        col_conf.addWidget(QLabel("Confidence Rating (0-100%):"))
        self.conf_spin = QSpinBox()
        self.conf_spin.setRange(1, 100)
        self.conf_spin.setValue(rule.confidence if rule else 85)
        col_conf.addWidget(self.conf_spin)
        row_meta.addLayout(col_conf, 1)

        sec.body().addLayout(row_meta)
        body.addWidget(sec)

        # Pattern & Remediation Section
        sec_pat = Section(
            title="Pattern & Remediation Guidance",
            caption="Regular expression pattern compiled against untrusted log requests",
            variant="inset",
            tone="violet",
        )

        sec_pat.add(QLabel("Regex Pattern (Case-insensitive):"))
        self.pattern_input = QLineEdit()
        self.pattern_input.setProperty("role", "mono")
        self.pattern_input.setPlaceholderText("e.g. (?:union\\s+select|information_schema)")
        self.pattern_input.setText(rule.pattern if rule else "")
        sec_pat.add(self.pattern_input)

        sec_pat.add(QLabel("Rule Description:"))
        self.desc_input = QLineEdit()
        self.desc_input.setPlaceholderText("Context on what this threat signature signifies")
        self.desc_input.setText(rule.description if rule else "")
        sec_pat.add(self.desc_input)

        sec_pat.add(QLabel("Recommended Remediation Action:"))
        self.rec_input = QLineEdit()
        self.rec_input.setPlaceholderText("SOC action step when this alert fires")
        self.rec_input.setText(rule.recommendation if rule else "")
        sec_pat.add(self.rec_input)

        body.addWidget(sec_pat)

        # Footer
        self.btn_cancel = TactileButton("Cancel", appearance="default")
        self.btn_cancel.clicked.connect(self.reject)

        self.btn_save = TactileButton("Save Rule", appearance="primary")
        self.btn_save.clicked.connect(self._validate_and_save)

        self.add_footer_action(self.btn_cancel)
        self.add_footer_action(self.btn_save)

    def _validate_and_save(self) -> None:
        pattern = self.pattern_input.text().strip()
        if not pattern:
            ToastHost.instance().show_toast(
                "Regex pattern cannot be empty.",
                title="Validation Error",
                severity="warning",
            )
            return

        try:
            re.compile(pattern)
        except re.error as err:
            ToastHost.instance().show_toast(
                f"Invalid regex syntax: {err}",
                title="Compilation Error",
                severity="error",
            )
            return

        rule_id = self.rule.rule_id if self.rule else f"custom-{uuid.uuid4().hex[:6]}"
        is_builtin = self.rule.is_builtin if self.rule else False

        self.rule = DetectionRule(
            rule_id=rule_id,
            name=self.name_input.text().strip() or "Custom Rule",
            category=RuleCategory(self.cat_combo.currentText()),
            description=self.desc_input.text().strip(),
            pattern=pattern,
            severity=Severity(self.sev_combo.currentText().lower()),
            confidence=self.conf_spin.value(),
            enabled=self.rule.enabled if self.rule else True,
            tags=("custom",),
            recommendation=self.rec_input.text().strip(),
            is_builtin=is_builtin,
            method=DetectionMethod.SIGNATURE,
        )
        self.accept()


class RulesView(QWidget):
    rules_changed = Signal()

    def __init__(self, rule_repo: RuleRepo, parent: QWidget | None = None):
        super().__init__(parent)
        self.rule_repo = rule_repo
        self.rules: list[DetectionRule] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(
            GUTTER["view"], GUTTER["view_top"], GUTTER["view"], GUTTER["view_bottom"]
        )
        layout.setSpacing(SPACE["md"])

        # 1. Header with action buttons
        self.header = SectionHeader(
            title="Detection Rule Management & Testing",
            caption="Manage signature rules, test custom regex in the live sandbox, or import/export rules",
        )

        self.btn_export = TactileButton("Export JSON", appearance="default")
        self.btn_export.clicked.connect(self._export_rules)

        self.btn_import = TactileButton("Import JSON", appearance="default")
        self.btn_import.clicked.connect(self._import_rules)

        self.btn_add = TactileButton("+ New Custom Rule", appearance="primary")
        self.btn_add.clicked.connect(self._add_rule)

        self.header.layout().addWidget(self.btn_export)
        self.header.layout().addWidget(self.btn_import)
        self.header.layout().addWidget(self.btn_add)
        layout.addWidget(self.header)

        # 2. Rules TableCard & AnalysisTable
        self.table_card = TableCard(
            title="Rule Catalog",
            caption="Active detection signatures evaluated during real-time and batch log ingestion",
            parent=self,
        )

        self.table = AnalysisTable(
            0,
            6,
            parent=self.table_card,
            severity_column=1,
            stretch_column=5,
        )
        self.table.setHorizontalHeaderLabels(
            ["Enabled", "Severity", "Rule Name", "Category", "Origin", "Regex Pattern"]
        )
        self.table.setColumnWidth(0, 80)
        self.table.setColumnWidth(1, 110)
        self.table.setColumnWidth(2, 240)
        self.table.setColumnWidth(3, 170)
        self.table.setColumnWidth(4, 100)
        self.table.horizontalHeader().setSectionResizeMode(
            5, QHeaderView.ResizeMode.Stretch
        )
        self.table.itemDoubleClicked.connect(self._on_table_double_clicked)
        self.table.row_activated.connect(self._on_table_row_activated)

        self.table_card.attach_table(self.table)
        layout.addWidget(self.table_card, 2)

        # 3. Table Action Row
        tbl_actions = QHBoxLayout()
        tbl_actions.setContentsMargins(0, 0, 0, 0)
        tbl_actions.setSpacing(SPACE["sm"])

        self.btn_edit = TactileButton("Edit Rule", appearance="default")
        self.btn_edit.clicked.connect(self._edit_selected_rule)
        tbl_actions.addWidget(self.btn_edit)

        self.btn_del = TactileButton("Delete Custom Rule", appearance="danger")
        self.btn_del.clicked.connect(self._delete_selected_rule)
        tbl_actions.addWidget(self.btn_del)

        tbl_actions.addStretch(1)
        layout.addLayout(tbl_actions)

        # 4. Live Regex Sandbox inside Inset Card
        sandbox_card = Card(
            title="Live Regex Sandbox & Match Simulator",
            subtitle="Test regex patterns against sample log lines safely in an air-gapped sandbox",
            variant="inset",
            parent=self,
        )

        test_row = QHBoxLayout()
        test_row.setSpacing(SPACE["sm"])

        self.test_regex_input = QLineEdit()
        self.test_regex_input.setPlaceholderText(
            "Regex pattern to test (e.g. \\b(SELECT|UNION)\\b)..."
        )
        self.test_regex_input.setProperty("role", "mono")
        test_row.addWidget(self.test_regex_input, 3)

        self.btn_test = TactileButton("Run Test", appearance="primary")
        self.btn_test.clicked.connect(self._run_sandbox_test)
        test_row.addWidget(self.btn_test, 0)
        sandbox_card.body().addLayout(test_row)

        self.sample_text_input = QPlainTextEdit()
        self.sample_text_input.setPlaceholderText(
            "Paste sample log lines or payloads here to test match..."
        )
        self.sample_text_input.setMaximumHeight(75)
        self.sample_text_input.setProperty("role", "mono")
        sandbox_card.body().addWidget(self.sample_text_input)

        self.sandbox_result = QLabel("Result: Ready for pattern evaluation")
        self.sandbox_result.setProperty("role", "mono")
        self.sandbox_result.setStyleSheet(f"color: {TOKENS['text_secondary']};")
        sandbox_card.body().addWidget(self.sandbox_result)

        layout.addWidget(sandbox_card, 1)
        self.refresh()

    def refresh(self) -> None:
        self.rules = self.rule_repo.get_all_rules()
        self.table.setRowCount(len(self.rules))

        for row, r in enumerate(self.rules):
            # Col 0: Checkbox
            chk = QCheckBox()
            chk.setChecked(r.enabled)
            chk.stateChanged.connect(
                lambda state, rid=r.rule_id: self._toggle_rule(
                    rid, state == Qt.CheckState.Checked.value or state == Qt.CheckState.Checked
                )
            )
            chk_widget = QWidget()
            chk_widget.setProperty("card", "plain")
            chk_lay = QHBoxLayout(chk_widget)
            chk_lay.addWidget(chk)
            chk_lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
            chk_lay.setContentsMargins(0, 0, 0, 0)
            self.table.setCellWidget(row, 0, chk_widget)

            # Col 1: Severity Badge
            badge = SeverityBadge(r.severity, r.method)
            self.table.setCellWidget(row, 1, badge)

            # Col 2: Name
            n_item = text_item(r.name, color_token="text_primary")
            self.table.setItem(row, 2, n_item)

            # Col 3: Category
            c_val = r.category.value if isinstance(r.category, RuleCategory) else str(r.category)
            c_item = text_item(c_val, color_token="text_secondary")
            self.table.setItem(row, 3, c_item)

            # Col 4: Origin
            o_txt = "Built-in" if r.is_builtin else "Custom"
            o_item = text_item(o_txt, color_token="accent" if r.is_builtin else "violet")
            self.table.setItem(row, 4, o_item)

            # Col 5: Pattern
            p_item = mono_item(r.pattern, color_token="text_muted")
            self.table.setItem(row, 5, p_item)

    def _toggle_rule(self, rule_id: str, enabled: bool) -> None:
        self.rule_repo.set_enabled(rule_id, enabled)
        status_word = "enabled" if enabled else "disabled"
        ToastHost.instance().show_toast(
            f"Rule {rule_id} {status_word}.",
            title="Rule Updated",
            severity="info",
        )
        self.rules_changed.emit()

    def _add_rule(self) -> None:
        dlg = RuleEditorDialog(parent=self)
        if dlg.exec() and dlg.rule:
            self.rule_repo.save_rule(dlg.rule)
            ToastHost.instance().show_toast(
                f"Custom rule '{dlg.rule.name}' saved.",
                title="Rule Created",
                severity="success",
            )
            self.refresh()
            self.rules_changed.emit()

    def _edit_selected_rule(self) -> None:
        row = self.table.selected_row()
        if not (0 <= row < len(self.rules)):
            ToastHost.instance().show_toast(
                "Please select a rule from the table first.",
                title="No Rule Selected",
                severity="warning",
            )
            return
        rule = self.rules[row]
        dlg = RuleEditorDialog(rule=rule, parent=self)
        if dlg.exec() and dlg.rule:
            self.rule_repo.save_rule(dlg.rule)
            ToastHost.instance().show_toast(
                f"Rule '{dlg.rule.name}' updated.",
                title="Rule Updated",
                severity="success",
            )
            self.refresh()
            self.rules_changed.emit()

    def _delete_selected_rule(self) -> None:
        row = self.table.selected_row()
        if not (0 <= row < len(self.rules)):
            ToastHost.instance().show_toast(
                "Please select a custom rule from the table first.",
                title="No Rule Selected",
                severity="warning",
            )
            return
        rule = self.rules[row]
        if rule.is_builtin:
            ToastHost.instance().show_toast(
                "Built-in rules cannot be deleted; disable them instead.",
                title="Action Restricted",
                severity="warning",
            )
            return
        if (
            QMessageBox.question(
                self, "Delete Rule", f"Delete custom rule '{rule.name}'?"
            )
            == QMessageBox.StandardButton.Yes
        ):
            self.rule_repo.delete_rule(rule.rule_id)
            ToastHost.instance().show_toast(
                f"Rule '{rule.name}' deleted.",
                title="Rule Deleted",
                severity="info",
            )
            self.refresh()
            self.rules_changed.emit()

    def _on_table_double_clicked(self, item) -> None:
        self._load_to_sandbox(item.row())

    def _on_table_row_activated(self, row: int) -> None:
        self._load_to_sandbox(row)

    def _load_to_sandbox(self, row: int) -> None:
        if 0 <= row < len(self.rules):
            r = self.rules[row]
            self.test_regex_input.setText(r.pattern)
            ToastHost.instance().show_toast(
                f"Loaded '{r.name}' pattern into sandbox.",
                title="Pattern Loaded",
                severity="info",
            )

    def _run_sandbox_test(self) -> None:
        pat_str = self.test_regex_input.text().strip()
        sample = self.sample_text_input.toPlainText()

        if not pat_str:
            self.sandbox_result.setStyleSheet(f"color: {TOKENS['warning']};")
            self.sandbox_result.setText("Result: Pattern is empty.")
            return

        try:
            pattern = re.compile(pat_str, re.IGNORECASE)
            matches = list(pattern.finditer(sample))
            if matches:
                snippets = [f"'{m.group(0)}'" for m in matches[:5]]
                self.sandbox_result.setStyleSheet(f"color: {TOKENS['success']};")
                self.sandbox_result.setText(
                    f"MATCH FOUND ({len(matches)} hit(s)): {', '.join(snippets)}"
                )
            else:
                self.sandbox_result.setStyleSheet(f"color: {TOKENS['warning']};")
                self.sandbox_result.setText(
                    "NO MATCH: Regex did not match sample text."
                )
        except re.error as err:
            self.sandbox_result.setStyleSheet(f"color: {TOKENS['danger']};")
            self.sandbox_result.setText(f"REGEX ERROR: {err}")

    def _export_rules(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Rules JSON", "threatdesk_rules.json", "JSON Files (*.json)"
        )
        if not path:
            return
        data = [
            {
                "rule_id": r.rule_id,
                "name": r.name,
                "category": r.category.value
                if isinstance(r.category, RuleCategory)
                else str(r.category),
                "description": r.description,
                "pattern": r.pattern,
                "severity": r.severity.value,
                "confidence": r.confidence,
                "enabled": r.enabled,
                "tags": list(r.tags),
                "recommendation": r.recommendation,
                "is_builtin": r.is_builtin,
            }
            for r in self.rules
        ]
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        ToastHost.instance().show_toast(
            f"Exported {len(data)} rules to JSON.",
            title="Rules Exported",
            severity="success",
        )

    def _import_rules(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Import Rules JSON", "", "JSON Files (*.json)"
        )
        if not path:
            return
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        count = 0
        for item in data:
            cat_val = item.get("category", "Anomaly / Protocol")
            try:
                cat = RuleCategory(cat_val)
            except ValueError:
                cat = RuleCategory.ANOMALY

            r = DetectionRule(
                rule_id=item["rule_id"],
                name=item["name"],
                category=cat,
                description=item.get("description", ""),
                pattern=item["pattern"],
                severity=Severity(item.get("severity", "medium")),
                confidence=item.get("confidence", 80),
                enabled=item.get("enabled", True),
                tags=tuple(item.get("tags", ())),
                recommendation=item.get("recommendation", ""),
                is_builtin=item.get("is_builtin", False),
            )
            self.rule_repo.save_rule(r)
            count += 1

        self.refresh()
        self.rules_changed.emit()
        ToastHost.instance().show_toast(
            f"Successfully imported/updated {count} rules.",
            title="Rules Imported",
            severity="success",
        )

    def refresh_theme(self) -> None:
        """Re-render table rows and badges when theme changes."""
        self.table.refresh_theme()
        self.refresh()
