"""Main PySide6 desktop workbench."""

from __future__ import annotations

import html
import json
import sys
from pathlib import Path

from PySide6.QtCore import QThread, Qt, QUrl, Signal
from PySide6.QtGui import QColor, QDesktopServices
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QStatusBar,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from dfir_copilot.config import AppConfig
from dfir_copilot.database import Database
from dfir_copilot.models import SEVERITY_ORDER
from dfir_copilot.services.case_service import CaseService
from dfir_copilot.services.copilot import CopilotService
from dfir_copilot.services.demo import install_demo_case
from dfir_copilot.services.report import ReportService
from dfir_copilot.ui.theme import APP_STYLE


class AnalysisWorker(QThread):
    completed = Signal(int)
    failed = Signal(str)

    def __init__(self, service: CaseService, case_id: int):
        super().__init__()
        self.service = service
        self.case_id = case_id

    def run(self) -> None:
        try:
            self.completed.emit(self.service.analyze_case(self.case_id))
        except Exception as exc:  # UI boundary
            self.failed.emit(str(exc))


class CopilotWorker(QThread):
    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, service: CopilotService, case_id: int, question: str, use_cloud: bool):
        super().__init__()
        self.service = service
        self.case_id = case_id
        self.question = question
        self.use_cloud = use_cloud

    def run(self) -> None:
        try:
            self.completed.emit(self.service.ask(self.case_id, self.question, self.use_cloud))
        except Exception as exc:  # UI boundary
            self.failed.emit(str(exc))


class NewCaseDialog(QDialog):
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle("Create Investigation Case")
        self.setMinimumWidth(480)
        layout = QFormLayout(self)
        self.name = QLineEdit()
        self.name.setPlaceholderText("Example: Suspicious PowerShell Investigation")
        self.investigator = QLineEdit("Vasanth Kumar")
        self.description = QTextEdit()
        self.description.setMaximumHeight(110)
        self.description.setPlaceholderText("Scope, source, and investigation objective")
        layout.addRow("Case name", self.name)
        layout.addRow("Investigator", self.investigator)
        layout.addRow("Description", self.description)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel | QDialogButtonBox.StandardButton.Ok)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def values(self) -> tuple[str, str, str]:
        return self.name.text(), self.investigator.text(), self.description.toPlainText()


class MainWindow(QMainWindow):
    NAV_ITEMS = ["Case Overview", "Evidence", "Timeline", "Findings", "AI Copilot", "Reports", "Chain of Custody", "Audit Log"]

    def __init__(self, config: AppConfig):
        super().__init__()
        self.config = config
        self.db = Database(config.db_path)
        self.cases = CaseService(config, self.db)
        self.copilot = CopilotService(config, self.db)
        self.reports = ReportService(config, self.db)
        self.current_case_id: int | None = None
        self.analysis_worker: AnalysisWorker | None = None
        self.copilot_worker: CopilotWorker | None = None
        self._build_ui()
        self.refresh_cases()

    def _build_ui(self) -> None:
        self.setWindowTitle("DFIR Copilot — Digital Forensics Workbench")
        self.resize(1450, 900)
        self.setMinimumSize(1160, 720)
        root = QWidget(objectName="Root")
        outer = QVBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        outer.addWidget(self._top_bar())

        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)
        sidebar = QFrame(objectName="Sidebar")
        sidebar.setFixedWidth(220)
        side_layout = QVBoxLayout(sidebar)
        side_layout.setContentsMargins(8, 14, 8, 14)
        self.navigation = QListWidget(objectName="Navigation")
        self.navigation.addItems(self.NAV_ITEMS)
        self.navigation.currentRowChanged.connect(self.pages_set_index)
        side_layout.addWidget(self.navigation)
        side_layout.addStretch()
        engine_label = QLabel("LOCAL FORENSIC ENGINE")
        engine_label.setObjectName("Muted")
        engine_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        side_layout.addWidget(engine_label)
        yara = f"{self.cases.analyzer.scanner_engine} READY" if self.cases.analyzer.yara_available else "INDICATOR FALLBACK"
        yara_label = QLabel(yara)
        yara_label.setStyleSheet("color:#55d3c2;font-size:10px;font-weight:700")
        yara_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        side_layout.addWidget(yara_label)

        self.pages = QStackedWidget()
        self.pages.addWidget(self._overview_page())
        self.pages.addWidget(self._evidence_page())
        self.pages.addWidget(self._timeline_page())
        self.pages.addWidget(self._findings_page())
        self.pages.addWidget(self._copilot_page())
        self.pages.addWidget(self._reports_page())
        self.pages.addWidget(self._custody_page())
        self.pages.addWidget(self._audit_page())
        self.navigation.setCurrentRow(0)
        body.addWidget(sidebar)
        body.addWidget(self.pages, 1)
        outer.addLayout(body, 1)
        self.setCentralWidget(root)
        self.setStatusBar(QStatusBar())
        self.statusBar().showMessage("Ready — original evidence is never modified")

    def _top_bar(self) -> QFrame:
        frame = QFrame(objectName="TopBar")
        frame.setFixedHeight(76)
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(18, 10, 18, 10)
        mark = QLabel("DF", objectName="BrandMark")
        mark.setFixedSize(43, 43)
        mark.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(mark)
        brand_box = QVBoxLayout()
        brand_box.setSpacing(0)
        brand_box.addWidget(QLabel("DFIR Copilot", objectName="Brand"))
        brand_box.addWidget(QLabel("Evidence-Grounded Forensic Workbench", objectName="Muted"))
        layout.addLayout(brand_box)
        layout.addStretch()
        layout.addWidget(QLabel("ACTIVE CASE", objectName="Muted"))
        self.case_combo = QComboBox()
        self.case_combo.setMinimumWidth(310)
        self.case_combo.currentIndexChanged.connect(self._case_changed)
        layout.addWidget(self.case_combo)
        demo = QPushButton("Load Safe Demo")
        demo.clicked.connect(self.load_demo)
        layout.addWidget(demo)
        create = QPushButton("+ New Case", objectName="Primary")
        create.clicked.connect(self.create_case)
        layout.addWidget(create)
        return frame

    def _page_shell(self, title: str, subtitle: str) -> tuple[QWidget, QVBoxLayout]:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(26, 22, 26, 22)
        layout.setSpacing(14)
        layout.addWidget(QLabel(title, objectName="PageTitle"))
        layout.addWidget(QLabel(subtitle, objectName="Muted"))
        return page, layout

    def _overview_page(self) -> QWidget:
        page, layout = self._page_shell("Case Overview", "Investigation health, evidence integrity, and prioritized findings")
        metrics = QHBoxLayout()
        self.metric_labels: dict[str, QLabel] = {}
        for key, title in [
            ("evidence_count", "EVIDENCE ITEMS"), ("artifact_count", "TIMELINE ARTIFACTS"),
            ("finding_count", "TOTAL FINDINGS"), ("high_count", "HIGH / CRITICAL"),
        ]:
            card = QFrame(objectName="Card")
            card_layout = QVBoxLayout(card)
            value = QLabel("0", objectName="MetricValue")
            label = QLabel(title, objectName="MetricLabel")
            card_layout.addWidget(value)
            card_layout.addWidget(label)
            self.metric_labels[key] = value
            metrics.addWidget(card)
        layout.addLayout(metrics)
        grid = QGridLayout()
        case_group = QGroupBox("Case Details")
        case_layout = QFormLayout(case_group)
        self.case_number_label = QLabel("No active case")
        self.case_name_label = QLabel("—")
        self.case_investigator_label = QLabel("—")
        self.case_status_label = QLabel("—")
        self.case_description_label = QLabel("Create or load a case to begin.")
        self.case_description_label.setWordWrap(True)
        case_layout.addRow("Case number", self.case_number_label)
        case_layout.addRow("Name", self.case_name_label)
        case_layout.addRow("Investigator", self.case_investigator_label)
        case_layout.addRow("Status", self.case_status_label)
        case_layout.addRow("Scope", self.case_description_label)
        grid.addWidget(case_group, 0, 0)
        top_group = QGroupBox("Priority Findings")
        top_layout = QVBoxLayout(top_group)
        self.priority_findings = QTextBrowser()
        self.priority_findings.setOpenExternalLinks(False)
        top_layout.addWidget(self.priority_findings)
        grid.addWidget(top_group, 0, 1)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 2)
        layout.addLayout(grid, 1)
        return page

    def _evidence_page(self) -> QWidget:
        page, layout = self._page_shell("Evidence Manager", "Preserve, hash, verify, and analyze case evidence")
        toolbar = QHBoxLayout()
        add = QPushButton("+ Import Evidence", objectName="Primary")
        add.clicked.connect(self.import_evidence)
        verify = QPushButton("Verify Selected Hash")
        verify.clicked.connect(self.verify_selected)
        analyze = QPushButton("Analyze All Evidence")
        analyze.clicked.connect(self.analyze_all)
        toolbar.addWidget(add)
        toolbar.addWidget(verify)
        toolbar.addWidget(analyze)
        toolbar.addStretch()
        self.engine_badge = QLabel(f"Scanner: {self.cases.analyzer.scanner_engine}")
        self.engine_badge.setObjectName("Muted")
        toolbar.addWidget(self.engine_badge)
        layout.addLayout(toolbar)
        self.evidence_table = self._table(["ID", "Filename", "Type", "Size", "SHA-256", "Verified", "Imported"])
        layout.addWidget(self.evidence_table, 1)
        return page

    def _timeline_page(self) -> QWidget:
        page, layout = self._page_shell("Investigation Timeline", "Chronological reconstruction from independently extracted artifacts")
        toolbar = QHBoxLayout()
        toolbar.addWidget(QLabel("Severity filter"))
        self.timeline_filter = QComboBox()
        self.timeline_filter.addItems(["All", "Critical", "High", "Medium", "Low", "Info"])
        self.timeline_filter.currentTextChanged.connect(self.refresh_timeline)
        toolbar.addWidget(self.timeline_filter)
        toolbar.addStretch()
        layout.addLayout(toolbar)
        self.timeline_table = self._table(["UTC Time", "Severity", "Artifact", "Description", "Source", "MITRE", "Reference"])
        layout.addWidget(self.timeline_table, 1)
        return page

    def _findings_page(self) -> QWidget:
        page, layout = self._page_shell("Forensic Findings", "Rule-based detections and cross-artifact correlations with traceable evidence")
        self.findings_table = self._table(["Severity", "Finding", "Category", "Confidence", "MITRE", "Evidence References"])
        layout.addWidget(self.findings_table, 1)
        return page

    def _copilot_page(self) -> QWidget:
        page, layout = self._page_shell("AI Copilot", "Ask questions about this case; every conclusion must point back to evidence")
        privacy = QFrame(objectName="Card")
        privacy_layout = QHBoxLayout(privacy)
        privacy_layout.addWidget(QLabel("PRIVACY CONTROL"))
        privacy_text = QLabel("Offline mode is default. Cloud mode sends only structured case context, never original evidence files.")
        privacy_text.setObjectName("Muted")
        privacy_text.setWordWrap(True)
        privacy_layout.addWidget(privacy_text, 1)
        self.cloud_checkbox = QCheckBox("Use Groq cloud")
        self.cloud_checkbox.setEnabled(self.copilot.cloud_available)
        self.cloud_checkbox.setToolTip("Add GROQ_API_KEY to .env to enable" if not self.copilot.cloud_available else "Structured case context will leave this device")
        privacy_layout.addWidget(self.cloud_checkbox)
        layout.addWidget(privacy)
        self.chat = QTextBrowser()
        self.chat.setHtml("<p style='color:#8298a5'>Analyze evidence, then ask: <b>How did this incident begin?</b></p>")
        layout.addWidget(self.chat, 1)
        suggestions = QHBoxLayout()
        for text in ["How did this incident begin?", "Show PowerShell evidence", "Summarize suspicious findings", "Was anything deleted?"]:
            button = QPushButton(text)
            button.clicked.connect(lambda checked=False, value=text: self._use_suggestion(value))
            suggestions.addWidget(button)
        layout.addLayout(suggestions)
        ask_row = QHBoxLayout()
        self.question = QLineEdit()
        self.question.setPlaceholderText("Ask an evidence-grounded investigation question…")
        self.question.returnPressed.connect(self.ask_copilot)
        self.ask_button = QPushButton("Ask Copilot", objectName="Primary")
        self.ask_button.clicked.connect(self.ask_copilot)
        ask_row.addWidget(self.question, 1)
        ask_row.addWidget(self.ask_button)
        layout.addLayout(ask_row)
        return page

    def _reports_page(self) -> QWidget:
        page, layout = self._page_shell("Reports & Exports", "Generate defensible case records for technical and executive review")
        cards = QGridLayout()
        for column, (title, description, action, label) in enumerate([
            ("PDF Forensic Report", "Evidence inventory, findings, timeline, and chain of custody.", self.export_pdf, "Generate PDF"),
            ("Interactive HTML Report", "Portable browser report with the complete investigation timeline.", self.export_html, "Generate HTML"),
            ("Structured JSON Export", "Machine-readable case bundle for validation and future integrations.", self.export_json, "Export JSON"),
        ]):
            card = QFrame(objectName="Card")
            card_layout = QVBoxLayout(card)
            card_layout.addWidget(QLabel(title, objectName="SectionTitle"))
            desc = QLabel(description, objectName="Muted")
            desc.setWordWrap(True)
            card_layout.addWidget(desc)
            card_layout.addStretch()
            button = QPushButton(label, objectName="Primary" if column == 0 else "")
            button.clicked.connect(action)
            card_layout.addWidget(button)
            cards.addWidget(card, 0, column)
        layout.addLayout(cards)
        report_group = QGroupBox("Report Location")
        report_layout = QHBoxLayout(report_group)
        self.report_path_label = QLabel(str(self.config.report_dir), objectName="Muted")
        self.report_path_label.setWordWrap(True)
        report_layout.addWidget(self.report_path_label, 1)
        open_folder = QPushButton("Open Folder")
        open_folder.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.config.report_dir))))
        report_layout.addWidget(open_folder)
        layout.addWidget(report_group)
        layout.addStretch()
        return page

    def _custody_page(self) -> QWidget:
        page, layout = self._page_shell("Chain of Custody", "Timestamped handling history for every evidence item")
        toolbar = QHBoxLayout()
        add = QPushButton("+ Add Manual Record")
        add.clicked.connect(self.add_manual_custody)
        toolbar.addWidget(add)
        toolbar.addStretch()
        layout.addLayout(toolbar)
        self.custody_table = self._table(["UTC Time", "Evidence", "Action", "Actor", "Location", "Notes"])
        layout.addWidget(self.custody_table, 1)
        return page

    def _audit_page(self) -> QWidget:
        page, layout = self._page_shell("Audit Log", "Application actions recorded for repeatability and accountability")
        self.audit_table = self._table(["UTC Time", "Action", "Details"])
        layout.addWidget(self.audit_table, 1)
        return page

    @staticmethod
    def _table(headers: list[str]) -> QTableWidget:
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.verticalHeader().setVisible(False)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        table.horizontalHeader().setStretchLastSection(True)
        return table

    def pages_set_index(self, index: int) -> None:
        if index >= 0:
            self.pages.setCurrentIndex(index)

    def refresh_cases(self, select_id: int | None = None) -> None:
        self.case_combo.blockSignals(True)
        self.case_combo.clear()
        for case in self.cases.list_cases():
            self.case_combo.addItem(f"{case['case_number']} — {case['name']}", int(case["id"]))
        self.case_combo.blockSignals(False)
        if self.case_combo.count() == 0:
            self.current_case_id = None
            self.refresh_all()
            return
        target = 0
        if select_id is not None:
            for index in range(self.case_combo.count()):
                if self.case_combo.itemData(index) == select_id:
                    target = index
                    break
        self.case_combo.setCurrentIndex(target)
        self._case_changed(target)

    def _case_changed(self, index: int) -> None:
        value = self.case_combo.itemData(index) if index >= 0 else None
        self.current_case_id = int(value) if value is not None else None
        self.refresh_all()

    def refresh_all(self) -> None:
        self.refresh_overview()
        self.refresh_evidence()
        self.refresh_timeline()
        self.refresh_findings()
        self.refresh_custody()
        self.refresh_audit()

    def refresh_overview(self) -> None:
        if self.current_case_id is None:
            for label in self.metric_labels.values():
                label.setText("0")
            self.case_number_label.setText("No active case")
            self.priority_findings.setHtml("<p style='color:#8298a5'>Create a case or load the safe demo.</p>")
            return
        case = self.cases.get_case(self.current_case_id) or {}
        metrics = self.cases.case_metrics(self.current_case_id)
        for key, label in self.metric_labels.items():
            label.setText(str(metrics.get(key, 0)))
        self.case_number_label.setText(str(case.get("case_number", "—")))
        self.case_name_label.setText(str(case.get("name", "—")))
        self.case_investigator_label.setText(str(case.get("investigator", "—")))
        self.case_status_label.setText(str(case.get("status", "—")))
        self.case_description_label.setText(str(case.get("description", "—")))
        findings = self.cases.list_findings(self.current_case_id)[:5]
        if not findings:
            self.priority_findings.setHtml("<p style='color:#8298a5'>No findings yet. Import and analyze evidence.</p>")
        else:
            blocks = []
            for finding in findings:
                color = "#ff756b" if finding["severity"] == "Critical" else "#f4b35e" if finding["severity"] == "High" else "#71c9bc"
                blocks.append(
                    f"<p><b style='color:{color}'>{html.escape(finding['severity'])}</b> "
                    f"<b>{html.escape(finding['title'])}</b><br>"
                    f"<span style='color:#9fb0b8'>{html.escape(finding['description'])}</span></p>"
                )
            self.priority_findings.setHtml("".join(blocks))

    def refresh_evidence(self) -> None:
        rows = self.cases.list_evidence(self.current_case_id) if self.current_case_id else []
        self.evidence_table.setRowCount(len(rows))
        for row_index, item in enumerate(rows):
            values = [
                item["evidence_number"], item["original_name"], item["source_type"], f"{item['size_bytes']:,}",
                item["sha256"], "PASS" if item["verified"] else "FAIL", item["imported_at"],
            ]
            for column, value in enumerate(values):
                cell = QTableWidgetItem(str(value))
                if column == 0:
                    cell.setData(Qt.ItemDataRole.UserRole, int(item["id"]))
                if column == 5:
                    cell.setForeground(QColor("#55d3c2" if item["verified"] else "#ff6b6b"))
                self.evidence_table.setItem(row_index, column, cell)

    def refresh_timeline(self) -> None:
        rows = self.cases.list_artifacts(self.current_case_id) if self.current_case_id else []
        selected = self.timeline_filter.currentText() if hasattr(self, "timeline_filter") else "All"
        if selected != "All":
            rows = [row for row in rows if row["severity"] == selected]
        self.timeline_table.setRowCount(len(rows))
        for row_index, item in enumerate(rows):
            values = [item["event_time"], item["severity"], item["artifact_type"], item["description"], item["source"], item["mitre_id"] or "—", item["artifact_ref"]]
            for column, value in enumerate(values):
                cell = QTableWidgetItem(str(value))
                if column == 1:
                    cell.setForeground(self._severity_color(item["severity"]))
                self.timeline_table.setItem(row_index, column, cell)

    def refresh_findings(self) -> None:
        rows = self.cases.list_findings(self.current_case_id) if self.current_case_id else []
        self.findings_table.setRowCount(len(rows))
        for row_index, item in enumerate(rows):
            refs = ", ".join(json.loads(item["evidence_refs_json"] or "[]"))
            values = [item["severity"], item["title"], item["category"], f"{item['confidence']}%", item["mitre_id"] or "—", refs]
            for column, value in enumerate(values):
                cell = QTableWidgetItem(str(value))
                if column == 0:
                    cell.setForeground(self._severity_color(item["severity"]))
                self.findings_table.setItem(row_index, column, cell)

    def refresh_custody(self) -> None:
        rows = self.cases.list_custody(self.current_case_id) if self.current_case_id else []
        self.custody_table.setRowCount(len(rows))
        for row_index, item in enumerate(rows):
            values = [item["event_time"], item.get("evidence_number") or "Case", item["action"], item["actor"], item["location"], item["notes"]]
            for column, value in enumerate(values):
                self.custody_table.setItem(row_index, column, QTableWidgetItem(str(value)))

    def refresh_audit(self) -> None:
        rows = self.cases.list_audit(self.current_case_id) if self.current_case_id else []
        self.audit_table.setRowCount(len(rows))
        for row_index, item in enumerate(rows):
            for column, value in enumerate([item["event_time"], item["action"], item["details"]]):
                self.audit_table.setItem(row_index, column, QTableWidgetItem(str(value)))

    @staticmethod
    def _severity_color(severity: str) -> QColor:
        return QColor({"Critical": "#ff665c", "High": "#f4ad52", "Medium": "#e7cf72", "Low": "#7cc6d8", "Info": "#8ea2ad"}.get(severity, "#dce7ed"))

    def create_case(self) -> None:
        dialog = NewCaseDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            name, investigator, description = dialog.values()
            case = self.cases.create_case(name, investigator, description)
            self.refresh_cases(int(case["id"]))
            self.statusBar().showMessage(f"Created {case['case_number']}", 5000)
        except Exception as exc:
            QMessageBox.critical(self, "Case creation failed", str(exc))

    def load_demo(self) -> None:
        try:
            self.statusBar().showMessage("Installing and analyzing safe demo evidence…")
            QApplication.processEvents()
            case = install_demo_case(self.cases)
            self.refresh_cases(int(case["id"]))
            self.statusBar().showMessage("Safe demo case analyzed successfully", 7000)
        except Exception as exc:
            QMessageBox.critical(self, "Demo failed", str(exc))

    def import_evidence(self) -> None:
        if not self._require_case():
            return
        paths, _ = QFileDialog.getOpenFileNames(
            self, "Import Evidence", "", "Supported evidence (*.evtx *.json *.jsonl *.csv *.log *.txt *.bin *.img *.raw *.E01);;All files (*)"
        )
        if not paths:
            return
        case = self.cases.get_case(self.current_case_id or 0) or {}
        try:
            for path in paths:
                self.cases.import_evidence(
                    self.current_case_id or 0, Path(path), actor=str(case.get("investigator", "Investigator"))
                )
            self.refresh_all()
            self.statusBar().showMessage(f"Imported {len(paths)} evidence item(s) with SHA-256 verification", 7000)
        except Exception as exc:
            QMessageBox.critical(self, "Evidence import failed", str(exc))

    def verify_selected(self) -> None:
        row = self.evidence_table.currentRow()
        if row < 0:
            QMessageBox.information(self, "Select evidence", "Select an evidence row first.")
            return
        item = self.evidence_table.item(row, 0)
        evidence_id = item.data(Qt.ItemDataRole.UserRole)
        try:
            valid = self.cases.verify_evidence(int(evidence_id))
            self.refresh_all()
            QMessageBox.information(self, "Integrity check", "SHA-256 hash matched." if valid else "HASH MISMATCH — evidence may have changed.")
        except Exception as exc:
            QMessageBox.critical(self, "Verification failed", str(exc))

    def analyze_all(self) -> None:
        if not self._require_case():
            return
        if not self.cases.list_evidence(self.current_case_id or 0):
            QMessageBox.information(self, "No evidence", "Import evidence before running analysis.")
            return
        self.navigation.setEnabled(False)
        self.statusBar().showMessage("Analyzing evidence without modifying originals…")
        self.analysis_worker = AnalysisWorker(self.cases, self.current_case_id or 0)
        self.analysis_worker.completed.connect(self._analysis_done)
        self.analysis_worker.failed.connect(self._analysis_failed)
        self.analysis_worker.start()

    def _analysis_done(self, count: int) -> None:
        self.navigation.setEnabled(True)
        self.refresh_all()
        self.statusBar().showMessage(f"Analysis complete — {count} artifacts extracted", 7000)

    def _analysis_failed(self, message: str) -> None:
        self.navigation.setEnabled(True)
        QMessageBox.critical(self, "Analysis stopped", message)
        self.statusBar().showMessage("Analysis stopped")

    def _use_suggestion(self, value: str) -> None:
        self.question.setText(value)
        self.ask_copilot()

    def ask_copilot(self) -> None:
        if not self._require_case():
            return
        question = self.question.text().strip()
        if not question:
            return
        safe_question = html.escape(question)
        self.chat.append(f"<p><b style='color:#67dfcf'>Investigator</b><br>{safe_question}</p>")
        self.question.clear()
        self.ask_button.setEnabled(False)
        self.ask_button.setText("Reviewing evidence…")
        self.copilot_worker = CopilotWorker(
            self.copilot, self.current_case_id or 0, question, self.cloud_checkbox.isChecked()
        )
        self.copilot_worker.completed.connect(self._copilot_done)
        self.copilot_worker.failed.connect(self._copilot_failed)
        self.copilot_worker.start()

    def _copilot_done(self, response: object) -> None:
        self.ask_button.setEnabled(True)
        self.ask_button.setText("Ask Copilot")
        answer = html.escape(response.answer).replace("\n", "<br>")
        refs = ", ".join(response.citations) if response.citations else "No citations — insufficient evidence response"
        self.chat.append(
            f"<div style='background:#10232c;padding:12px;border-left:3px solid #55d3c2'>"
            f"<b style='color:#67dfcf'>DFIR Copilot</b> <span style='color:#8198a3'>({html.escape(response.mode)})</span><br>"
            f"{answer}<br><small style='color:#8198a3'>Evidence: {html.escape(refs)} · Confidence: {response.confidence}%</small></div>"
        )
        self.refresh_audit()

    def _copilot_failed(self, message: str) -> None:
        self.ask_button.setEnabled(True)
        self.ask_button.setText("Ask Copilot")
        QMessageBox.critical(self, "Copilot error", message)

    def export_pdf(self) -> None:
        self._export("PDF", self.reports.export_pdf)

    def export_html(self) -> None:
        self._export("HTML", self.reports.export_html)

    def export_json(self) -> None:
        self._export("JSON", self.reports.export_json)

    def _export(self, kind: str, function: object) -> None:
        if not self._require_case():
            return
        try:
            path = function(self.current_case_id or 0)
            self.refresh_audit()
            self.report_path_label.setText(str(path))
            answer = QMessageBox.question(self, f"{kind} ready", f"Report created:\n{path}\n\nOpen it now?")
            if answer == QMessageBox.StandardButton.Yes:
                QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))
        except Exception as exc:
            QMessageBox.critical(self, f"{kind} export failed", str(exc))

    def add_manual_custody(self) -> None:
        if not self._require_case():
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("Add Chain-of-Custody Record")
        form = QFormLayout(dialog)
        evidence_combo = QComboBox()
        evidence_combo.addItem("Case-level record", None)
        for item in self.cases.list_evidence(self.current_case_id or 0):
            evidence_combo.addItem(f"{item['evidence_number']} — {item['original_name']}", int(item["id"]))
        action = QLineEdit()
        actor = QLineEdit((self.cases.get_case(self.current_case_id or 0) or {}).get("investigator", "Investigator"))
        location = QLineEdit()
        notes = QLineEdit()
        form.addRow("Evidence", evidence_combo)
        form.addRow("Action", action)
        form.addRow("Actor", actor)
        form.addRow("Location", location)
        form.addRow("Notes", notes)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel | QDialogButtonBox.StandardButton.Ok)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        form.addRow(buttons)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            if not action.text().strip() or not actor.text().strip():
                QMessageBox.warning(self, "Missing fields", "Action and actor are required.")
                return
            self.cases.add_custody_record(
                self.current_case_id or 0, evidence_combo.currentData(), action.text().strip(), actor.text().strip(),
                location.text().strip(), notes.text().strip(),
            )
            self.db.audit(self.current_case_id, "CUSTODY_RECORDED", action.text().strip())
            self.refresh_all()

    def _require_case(self) -> bool:
        if self.current_case_id is None:
            QMessageBox.information(self, "No active case", "Create a case or load the safe demo first.")
            return False
        return True


def run_gui(config: AppConfig) -> int:
    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("DFIR Copilot")
    app.setOrganizationName("V Security Labs")
    app.setStyle("Fusion")
    app.setStyleSheet(APP_STYLE)
    window = MainWindow(config)
    window.show()
    return int(app.exec())
