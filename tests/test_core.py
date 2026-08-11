from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC = PROJECT_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from dfir_copilot.config import AppConfig
from dfir_copilot.database import Database
from dfir_copilot.engine.hashing import sha256_file
from dfir_copilot.engine.scanner import YaraScanner
from dfir_copilot.services.case_service import CaseService
from dfir_copilot.services.copilot import CopilotService
from dfir_copilot.services.demo import install_demo_case
from dfir_copilot.services.report import ReportService


class CoreWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="dfir-copilot-test-")
        self.config = AppConfig.load(Path(self.temp.name))
        self.db = Database(self.config.db_path)
        self.cases = CaseService(self.config, self.db)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_hash_detects_changes(self) -> None:
        sample = Path(self.temp.name) / "sample.txt"
        sample.write_text("forensic evidence", encoding="utf-8")
        first = sha256_file(sample)
        self.assertEqual(len(first), 64)
        sample.write_text("forensic evidence changed", encoding="utf-8")
        self.assertNotEqual(first, sha256_file(sample))

    def test_yara_x_rule_match_when_available(self) -> None:
        scanner = YaraScanner(PROJECT_ROOT / "resources" / "rules" / "suspicious.yar")
        if not scanner.available:
            self.skipTest("YARA-X dependency is not installed in this test environment")
        results = scanner.scan(PROJECT_ROOT / "demo_evidence" / "safe_samples" / "invoice_viewer.ps1.txt")
        self.assertEqual(scanner.engine_name, "YARA-X")
        self.assertTrue(any(item.artifact_type == "YARA-X Match" for item in results))
        self.assertTrue(any(item.mitre_id == "T1105" for item in results))

    def test_end_to_end_demo_workflow(self) -> None:
        case = install_demo_case(self.cases, "Test Investigator")
        case_id = int(case["id"])
        metrics = self.cases.case_metrics(case_id)
        self.assertEqual(metrics["evidence_count"], 3)
        self.assertGreaterEqual(metrics["artifact_count"], 13)
        self.assertGreaterEqual(metrics["finding_count"], 3)
        self.assertGreaterEqual(metrics["high_count"], 2)

        manifest_path = self.config.evidence_dir / case["case_number"] / "evidence_manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(manifest["hash_algorithm"], "SHA-256")
        self.assertEqual(len(manifest["evidence"]), 3)

        findings = self.cases.list_findings(case_id)
        titles = {item["title"] for item in findings}
        self.assertIn("Suspicious download-to-execution chain", titles)
        self.assertIn("Potential anti-forensic file deletion", titles)

        for evidence in self.cases.list_evidence(case_id):
            self.assertTrue(self.cases.verify_evidence(int(evidence["id"]), "Test Investigator"))

        copilot = CopilotService(self.config, self.db)
        response = copilot.ask(case_id, "How did this incident begin?", use_cloud=False)
        self.assertEqual(response.mode, "Offline grounded")
        self.assertGreaterEqual(response.confidence, 80)
        self.assertTrue(response.citations)
        valid_refs = {item["artifact_ref"] for item in self.cases.list_artifacts(case_id)}
        self.assertTrue(set(response.citations).issubset(valid_refs))

    def test_tampering_stops_analysis(self) -> None:
        case = self.cases.create_case("Integrity Test", "Test Investigator")
        source = Path(self.temp.name) / "original.log"
        source.write_text("unaltered evidence", encoding="utf-8")
        evidence = self.cases.import_evidence(int(case["id"]), source, "Test Investigator")
        stored = Path(evidence["stored_path"])
        stored.write_text("tampered evidence", encoding="utf-8")
        self.assertFalse(self.cases.verify_evidence(int(evidence["id"])))
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            self.cases.analyze_evidence(int(evidence["id"]))

    def test_reports_are_generated(self) -> None:
        case = install_demo_case(self.cases, "Report Investigator")
        reports = ReportService(self.config, self.db)
        case_id = int(case["id"])
        json_path = reports.export_json(case_id)
        html_path = reports.export_html(case_id)
        pdf_path = reports.export_pdf(case_id)
        self.assertTrue(json_path.is_file())
        self.assertTrue(html_path.is_file())
        self.assertTrue(pdf_path.is_file())
        self.assertEqual(pdf_path.read_bytes()[:4], b"%PDF")
        payload = json.loads(json_path.read_text(encoding="utf-8"))
        self.assertEqual(payload["case"]["case_number"], case["case_number"])
        self.assertIn("Chain of Custody", html_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
