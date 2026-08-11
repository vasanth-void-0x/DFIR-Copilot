"""Command-line entry point and GUI launcher."""

from __future__ import annotations

import argparse
import tempfile
from pathlib import Path

from dfir_copilot import __version__
from dfir_copilot.config import AppConfig
from dfir_copilot.database import Database
from dfir_copilot.services.case_service import CaseService
from dfir_copilot.services.copilot import CopilotService
from dfir_copilot.services.demo import install_demo_case
from dfir_copilot.services.report import ReportService


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DFIR Copilot forensic workbench")
    parser.add_argument("--version", action="version", version=f"DFIR Copilot {__version__}")
    parser.add_argument("--data-dir", type=Path, help="Override the local case-data directory")
    parser.add_argument("--cli-demo", action="store_true", help="Analyze the safe demo case without the GUI")
    parser.add_argument("--self-check", action="store_true", help="Run an isolated end-to-end verification")
    parser.add_argument("--investigator", default="Vasanth Kumar", help="Investigator name for the demo case")
    return parser


def _run_demo(config: AppConfig, investigator: str) -> int:
    database = Database(config.db_path)
    cases = CaseService(config, database)
    case = install_demo_case(cases, investigator)
    reports = ReportService(config, database)
    pdf = reports.export_pdf(int(case["id"]))
    html = reports.export_html(int(case["id"]))
    json_path = reports.export_json(int(case["id"]))
    copilot = CopilotService(config, database)
    answer = copilot.ask(int(case["id"]), "Summarize what happened", use_cloud=False)
    metrics = cases.case_metrics(int(case["id"]))
    print(f"Case: {case['case_number']} — {case['name']}")
    print(
        f"Evidence: {metrics['evidence_count']} | Artifacts: {metrics['artifact_count']} | "
        f"Findings: {metrics['finding_count']} | High/Critical: {metrics['high_count']}"
    )
    print(answer.answer)
    print(f"Citations: {', '.join(answer.citations)}")
    print(f"PDF: {pdf}")
    print(f"HTML: {html}")
    print(f"JSON: {json_path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.self_check:
        with tempfile.TemporaryDirectory(prefix="dfir-copilot-check-") as directory:
            config = AppConfig.load(Path(directory))
            return _run_demo(config, args.investigator)
    config = AppConfig.load(args.data_dir)
    if args.cli_demo:
        return _run_demo(config, args.investigator)
    try:
        from dfir_copilot.ui.main_window import run_gui
    except ImportError as exc:
        print("The desktop UI dependency is missing. Run: pip install -r requirements.txt")
        print(f"Details: {exc}")
        return 2
    return run_gui(config)

