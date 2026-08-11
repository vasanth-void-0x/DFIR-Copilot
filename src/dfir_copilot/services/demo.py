"""Install the bundled safe, synthetic investigation case."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from dfir_copilot.config import resource_root
from dfir_copilot.services.case_service import CaseService


def install_demo_case(service: CaseService, investigator: str = "Vasanth Kumar") -> dict[str, Any]:
    case = service.create_case(
        name="Operation Paper Trail (Safe Demo)",
        investigator=investigator,
        description=(
            "Synthetic forensic exercise: suspicious download, PowerShell execution, outbound communication, "
            "persistence, and deleted-file evidence. No live malware or routable malicious infrastructure is included."
        ),
    )
    demo_root = resource_root() / "demo_evidence"
    evidence_files = [
        demo_root / "windows_events.json",
        demo_root / "autopsy_deleted_files.csv",
        demo_root / "safe_samples" / "invoice_viewer.ps1.txt",
    ]
    for path in evidence_files:
        service.import_evidence(
            int(case["id"]),
            path,
            actor=investigator,
            source_type="Synthetic training evidence",
            notes="Bundled safe demo artifact",
        )
    service.analyze_case(int(case["id"]), actor="DFIR Copilot Demo Engine")
    return service.get_case(int(case["id"])) or case

