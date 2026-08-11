"""Case workflow, evidence preservation, analysis, and chain of custody."""

from __future__ import annotations

import json
import mimetypes
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dfir_copilot.config import AppConfig
from dfir_copilot.database import Database, utc_now
from dfir_copilot.engine.analyzer import EvidenceAnalyzer
from dfir_copilot.engine.correlator import correlate
from dfir_copilot.engine.hashing import safe_filename, sha256_file


class CaseService:
    def __init__(self, config: AppConfig, database: Database | None = None):
        self.config = config
        self.db = database or Database(config.db_path)
        self.analyzer = EvidenceAnalyzer(config)

    def create_case(
        self,
        name: str,
        investigator: str,
        description: str = "",
        case_number: str | None = None,
    ) -> dict[str, Any]:
        if not name.strip() or not investigator.strip():
            raise ValueError("Case name and investigator are required")
        case_number = case_number or f"DFIR-{datetime.now().year}-{uuid.uuid4().hex[:6].upper()}"
        now = utc_now()
        case_id = self.db.execute(
            """
            INSERT INTO cases(case_number, name, description, investigator, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'Open', ?, ?)
            """,
            (case_number, name.strip(), description.strip(), investigator.strip(), now, now),
        )
        case_dir = self.config.evidence_dir / case_number / "evidence"
        case_dir.mkdir(parents=True, exist_ok=True)
        self.db.audit(case_id, "CASE_CREATED", f"Case {case_number} created by {investigator.strip()}")
        return self.get_case(case_id) or {}

    def list_cases(self) -> list[dict[str, Any]]:
        return self.db.fetch_all("SELECT * FROM cases ORDER BY created_at DESC")

    def get_case(self, case_id: int) -> dict[str, Any] | None:
        return self.db.fetch_one("SELECT * FROM cases WHERE id = ?", (case_id,))

    def update_case_status(self, case_id: int, status: str) -> None:
        if status not in {"Open", "In Review", "Closed"}:
            raise ValueError("Invalid case status")
        self.db.execute(
            "UPDATE cases SET status = ?, updated_at = ? WHERE id = ?",
            (status, utc_now(), case_id),
        )
        self.db.audit(case_id, "STATUS_CHANGED", f"Case status changed to {status}")

    def import_evidence(
        self,
        case_id: int,
        source_path: Path,
        actor: str,
        source_type: str = "File",
        acquired_at: str | None = None,
        notes: str = "",
    ) -> dict[str, Any]:
        case = self.get_case(case_id)
        source_path = Path(source_path)
        if not case:
            raise ValueError("Case not found")
        if not source_path.is_file():
            raise FileNotFoundError(source_path)
        current_count = self.db.fetch_one(
            "SELECT COUNT(*) AS count FROM evidence WHERE case_id = ?", (case_id,)
        ) or {"count": 0}
        evidence_number = f"E-{int(current_count['count']) + 1:03d}"
        original_hash = sha256_file(source_path)
        destination_dir = self.config.evidence_dir / case["case_number"] / "evidence"
        destination_dir.mkdir(parents=True, exist_ok=True)
        destination = destination_dir / f"{evidence_number}_{safe_filename(source_path.name)}"
        shutil.copy2(source_path, destination)
        copied_hash = sha256_file(destination)
        if copied_hash != original_hash:
            destination.unlink(missing_ok=True)
            raise IOError("Evidence copy failed integrity verification")

        now = utc_now()
        evidence_id = self.db.execute(
            """
            INSERT INTO evidence(
                case_id, evidence_number, original_name, stored_path, sha256, size_bytes,
                mime_type, source_type, acquired_at, imported_at, verified, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
            """,
            (
                case_id,
                evidence_number,
                source_path.name,
                str(destination),
                original_hash,
                destination.stat().st_size,
                mimetypes.guess_type(source_path.name)[0] or "application/octet-stream",
                source_type,
                acquired_at or now,
                now,
                notes,
            ),
        )
        self.add_custody_record(
            case_id,
            evidence_id,
            "Imported and hash verified",
            actor,
            str(destination_dir),
            f"SHA-256: {original_hash}",
        )
        self.write_evidence_manifest(case_id)
        self.db.audit(case_id, "EVIDENCE_IMPORTED", f"{evidence_number}: {source_path.name}")
        return self.get_evidence(evidence_id) or {}

    def get_evidence(self, evidence_id: int) -> dict[str, Any] | None:
        return self.db.fetch_one("SELECT * FROM evidence WHERE id = ?", (evidence_id,))

    def list_evidence(self, case_id: int) -> list[dict[str, Any]]:
        return self.db.fetch_all(
            "SELECT * FROM evidence WHERE case_id = ? ORDER BY evidence_number", (case_id,)
        )

    def verify_evidence(self, evidence_id: int, actor: str = "Investigator") -> bool:
        evidence = self.get_evidence(evidence_id)
        if not evidence:
            raise ValueError("Evidence not found")
        path = Path(evidence["stored_path"])
        valid = path.is_file() and sha256_file(path) == evidence["sha256"]
        self.db.execute("UPDATE evidence SET verified = ? WHERE id = ?", (int(valid), evidence_id))
        self.add_custody_record(
            int(evidence["case_id"]),
            evidence_id,
            "Integrity verification",
            actor,
            str(path.parent),
            "Hash matched" if valid else "HASH MISMATCH",
        )
        self.db.audit(
            int(evidence["case_id"]),
            "HASH_VERIFIED" if valid else "HASH_MISMATCH",
            f"{evidence['evidence_number']} integrity {'passed' if valid else 'failed'}",
        )
        self.write_evidence_manifest(int(evidence["case_id"]))
        return valid

    def write_evidence_manifest(self, case_id: int) -> Path:
        """Atomically refresh the human-readable SHA-256 manifest for a case."""
        case = self.get_case(case_id)
        if not case:
            raise ValueError("Case not found")
        manifest = {
            "schema": "dfir-copilot/evidence-manifest/v1",
            "case_number": case["case_number"],
            "hash_algorithm": "SHA-256",
            "generated_at": utc_now(),
            "evidence": [
                {
                    "evidence_number": item["evidence_number"],
                    "original_name": item["original_name"],
                    "sha256": item["sha256"],
                    "size_bytes": item["size_bytes"],
                    "acquired_at": item["acquired_at"],
                    "imported_at": item["imported_at"],
                    "verified": bool(item["verified"]),
                }
                for item in self.list_evidence(case_id)
            ],
        }
        case_dir = self.config.evidence_dir / case["case_number"]
        destination = case_dir / "evidence_manifest.json"
        temporary = case_dir / "evidence_manifest.json.tmp"
        temporary.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
        temporary.replace(destination)
        return destination

    def analyze_evidence(self, evidence_id: int, actor: str = "DFIR Copilot Engine") -> int:
        evidence = self.get_evidence(evidence_id)
        if not evidence:
            raise ValueError("Evidence not found")
        if not self.verify_evidence(evidence_id, actor):
            raise ValueError("Evidence hash mismatch; analysis stopped")
        path = Path(evidence["stored_path"])
        artifacts = self.analyzer.analyze(path)
        self.db.execute("DELETE FROM artifacts WHERE evidence_id = ?", (evidence_id,))
        for artifact in artifacts:
            artifact_ref = f"ART-{uuid.uuid4().hex[:8].upper()}"
            self.db.execute(
                """
                INSERT INTO artifacts(
                    case_id, evidence_id, artifact_ref, artifact_type, event_time, source,
                    description, severity, mitre_id, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    evidence["case_id"],
                    evidence_id,
                    artifact_ref,
                    artifact.artifact_type,
                    artifact.timestamp,
                    artifact.source,
                    artifact.description,
                    artifact.severity,
                    artifact.mitre_id,
                    self.db.json(artifact.details),
                ),
            )
        self.rebuild_findings(int(evidence["case_id"]))
        self.db.audit(
            int(evidence["case_id"]),
            "EVIDENCE_ANALYZED",
            f"{evidence['evidence_number']} produced {len(artifacts)} artifacts",
        )
        return len(artifacts)

    def analyze_case(self, case_id: int, actor: str = "DFIR Copilot Engine") -> int:
        total = 0
        for evidence in self.list_evidence(case_id):
            total += self.analyze_evidence(int(evidence["id"]), actor)
        self.rebuild_findings(case_id)
        return total

    def rebuild_findings(self, case_id: int) -> int:
        artifacts = self.list_artifacts(case_id)
        findings = correlate(artifacts)
        self.db.execute("DELETE FROM findings WHERE case_id = ?", (case_id,))
        for finding in findings:
            self.db.execute(
                """
                INSERT INTO findings(
                    case_id, finding_ref, title, severity, category, description,
                    evidence_refs_json, mitre_id, confidence, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    case_id,
                    f"FND-{uuid.uuid4().hex[:8].upper()}",
                    finding.title,
                    finding.severity,
                    finding.category,
                    finding.description,
                    self.db.json(finding.evidence_refs),
                    finding.mitre_id,
                    finding.confidence,
                    utc_now(),
                ),
            )
        return len(findings)

    def list_artifacts(self, case_id: int) -> list[dict[str, Any]]:
        return self.db.fetch_all(
            """
            SELECT a.*, e.evidence_number, e.original_name
            FROM artifacts a JOIN evidence e ON e.id = a.evidence_id
            WHERE a.case_id = ?
            ORDER BY a.event_time, a.id
            """,
            (case_id,),
        )

    def list_findings(self, case_id: int) -> list[dict[str, Any]]:
        return self.db.fetch_all(
            """
            SELECT * FROM findings WHERE case_id = ?
            ORDER BY CASE severity
                WHEN 'Critical' THEN 4 WHEN 'High' THEN 3 WHEN 'Medium' THEN 2
                WHEN 'Low' THEN 1 ELSE 0 END DESC, id
            """,
            (case_id,),
        )

    def add_custody_record(
        self,
        case_id: int,
        evidence_id: int | None,
        action: str,
        actor: str,
        location: str = "",
        notes: str = "",
    ) -> int:
        return self.db.execute(
            """
            INSERT INTO custody_records(case_id, evidence_id, action, actor, event_time, location, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (case_id, evidence_id, action, actor, utc_now(), location, notes),
        )

    def list_custody(self, case_id: int) -> list[dict[str, Any]]:
        return self.db.fetch_all(
            """
            SELECT c.*, e.evidence_number
            FROM custody_records c LEFT JOIN evidence e ON e.id = c.evidence_id
            WHERE c.case_id = ? ORDER BY c.event_time, c.id
            """,
            (case_id,),
        )

    def list_audit(self, case_id: int) -> list[dict[str, Any]]:
        return self.db.fetch_all(
            "SELECT * FROM audit_log WHERE case_id = ? ORDER BY event_time, id", (case_id,)
        )

    def case_metrics(self, case_id: int) -> dict[str, int]:
        counts = self.db.fetch_one(
            """
            SELECT
              (SELECT COUNT(*) FROM evidence WHERE case_id = ?) AS evidence_count,
              (SELECT COUNT(*) FROM artifacts WHERE case_id = ?) AS artifact_count,
              (SELECT COUNT(*) FROM findings WHERE case_id = ?) AS finding_count,
              (SELECT COUNT(*) FROM findings WHERE case_id = ? AND severity IN ('Critical', 'High')) AS high_count
            """,
            (case_id, case_id, case_id, case_id),
        )
        return {key: int(value) for key, value in (counts or {}).items()}
