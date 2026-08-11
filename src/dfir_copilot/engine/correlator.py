"""Evidence correlation and deterministic forensic findings."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from dfir_copilot.models import Finding, SEVERITY_ORDER


def _time(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)


def _contains(row: dict[str, Any], *needles: str) -> bool:
    text = f"{row.get('artifact_type', '')} {row.get('description', '')} {row.get('details_json', '')}".lower()
    return any(needle in text for needle in needles)


def correlate(artifacts: list[dict[str, Any]]) -> list[Finding]:
    ordered = sorted(artifacts, key=lambda row: _time(str(row.get("event_time", ""))))
    downloads = [row for row in ordered if _contains(row, "download", "browser history")]
    powershell = [row for row in ordered if _contains(row, "powershell", "encoded command")]
    networks = [row for row in ordered if _contains(row, "network connection", "external connection", "destination_ip")]
    deletions = [row for row in ordered if _contains(row, "deleted file", "file deletion", "recycle")]

    findings: list[Finding] = []
    for download in downloads:
        for shell in powershell:
            delta = (_time(shell["event_time"]) - _time(download["event_time"])).total_seconds()
            if 0 <= delta <= 15 * 60:
                related_network = next(
                    (
                        network
                        for network in networks
                        if 0 <= (_time(network["event_time"]) - _time(shell["event_time"])).total_seconds() <= 15 * 60
                    ),
                    None,
                )
                if related_network:
                    refs = [download["artifact_ref"], shell["artifact_ref"], related_network["artifact_ref"]]
                    findings.append(
                        Finding(
                            title="Suspicious download-to-execution chain",
                            severity="Critical",
                            category="Incident Correlation",
                            description=(
                                "A downloaded file was followed by PowerShell execution and an outbound connection "
                                "within a short time window. This sequence is consistent with staged payload execution."
                            ),
                            evidence_refs=refs,
                            mitre_id="T1105, T1059.001, T1071.001",
                            confidence=95,
                        )
                    )
                    break
        if findings:
            break

    if deletions and networks:
        deletion = deletions[0]
        prior_network = next(
            (network for network in reversed(networks) if _time(network["event_time"]) <= _time(deletion["event_time"])),
            None,
        )
        if prior_network:
            findings.append(
                Finding(
                    title="Potential anti-forensic file deletion",
                    severity="High",
                    category="Anti-Forensics",
                    description="A deleted-file artifact was recorded after suspicious outbound activity.",
                    evidence_refs=[prior_network["artifact_ref"], deletion["artifact_ref"]],
                    mitre_id="T1070.004",
                    confidence=84,
                )
            )

    high_rows = [
        row
        for row in ordered
        if SEVERITY_ORDER.get(str(row.get("severity", "Info")), 0) >= SEVERITY_ORDER["High"]
    ]
    already_used = {ref for finding in findings for ref in finding.evidence_refs}
    for row in high_rows:
        if row["artifact_ref"] in already_used:
            continue
        findings.append(
            Finding(
                title=f"High-risk artifact: {row['artifact_type']}",
                severity=str(row["severity"]),
                category="Artifact Detection",
                description=str(row["description"]),
                evidence_refs=[row["artifact_ref"]],
                mitre_id=str(row.get("mitre_id", "")),
                confidence=80,
            )
        )

    seen: set[tuple[str, tuple[str, ...]]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.title, tuple(finding.evidence_refs))
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique
