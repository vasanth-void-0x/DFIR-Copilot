"""Parsers for structured artifacts, Autopsy exports, and Windows EVTX files."""

from __future__ import annotations

import csv
import json
import mimetypes
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from xml.etree import ElementTree

from dfir_copilot.models import Artifact


EVENT_ID_MAP: dict[str, tuple[str, str, str, str]] = {
    "1": ("Process Creation", "Process was created", "Medium", "T1059"),
    "3": ("Network Connection", "A process created a network connection", "Medium", "T1071"),
    "11": ("File Creation", "A file was created", "Low", "T1105"),
    "22": ("DNS Query", "A DNS query was observed", "Low", "T1071.004"),
    "4624": ("Successful Logon", "A successful Windows logon occurred", "Info", ""),
    "4625": ("Failed Logon", "A Windows logon attempt failed", "Medium", "T1110"),
    "4688": ("Process Creation", "A new Windows process was created", "Medium", "T1059"),
    "4104": ("PowerShell", "PowerShell script block execution was logged", "High", "T1059.001"),
    "7045": ("Service Installation", "A Windows service was installed", "High", "T1543.003"),
}


def normalize_timestamp(value: Any, fallback: datetime | None = None) -> str:
    fallback = fallback or datetime.now(timezone.utc)
    if value in (None, ""):
        return fallback.isoformat(timespec="seconds")
    text = str(value).strip().replace("Z", "+00:00")
    for candidate in (text, text.replace(" ", "T", 1)):
        try:
            parsed = datetime.fromisoformat(candidate)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc).isoformat(timespec="seconds")
        except ValueError:
            pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
        try:
            parsed = datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
            return parsed.isoformat(timespec="seconds")
        except ValueError:
            pass
    return fallback.isoformat(timespec="seconds")


def file_metadata(path: Path) -> Artifact:
    stat = path.stat()
    modified = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
    created = datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc)
    return Artifact(
        artifact_type="File Metadata",
        timestamp=modified.isoformat(timespec="seconds"),
        source=path.name,
        description=f"Metadata recorded for {path.name} ({stat.st_size:,} bytes)",
        severity="Info",
        details={
            "filename": path.name,
            "size_bytes": stat.st_size,
            "modified_utc": modified.isoformat(timespec="seconds"),
            "created_utc": created.isoformat(timespec="seconds"),
            "mime_type": mimetypes.guess_type(path.name)[0] or "application/octet-stream",
        },
    )


def _artifact_from_mapping(row: dict[str, Any], source: str, fallback: datetime) -> Artifact:
    lowered = {str(key).strip().lower(): value for key, value in row.items()}
    event_type = str(
        lowered.get("event_type")
        or lowered.get("artifact_type")
        or lowered.get("category")
        or lowered.get("type")
        or "Structured Event"
    )
    description = str(
        lowered.get("description")
        or lowered.get("message")
        or lowered.get("notes")
        or lowered.get("name")
        or event_type
    )
    status = str(lowered.get("status", ""))
    deleted_value = str(lowered.get("deleted", lowered.get("is deleted", ""))).lower()
    if "deleted" in status.lower() or deleted_value in {"true", "yes", "1"}:
        event_type = "Deleted File"
        description = f"Deleted-file record identified: {lowered.get('name', description)}"
        severity = "Medium"
        mitre = "T1070.004"
    else:
        severity = str(lowered.get("severity") or "Info").title()
        mitre = str(lowered.get("mitre") or lowered.get("mitre_id") or "")

    timestamp = normalize_timestamp(
        lowered.get("timestamp")
        or lowered.get("event_time")
        or lowered.get("time")
        or lowered.get("modified time"),
        fallback,
    )
    valid_severities = {"Info", "Low", "Medium", "High", "Critical"}
    if severity not in valid_severities:
        severity = "Info"
    return Artifact(
        artifact_type=event_type,
        timestamp=timestamp,
        source=str(lowered.get("source") or source),
        description=description,
        severity=severity,
        details={key: value for key, value in lowered.items() if value not in (None, "")},
        mitre_id=mitre,
    )


def parse_json(path: Path) -> list[Artifact]:
    fallback = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    try:
        content = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return []
    if isinstance(content, dict):
        rows: Iterable[Any] = content.get("events", content.get("artifacts", [content]))
    elif isinstance(content, list):
        rows = content
    else:
        return []
    return [
        _artifact_from_mapping(row, path.name, fallback)
        for row in rows
        if isinstance(row, dict)
    ]


def parse_jsonl(path: Path) -> list[Artifact]:
    fallback = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    results: list[Artifact] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return results
    for line in lines:
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            results.append(_artifact_from_mapping(row, path.name, fallback))
    return results


def parse_csv(path: Path) -> list[Artifact]:
    fallback = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    try:
        with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
            reader = csv.DictReader(handle)
            return [_artifact_from_mapping(dict(row), path.name, fallback) for row in reader]
    except (OSError, csv.Error):
        return []


def _event_data(root: ElementTree.Element) -> dict[str, str]:
    values: dict[str, str] = {}
    for item in root.findall(".//{*}EventData/{*}Data"):
        name = item.attrib.get("Name", f"Data{len(values) + 1}")
        values[name] = item.text or ""
    return values


def parse_evtx(path: Path) -> list[Artifact]:
    """Parse EVTX when python-evtx is installed; otherwise return no artifacts."""
    try:
        from Evtx.Evtx import Evtx  # type: ignore
    except ImportError:
        return []

    results: list[Artifact] = []
    with Evtx(str(path)) as log:
        for record in log.records():
            try:
                root = ElementTree.fromstring(record.xml())
                event_id = root.findtext(".//{*}EventID", default="")
                time_node = root.find(".//{*}TimeCreated")
                timestamp = normalize_timestamp(
                    time_node.attrib.get("SystemTime") if time_node is not None else None
                )
                provider_node = root.find(".//{*}Provider")
                provider = provider_node.attrib.get("Name", "Windows Event Log") if provider_node is not None else "Windows Event Log"
                data = _event_data(root)
                event_type, base, severity, mitre = EVENT_ID_MAP.get(
                    event_id, ("Windows Event", "Windows event was recorded", "Info", "")
                )
                command = data.get("CommandLine") or data.get("ScriptBlockText") or data.get("Image") or ""
                description = f"{base} (Event ID {event_id})"
                if command:
                    description += f": {command[:300]}"
                lowered = command.lower()
                if "powershell" in lowered and any(token in lowered for token in ("-enc", "downloadstring", "invoke-webrequest")):
                    severity = "High"
                    mitre = "T1059.001"
                results.append(
                    Artifact(
                        artifact_type=event_type,
                        timestamp=timestamp,
                        source=f"{path.name} / {provider}",
                        description=description,
                        severity=severity,
                        details={"event_id": event_id, "provider": provider, **data},
                        mitre_id=mitre,
                    )
                )
            except (ElementTree.ParseError, AttributeError, ValueError):
                continue
    return results


def parse_supported(path: Path) -> list[Artifact]:
    suffix = path.suffix.lower()
    if suffix == ".json":
        return parse_json(path)
    if suffix in {".jsonl", ".ndjson"}:
        return parse_jsonl(path)
    if suffix == ".csv":
        return parse_csv(path)
    if suffix == ".evtx":
        return parse_evtx(path)
    return []
