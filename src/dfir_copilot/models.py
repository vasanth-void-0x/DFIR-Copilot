"""Shared data structures used by the forensic engine and UI."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


SEVERITY_ORDER = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}


@dataclass(slots=True)
class Artifact:
    artifact_type: str
    timestamp: str
    source: str
    description: str
    severity: str = "Info"
    details: dict[str, Any] = field(default_factory=dict)
    mitre_id: str = ""


@dataclass(slots=True)
class Finding:
    title: str
    severity: str
    category: str
    description: str
    evidence_refs: list[str] = field(default_factory=list)
    mitre_id: str = ""
    confidence: int = 70


@dataclass(slots=True)
class CopilotResponse:
    answer: str
    citations: list[str]
    confidence: int
    mode: str

