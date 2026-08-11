"""Official YARA-X integration with a labelled last-resort fallback."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from dfir_copilot.models import Artifact


FALLBACK_PATTERNS: list[tuple[bytes, str, str]] = [
    (rb"powershell(?:\.exe)?\s+.*(?:-enc|-encodedcommand)", "Encoded PowerShell command", "T1059.001"),
    (rb"(?:invoke-webrequest|downloadstring|start-bitstransfer)", "PowerShell download behavior", "T1105"),
    (rb"(?:frombase64string|certutil\s+-decode)", "Encoded content decoding behavior", "T1140"),
    (rb"(?:schtasks\s+/create|currentversion\\run)", "Persistence-related command", "T1053.005"),
]


class YaraScanner:
    def __init__(self, rules_path: Path):
        self.rules_path = rules_path
        self.available = False
        self.engine_name = "Built-in indicator fallback"
        self.initialization_error = ""
        self._rules = None
        self._yara_x = None
        try:
            import yara_x  # type: ignore

            if rules_path.exists():
                source = rules_path.read_text(encoding="utf-8")
                self._rules = yara_x.compile(source)
                self._yara_x = yara_x
                self.available = True
                self.engine_name = "YARA-X"
        except Exception as exc:
            self._rules = None
            self._yara_x = None
            self.initialization_error = str(exc)

    def scan(self, path: Path) -> list[Artifact]:
        timestamp = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat(timespec="seconds")
        if self._rules is not None and self._yara_x is not None:
            try:
                scanner = self._yara_x.Scanner(self._rules)
                scanner.set_timeout(20)
                scan_results = scanner.scan_file(str(path))
            except Exception as exc:
                self.initialization_error = f"YARA-X scan error: {exc}"
                return self._fallback_scan(path, timestamp)
            results: list[Artifact] = []
            for match in scan_results.matching_rules:
                meta = dict(getattr(match, "metadata", ()) or ())
                rule_name = str(match.identifier)
                results.append(
                    Artifact(
                        artifact_type="YARA-X Match",
                        timestamp=timestamp,
                        source=path.name,
                        description=str(meta.get("description") or f"YARA-X rule matched: {rule_name}"),
                        severity=str(meta.get("severity", "High")).title(),
                        details={"rule": rule_name, "engine": "YARA-X", "metadata": meta},
                        mitre_id=str(meta.get("mitre", "")),
                    )
                )
            return results
        return self._fallback_scan(path, timestamp)

    def _fallback_scan(self, path: Path, timestamp: str) -> list[Artifact]:
        if path.stat().st_size > 2 * 1024 * 1024:
            return []
        try:
            content = path.read_bytes()
        except OSError:
            return []
        results: list[Artifact] = []
        for pattern, description, mitre in FALLBACK_PATTERNS:
            if re.search(pattern, content, flags=re.IGNORECASE):
                results.append(
                    Artifact(
                        artifact_type="Indicator Match",
                        timestamp=timestamp,
                        source=path.name,
                        description=description,
                        severity="High",
                        details={
                            "engine": "Built-in indicator fallback",
                            "pattern": pattern.decode("ascii"),
                            "yara_x_error": self.initialization_error,
                        },
                        mitre_id=mitre,
                    )
                )
        return results
