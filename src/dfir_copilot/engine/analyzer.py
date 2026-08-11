"""Top-level analyzer that never mutates the supplied evidence."""

from __future__ import annotations

from pathlib import Path

from dfir_copilot.config import AppConfig
from dfir_copilot.engine.parsers import file_metadata, parse_supported
from dfir_copilot.engine.scanner import YaraScanner
from dfir_copilot.models import Artifact


class EvidenceAnalyzer:
    def __init__(self, config: AppConfig):
        self.scanner = YaraScanner(config.rules_path)

    @property
    def yara_available(self) -> bool:
        return self.scanner.available

    @property
    def scanner_engine(self) -> str:
        return self.scanner.engine_name

    def analyze(self, path: Path) -> list[Artifact]:
        path = Path(path)
        if not path.is_file():
            raise FileNotFoundError(path)
        artifacts: list[Artifact] = [file_metadata(path)]
        artifacts.extend(parse_supported(path))
        artifacts.extend(self.scanner.scan(path))
        return artifacts
