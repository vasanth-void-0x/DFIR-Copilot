"""Runtime configuration with an offline-first default."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path


def resource_root() -> Path:
    """Return the project resource root in development or a PyInstaller build."""
    bundled = getattr(sys, "_MEIPASS", None)
    if bundled:
        return Path(bundled)
    return Path(__file__).resolve().parents[2]


def _load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


@dataclass(frozen=True)
class AppConfig:
    data_dir: Path
    db_path: Path
    evidence_dir: Path
    report_dir: Path
    rules_path: Path
    groq_api_key: str = ""
    groq_model: str = "llama-3.3-70b-versatile"
    groq_base_url: str = "https://api.groq.com/openai/v1/chat/completions"

    @classmethod
    def load(cls, data_dir: Path | None = None) -> "AppConfig":
        root = resource_root()
        _load_dotenv(root / ".env")

        configured = os.getenv("DFIR_COPILOT_DATA_DIR", "").strip()
        if data_dir is None:
            if configured:
                data_dir = Path(configured).expanduser()
            else:
                data_dir = Path.home() / "DFIR-Copilot-Data"

        resolved = data_dir.resolve()
        config = cls(
            data_dir=resolved,
            db_path=resolved / "dfir_copilot.db",
            evidence_dir=resolved / "cases",
            report_dir=resolved / "reports",
            rules_path=root / "resources" / "rules" / "suspicious.yar",
            groq_api_key=os.getenv("GROQ_API_KEY", "").strip(),
            groq_model=os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile").strip(),
        )
        config.ensure_directories()
        return config

    def ensure_directories(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.report_dir.mkdir(parents=True, exist_ok=True)
